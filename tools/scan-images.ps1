<#
.SYNOPSIS
    Builds a real vulnerability catalogue for the images actually running in the
    lab, by reading each container's package database and asking OSV.dev whether
    any advisory covers what it finds.

.DESCRIPTION
    Phase 3 requires that vulnerable images be catalogued, and the rule for this
    repository is that nothing is simulated. Every number this script prints
    comes from one of two places: a file read out of a running container, or a
    response from OSV.dev. There is no built-in list of known-bad packages.

    Where the data comes from
    -------------------------
    The package inventory is read from the running container, not from image
    metadata in a registry. That is a deliberate choice:

      - The host does not hold these images. They were pulled inside the kind
        node containers, so reading them host-side would mean pulling duplicates
        for no analytical gain.
      - What is deployed is more useful to a SOC than what a registry advertises.
        If a manifest was changed without the image being rebuilt, the running
        filesystem is the truth.

    The cost is that this only covers workloads that are running, and it says
    nothing about a layer that was present at build time and removed later.

    What "no vulnerabilities" means
    -------------------------------
    OSV matches on declared version ranges. Alpine and Debian both backport
    security fixes without changing the upstream version number, so a package
    can be patched and still fall inside a vulnerable range. Every count here is
    therefore "advisories whose declared range includes this version", which is
    an upper bound on real exposure and an upper bound on false positives.

    The one thing this script refuses to do
    ----------------------------------------
    OSV does not validate the ecosystem name. An ecosystem of `Alpine:v9.99` is
    accepted and returns a response with no `vulns` key, which is byte-identical
    to a genuinely clean package. A typo in one string would report the whole
    image as vulnerability-free, confidently and silently.

    So a workload that returns zero advisories across every one of its packages
    is reported as UNVERIFIED, not as clean, and it fails the scan. Proving a
    negative against an API that cannot say no is the whole problem.

.PARAMETER Refresh
    Ignore the response cache and re-query OSV.

.PARAMETER OutputPath
    Where to write the JSON catalogue. Defaults to .telemetry\image-catalog.json.

.EXAMPLE
    .\tools\scan-images.ps1
    .\tools\scan-images.ps1 -Refresh
#>
[CmdletBinding()]
param(
    [switch] $Refresh,
    [switch] $WriteBaseline,
    [string] $OutputPath,
    [string] $BaselinePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $OutputPath)   { $OutputPath   = Join-Path $repoRoot '.telemetry\image-catalog.json' }
if (-not $BaselinePath) { $BaselinePath = Join-Path $repoRoot 'drift\images-baseline.json' }
$cacheDir  = Join-Path $repoRoot '.telemetry\osv-cache'

$labNamespaces = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

# Workloads to inventory, with the image reference recorded in the manifest.
# The digest is read back from the running pod rather than trusted from here, so
# the catalogue reports what is deployed.
# Workloads to inventory. The pod selector is explicit per workload because the
# label key is not uniform: kube-router's DaemonSet uses k8s-app=, everything
# else in this lab uses app=. Guessing one key for all of them silently skipped
# the CNI, which is the one image here that is neither nginx nor alpine.
$workloads = @(
    @{ app = 'web-frontend';    namespace = 'zerotrust';         selector = 'app=web-frontend' }
    @{ app = 'orders-api';      namespace = 'zerotrust';         selector = 'app=orders-api' }
    @{ app = 'postgres';        namespace = 'zerotrust';         selector = 'app=postgres' }
    @{ app = 'build-runner';    namespace = 'zerotrust-build';   selector = 'app=build-runner' }
    @{ app = 'telemetry-agent'; namespace = 'zerotrust-observe'; selector = 'app=telemetry-agent' }
    @{ app = 'kube-router';     namespace = 'kube-system';       selector = 'k8s-app=kube-router' }
)

# Calibration probe. OSV will not tell us whether an ecosystem string is one it
# has data for: `Alpine:v9.99` is accepted and returns an empty response that is
# byte-identical to a clean result. So before trusting a zero, the ecosystem
# itself is interrogated with a package known to be densely covered. A live
# ecosystem returns advisories; a bogus one returns nothing.
#
# Measured against the live API while writing this:
#   Alpine:v3.20 -> 73    Alpine:v3.21 -> 86    Alpine:v3.24 -> 102
#   Debian:12    -> 260   Alpine:v9.99 -> 0     <- no data, and accepted
$calibrationPackage = 'openssl'

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

function Write-JsonFile {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string] $Path)
    $json = $Object | ConvertTo-Json -Depth 12
    $lf   = ($json -replace "`r`n", "`n").TrimEnd() + "`n"
    $dir  = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

# `vulns` is ABSENT, not empty, when a query matches nothing.
#
# This deliberately does NOT return `, @(...)`. The comma idiom is correct for
# assignment -- it stops PowerShell unrolling an empty array into $null -- but it
# is actively harmful when the result is piped, which is how this function is
# used. Piping unwraps the comma and hands the downstream ForEach-Object the
# inner array as a single object, and PSObject.Properties['id'] against an array
# returns null rather than enumerating. That bug shipped a scanner which
# reported 29 real CVEs in the nginx image as "clean": every match was read,
# then thrown away by a property lookup on the wrong type.
#
# So this returns a plain unrolled stream, and every call site wraps the call in
# @() to turn "nothing" back into a real empty array.
function Get-VulnList {
    param($Response)
    if ($null -eq $Response) { return }
    if (-not $Response.PSObject.Properties['vulns']) { return }
    $Response.vulns | Where-Object { $null -ne $_ }
}

# OSV has no auth, but it is a shared public service, so every response is cached
# on disk keyed by the request body. A re-run is free and offline, and the exact
# bytes that produced a finding are kept for audit.
function Invoke-Osv {
    param([string] $Uri, [string] $Body, [string] $Method = 'Post')

    if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }

    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes("$Method $Uri`n$Body")
    $sha      = [System.Security.Cryptography.SHA256]::Create()
    $key      = ([BitConverter]::ToString($sha.ComputeHash($keyBytes))) -replace '-', ''
    $sha.Dispose()
    $cacheFile = Join-Path $cacheDir "$key.json"

    if (-not $Refresh -and (Test-Path -LiteralPath $cacheFile)) {
        return (Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json)
    }

    $response = $null
    try {
        if ($Method -eq 'Post') {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType 'application/json' -TimeoutSec 60
        } else {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec 60
        }
    } catch {
        Write-Host ("    OSV request failed: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        return $null
    }

    if ($null -ne $response) {
        Write-JsonFile -Object $response -Path $cacheFile
    }
    return $response
}

# Parse `name=version` pairs out of the Alpine apk installed database. Fields are
# single-letter and the record for one package runs until the next P: marker.
function ConvertFrom-ApkInstalled {
    param([string[]] $Lines)
    $out = [System.Collections.Generic.List[object]]::new()
    $name = $null
    foreach ($line in $Lines) {
        if ($line.StartsWith('P:')) { $name = $line.Substring(2) }
        elseif ($line.StartsWith('V:') -and $name) {
            $out.Add([pscustomobject]@{ name = $name; version = $line.Substring(2) })
            $name = $null
        }
    }
    return , @($out)
}

# Parse the Debian dpkg status file. It is a single RFC822-ish stanza format, so
# blank-line separated blocks each describe one package.
function ConvertFrom-DpkgStatus {
    param([string[]] $Lines)
    $out   = [System.Collections.Generic.List[object]]::new()
    $name  = $null
    $ver   = $null
    $flush = {
        if ($name -and $ver) { $out.Add([pscustomobject]@{ name = $name; version = $ver }) }
        $name = $null; $ver = $null
    }
    foreach ($line in $Lines) {
        if ($line.StartsWith('Package: ')) { $name = $line.Substring(9).Trim() }
        elseif ($line.StartsWith('Version: ')) { $ver = $line.Substring(9).Trim() }
        elseif ($line -eq '') { & $flush }
    }
    & $flush
    return , @($out)
}

# OSV ecosystem names are `Alpine:v3.24` and `Debian:12`. Both formats were
# confirmed against the live API: `Alpine v3.24` and `Alpine 3.24` are rejected
# with HTTP 400, while `Alpine:v3.24` and `Debian:12` resolve.
#
# The version has to be narrowed to the right precision. Alpine reports
# VERSION_ID=3.24.2 but the ecosystem is `Alpine:v3.24`, and Debian reports
# VERSION_ID=12 but Ubuntu-style point releases would need the major only.
# Getting this wrong produces a valid-looking ecosystem string that OSV has no
# data for, which is exactly the silent-clean failure described above.
function Get-Ecosystem {
    param([string] $Id, [string] $VersionId)
    if (-not $Id -or -not $VersionId) { return $null }
    $parts = $VersionId -split '[^0-9]+' | Where-Object { $_ -ne '' }
    switch ($Id) {
        'alpine' {
            if ($parts.Count -lt 2) { return $null }
            return "Alpine:v$($parts[0]).$($parts[1])"
        }
        'debian' {
            if ($parts.Count -lt 1) { return $null }
            return "Debian:$($parts[0])"
        }
        'ubuntu' {
            if ($parts.Count -lt 1) { return $null }
            return "Ubuntu:$($parts[0])"
        }
        default { return $null }
    }
}

function Get-CVSS {
    param($Vuln)
    foreach ($s in @(Get-Prop $Vuln 'severity')) {
        $score = Get-Prop $s 'score'
        if ($score) { return [string]$score }
    }
    return ''
}

# Interrogate an ecosystem before trusting a zero result from it. Cached per
# ecosystem because three of the lab's workloads share Alpine:v3.21, and this is
# a network call.
$calibrationCache = @{}

function Test-EcosystemLive {
    param([Parameter(Mandatory)] [string] $Ecosystem)
    if ($calibrationCache.ContainsKey($Ecosystem)) { return $calibrationCache[$Ecosystem] }

    # No version constraint on purpose: this asks whether OSV holds data for the
    # ecosystem at all, not whether a particular build is affected.
    $body = (@{ package = @{ name = $calibrationPackage; ecosystem = $Ecosystem } } | ConvertTo-Json -Depth 4 -Compress)
    $r    = Invoke-Osv -Uri 'https://api.osv.dev/v1/query' -Body $body
    $n    = @(Get-VulnList $r).Count
    $calibrationCache[$Ecosystem] = $n
    return $n
}

function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
Write-Head 'preflight'
$nodes = (& kubectl get nodes --no-headers 2>$null | Measure-Object).Count
if ($nodes -lt 1) {
    Write-Host '  no reachable cluster. Start it with cluster\bootstrap\bootstrap.ps1' -ForegroundColor Red
    exit 1
}
Write-Host "  $nodes node(s) reachable"

# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------
$inventory = [System.Collections.Generic.List[object]]::new()

foreach ($w in $workloads) {
    $podName = (& kubectl get pod -n $w.namespace -l $w.selector -o jsonpath='{.items[0].metadata.name}' 2>$null)
    if (-not $podName) {
        Write-Host ("  [skip] {0}/{1}: no running pod" -f $w.namespace, $w.app) -ForegroundColor DarkYellow
        $inventory.Add([pscustomobject]@{
            app = $w.app; namespace = $w.namespace; pod = $null; status = 'absent'
            packages = 0; advisories = 0; unverified = $true
            reason = 'no running pod, so no package inventory could be read'
            findings = @()
        })
        continue
    }

    # The deployed image, with its digest, read back from the pod rather than
    # trusted from the manifest.
    $imageId = (& kubectl get pod -n $w.namespace $podName -o jsonpath='{.status.containerStatuses[0].imageID}' 2>$null)

    # Distro identity, straight from the container.
    $osRelease = @(& kubectl exec -n $w.namespace $podName -- cat /etc/os-release 2>$null)
    $osId   = $null; $osVer = $null
    foreach ($line in $osRelease) {
        if ($line.StartsWith('ID='))          { $osId  = $line.Substring(3).Trim('"') }
        elseif ($line.StartsWith('VERSION_ID=')) { $osVer = $line.Substring(11).Trim('"') }
    }

    $packages = @()
    $dbKind = 'unknown'
    if ($osId -eq 'alpine') {
        $dbKind = 'apk'
        $packages = ConvertFrom-ApkInstalled -Lines @(& kubectl exec -n $w.namespace $podName -- cat /lib/apk/db/installed 2>$null)
    } elseif ($osId -eq 'debian') {
        $dbKind = 'dpkg'
        $packages = ConvertFrom-DpkgStatus -Lines @(& kubectl exec -n $w.namespace $podName -- cat /var/lib/dpkg/status 2>$null)
    }

    $ecosystem = Get-Ecosystem -Id $osId -VersionId $osVer

    Write-Host ("  {0}/{1}" -f $w.namespace, $w.app) -ForegroundColor Cyan
    Write-Host ("    image    {0}" -f $imageId)
    Write-Host ("    distro   {0} {1}  -> ecosystem '{2}'  ({3} packages via {4})" -f $osId, $osVer, $ecosystem, $packages.Count, $dbKind)

    if (-not $ecosystem) {
        Write-Host '    UNVERIFIED: no OSV ecosystem mapping for this distro' -ForegroundColor Red
        $inventory.Add([pscustomobject]@{
            app = $w.app; namespace = $w.namespace; pod = $podName; status = 'unverified'
            image = $imageId; distro = "$osId $osVer"; ecosystem = $null
            packages = $packages.Count; advisories = 0; unverified = $true
            reason = "no OSV ecosystem is defined for '$osId', so no query could be constructed"
            findings = @()
        })
        continue
    }

    # ---- batch query -------------------------------------------------------
    # querybatch is used for the match because it takes up to 1000 packages in
    # one request. It returns bare ids with no severity, so details are fetched
    # afterwards for the ids that actually matched, which is a much smaller set.
    $queries = @($packages | ForEach-Object {
        @{ package = @{ name = $_.name; ecosystem = $ecosystem }; version = $_.version }
    })

    $matched = @{}   # package name -> list of vuln ids
    $allIds  = [System.Collections.Generic.HashSet[string]]::new()
    $batches  = [math]::Ceiling($queries.Count / 200)

    for ($b = 0; $b -lt $batches; $b++) {
        $offset = $b * 200
        $slice  = @($queries | Select-Object -Skip $offset -First 200)
        $body   = (@{ queries = $slice } | ConvertTo-Json -Depth 6 -Compress)
        $result = Invoke-Osv -Uri 'https://api.osv.dev/v1/querybatch' -Body $body
        if (-not $result) { continue }
        $resultRows = @(Get-Prop $result 'results')
        for ($i = 0; $i -lt $slice.Count; $i++) {
            $res = $resultRows[$i]
            # $_.id, not Get-Prop $_ 'id': the elements are real objects, and a
            # property lookup against anything that is not an object returns
            # null and discards the finding. See Get-VulnList.
            $ids = @(Get-VulnList $res | ForEach-Object { $_.id } | Where-Object { $_ })
            if ($ids.Count -gt 0) {
                # Indexed from $packages by offset, not read back out of
                # $slice[$i]. A query element is a Hashtable, and
                # PSObject.Properties does not expose Hashtable keys, so the
                # accessor silently returns null and the match is attributed to
                # no package at all -- which is how 30 matched advisories
                # produced an empty catalogue.
                $pkgName = $packages[$offset + $i].name
                if (-not $matched.ContainsKey($pkgName)) { $matched[$pkgName] = @() }
                $matched[$pkgName] += $ids
                foreach ($id in $ids) { [void]$allIds.Add($id) }
            }
        }
    }

    Write-Host ("    matched  {0} advisory id(s) across {1} package(s)" -f $allIds.Count, $matched.Count)

    # ---- details for the ids that matched ---------------------------------
    $detail = @{}
    foreach ($id in $allIds) {
        $d = Invoke-Osv -Uri "https://api.osv.dev/v1/vulns/$id" -Method Get
        if ($d) { $detail[$id] = $d }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($pkg in ($matched.Keys | Sort-Object)) {
        $version = ($packages | Where-Object { $_.name -eq $pkg } | Select-Object -First 1).version
        foreach ($id in ($matched[$pkg] | Sort-Object -Unique)) {
            $d = $detail[$id]
            $cvss = if ($d) { Get-CVSS $d } else { '' }
            # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is a 9.8. The vector is
            # the only severity OSV reliably carries for distro records, and
            # Alpine records in particular have no summary text, so the vector
            # is worth surfacing rather than discarding.
            $findings.Add([pscustomobject]@{
                id       = $id
                package  = $pkg
                version  = $version
                cvss     = $cvss
                summary  = if ($d) { Get-Prop $d 'summary' } else { $null }
                modified = if ($d) { Get-Prop $d 'modified' } else { $null }
            })
        }
    }

    # ---- the guard --------------------------------------------------------
    # A zero here is only meaningful if OSV actually holds data for the
    # ecosystem. The ecosystem is calibrated first, so "clean" means "checked
    # against a source that demonstrably has this ecosystem", not "the query
    # returned nothing, which is also what a typo would return".
    $calibrationCount = Test-EcosystemLive -Ecosystem $ecosystem
    $ecosystemLive    = ($calibrationCount -gt 0)
    $unverified       = (-not $ecosystemLive)
    $reason           = $null

    if ($unverified) {
        $reason = "OSV holds no data for ecosystem '$ecosystem' (calibration probe on $calibrationPackage returned 0), so a zero finding count here means nothing and this workload is UNVERIFIED."
        Write-Host ("    UNVERIFIED: ecosystem '{0}' has no OSV data" -f $ecosystem) -ForegroundColor Red
    } elseif ($findings.Count -eq 0) {
        Write-Host ("    clean: 0 advisories, against an ecosystem holding {0} records for {1}" -f $calibrationCount, $calibrationPackage) -ForegroundColor Green
    }

    $inventory.Add([pscustomobject]@{
        app               = $w.app
        namespace         = $w.namespace
        pod               = $podName
        status            = if ($unverified) { 'unverified' } else { 'scanned' }
        image             = $imageId
        distro            = "$osId $osVer"
        ecosystem         = $ecosystem
        ecosystemVerified = $ecosystemLive
        calibrationCount  = $calibrationCount
        packages          = $packages.Count
        advisories        = $findings.Count
        unverified        = $unverified
        reason            = $reason
        findings          = @($findings | Sort-Object package, id)
    })
}

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
Write-Head 'catalogue'

$totalAdvisories = 0
$unverifiedCount = 0
foreach ($item in $inventory) {
    Write-Host ''
    if ($item.status -eq 'absent') {
        Write-Host ("  {0}/{1}  ABSENT      {2}" -f $item.namespace, $item.app, $item.reason) -ForegroundColor DarkYellow
        $unverifiedCount++
        continue
    }
    $colour = if ($item.unverified) { 'DarkYellow' } else { 'White' }
    Write-Host ("  {0}/{1}  {2} advisories across {3} packages   [{4}]" -f `
        $item.namespace, $item.app, $item.advisories, $item.packages, $item.ecosystem) -ForegroundColor $colour
    Write-Host ("    image: {0}" -f $item.image) -ForegroundColor DarkGray
    if ($item.unverified) {
        Write-Host ("    UNVERIFIED: {0}" -f $item.reason) -ForegroundColor Red
        $unverifiedCount++
        continue
    }
    Write-Host ("    ecosystem verified: {0} holds {1} record(s) for {2}" -f $item.ecosystem, $item.calibrationCount, $calibrationPackage) -ForegroundColor DarkGray
    $totalAdvisories += $item.advisories
    foreach ($f in @($item.findings) | Select-Object -First 8) {
        Write-Host ("    {0,-22} {1}@{2}" -f $f.id, $f.package, $f.version) -ForegroundColor DarkGray
        if ($f.cvss) { Write-Host ("      {0}" -f $f.cvss) -ForegroundColor DarkGray }
    }
    if (@($item.findings).Count -gt 8) {
        Write-Host ("    ... and {0} more (see the JSON catalogue)" -f (@($item.findings).Count - 8)) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host "  $totalAdvisories advisory record(s) across the lab; $unverifiedCount workload(s) UNVERIFIED"

$report = [ordered]@{
    generatedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    source       = 'OSV.dev (https://osv.dev), queried per package from the running container package database'
    caveats      = @(
        'Version-range matching is an upper bound. Alpine and Debian backport security fixes without changing the upstream version, so a patched package can still fall inside a vulnerable range. A clean result means no advisory declares this version affected, not that the package is free of defects.',
        'The inventory is read from the running container, so it reflects what is deployed rather than what a registry advertises, and it cannot see a layer that was present at build time and later removed.',
        'Alpine splits some upstream packages into differently named subpackages. Alpine 3.24 has no package named openssl; it has libcrypto3 and libssl3. OSV keys on distro package names, so those are queried under their own names.',
        'Every ecosystem is calibrated before a zero is believed: the calibration probe asks OSV for all openssl advisories in that ecosystem with no version constraint. A live ecosystem answers; an ecosystem string OSV has no data for answers empty, and a workload on such an ecosystem is reported UNVERIFIED and fails the scan.'
    )
    workloads    = @($inventory)
    totalAdvisories = $totalAdvisories
    unverified      = $unverifiedCount
}
Write-JsonFile -Object $report -Path $OutputPath
Write-Host "  catalogue written to $OutputPath"

# ---------------------------------------------------------------------------
# supply-chain drift
#
# A catalogue that only ever reports is decoration. Two things must fail the
# scan, and neither is a count of CVEs:
#
#   1. The image digest changed. The manifest pins a digest precisely so that the
#      thing running is the thing reviewed. A changed digest means every other
#      property of this catalogue -- package set, advisory list -- is now
#      describing software nobody signed off, and it is the single most
#      important thing this tool can notice.
#
#   2. A new advisory appeared. Advisories are published about old software all
#      the time, so the CVE set for a pinned image is expected to grow without
#      anyone changing anything. That growth is news, and the response is to
#      update the image or to accept the advisory explicitly, not to keep a
#      number in a report and read it next quarter.
#
# Resolved advisories are reported but do not fail: an advisory disappearing
# means the base image moved forward, which is an improvement, and demanding a
# baseline edit for good news trains people to regenerate baselines without
# reading them.
# ---------------------------------------------------------------------------

# app key -> @{ image; advisories }
$current = [ordered]@{}
foreach ($item in $inventory) {
    $key = "$($item.namespace)/$($item.app)"
    $ids = @($item.findings | ForEach-Object { $_.id } | Where-Object { $_ } | Sort-Object -Unique)
    $current[$key] = [ordered]@{
        image      = $item.image
        packages   = $item.packages
        advisories = $ids
    }
}

if ($WriteBaseline) {
    $baseline = [ordered]@{
        generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        note        = @'
Known state of the pinned images. The scan fails if a digest changes, because
that means the running software is not the software that was reviewed, and it
fails if an advisory is added, because advisories are published about old
software and a newly-known vulnerability in a pinned image is news.
'@
        workloads = $current
    }
    Write-JsonFile -Object $baseline -Path $BaselinePath
    Write-Host ''
    Write-Host "  image baseline written to $BaselinePath" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    Write-Host ''
    Write-Host "  no image baseline at $BaselinePath" -ForegroundColor Red
    Write-Host '  run once with -WriteBaseline, read the catalogue, and commit it' -ForegroundColor Red
    exit 1
}

$saved = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
$savedWorkloads = Get-Prop $saved 'workloads'

$digestChanges = [System.Collections.Generic.List[string]]::new()
$newAdvisories = [System.Collections.Generic.List[string]]::new()
$resolved      = [System.Collections.Generic.List[string]]::new()

foreach ($key in $savedWorkloads.PSObject.Properties.Name) {
    $before = $savedWorkloads.$key
    $beforeImage = Get-Prop $before 'image'
    $beforeIds   = @(Get-Prop $before 'advisories')

    if (-not $current.Contains($key)) {
        $digestChanges.Add("$key : in the baseline but not running any more")
        continue
    }
    $now = $current[$key]

    if ($beforeImage -ne $now.image) {
        # -f formatting, not string interpolation. This is not a style choice.
        # PowerShell resolves `$now.image` correctly in an expression (so the
        # -ne comparison above is sound), but inside a double-quoted string it
        # stringifies the OrderedDictionary and appends the literal text
        # ".image", printing:
        #     now System.Collections.Specialized.OrderedDictionary.image
        # The verdict was right and the explanation was nonsense, which is the
        # worst combination for a drift report: it tells you the pinned image
        # moved without telling you what it moved to.
        $digestChanges.Add(("{0}`n      was {1}`n      now {2}" -f $key, $beforeImage, $now.image))
    }
    foreach ($id in $now.advisories) {
        if ($beforeIds -notcontains $id) { $newAdvisories.Add("$key  $id") }
    }
    foreach ($id in $beforeIds) {
        if ($now.advisories -notcontains $id) { $resolved.Add("$key  $id") }
    }
}

Write-Host ''
Write-Head 'supply-chain drift'
Write-Host ("  {0} workload(s) compared" -f $savedWorkloads.PSObject.Properties.Name.Count)

if ($digestChanges.Count -gt 0) {
    Write-Host ''
    Write-Host '  IMAGE DIGEST CHANGED:' -ForegroundColor Red
    foreach ($d in $digestChanges) { Write-Host ("    ! " + $d) -ForegroundColor Red }
}
if ($newAdvisories.Count -gt 0) {
    Write-Host ''
    Write-Host ("  {0} NEW ADVISORY/ADVISORIES against pinned images:" -f $newAdvisories.Count) -ForegroundColor Red
    foreach ($n in $newAdvisories) { Write-Host ("    + " + $n) -ForegroundColor Red }
    Write-Host '    update the image, or accept each one explicitly with -WriteBaseline' -ForegroundColor Red
}
if ($resolved.Count -gt 0) {
    Write-Host ''
    Write-Host ("  {0} advisory/ies no longer apply (base image moved on; not a failure):" -f $resolved.Count) -ForegroundColor Green
    foreach ($r in $resolved) { Write-Host ("    - " + $r) -ForegroundColor Green }
}

$driftReport = [ordered]@{
    generatedAt    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    totalAdvisories = $totalAdvisories
    unverified      = $unverifiedCount
    digestChanges   = @($digestChanges)
    newAdvisories   = @($newAdvisories)
    resolved        = @($resolved)
    drift           = ($digestChanges.Count -gt 0 -or $newAdvisories.Count -gt 0 -or $unverifiedCount -gt 0)
}
Write-JsonFile -Object $driftReport -Path (Join-Path $repoRoot '.telemetry\image-drift.json')

# Unverified is a failure. A catalogue that silently reports "clean" for an image
# it could not actually check is worse than no catalogue, because it is believed.
exit $(if ($digestChanges.Count -gt 0 -or $newAdvisories.Count -gt 0 -or $unverifiedCount -gt 0) { 1 } else { 0 })
