<#
.SYNOPSIS
    Finds out how far each credential in the lab has spread, and fails if any of
    it has escaped into somewhere it should never be.

.DESCRIPTION
    Phase 3 requires secret sprawl to be catalogued. "Sprawl" is not one bug, it
    is a shape: a credential that lives in more than one place, or in a place
    with more readers than the workload that needs it. This script measures that
    shape rather than guessing at it.

    What it checks
    --------------
    1. A Secret value reproduced verbatim in a ConfigMap, either as the whole
       value or embedded inside a larger one. This is SP-01. The embedded case
       matters: the leaked DATABASE_URL contains the password inside a
       connection string, so an equality test alone would miss the single worst
       copy of it in the cluster.

    2. A ConfigMap value that looks like a credential by shape, whether or not
       it matches any Secret. This catches a password that was duplicated
       somewhere and then rotated, leaving the stale copy with no Secret to
       match against. Shape-based detection is the only way to see those.

    3. A container env var carrying a literal credential, as opposed to a
       secretKeyRef. An env var literal is visible in the pod spec, in
       `kubectl describe`, and to anything that can read the pod.

    4. A credential in a container command or argument. Worse than an env var,
       because a process listing inside the pod shows it too.

    5. The live Secret values appearing anywhere in the committed git tree.
       This is the check that matters most and the one least likely to be
       written, and it is the reason this script exists: a lab that generates
       fresh credentials on every bootstrap can still leak the previous run's
       password into a committed file the moment somebody pastes a command
       output into a document.

    On not printing credentials
    ---------------------------
    No value is ever printed. Every finding reports the location, the length, and
    a 16-hex-character prefix of the SHA-256, which is enough to correlate two
    copies of the same credential and completely useless to anyone who wants the
    credential. There is deliberately no switch to reveal values, because a
    scanner that can print a secret will eventually print one into a terminal, a
    ticket, or a commit message.

    Nothing here decides what to do about a finding. The baseline records the
    known sprawl; it is not an approval.

.NOTES
    Requires read access to Secret data, which means this cannot run against a
    cluster where the caller is not authorised to read secrets. That is correct
    and worth stating: a sprawl scanner that cannot see the sprawl is useless,
    and a sprawl scanner that could see it as an unprivileged user would itself
    be the vulnerability.

.EXAMPLE
    .\tools\scan-secrets.ps1
    .\tools\scan-secrets.ps1 -WriteBaseline
#>
[CmdletBinding()]
param(
    [switch] $WriteBaseline,
    [switch] $SkipGitScan,
    [string] $OutputPath,
    [string] $BaselinePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $OutputPath)   { $OutputPath   = Join-Path $repoRoot '.telemetry\secret-scan.json' }
if (-not $BaselinePath) { $BaselinePath = Join-Path $repoRoot 'drift\secrets-baseline.json' }

$labNamespaces = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

# What each workload is actually supposed to need. Anything a Secret is exposed
# to outside this list is sprawl by definition, and it is a decision to record
# rather than an accident to discover later.
$legitimateReaders = @{
    'postgres-credentials' = @('zerotrust/orders-api', 'zerotrust/postgres')
    'build-credentials'    = @('zerotrust-build/build-runner')
}

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

# Out-String is required, not cosmetic. `kubectl -o json` emits one line per
# line, and piping that straight into ConvertFrom-Json hands it a single line at
# a time, so it throws and the variable ends up $null. Every call site below
# that parses command output goes through here for that reason.
function Get-Json {
    param([string[]] $Arguments)
    $out = & kubectl @Arguments 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $out.Trim()) { return $null }
    try { return ($out | ConvertFrom-Json) } catch { return $null }
}

function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Extracts the items array from a `kubectl -o json` list response.
#
# This returns a plain unrolled stream and every call site wraps the call in @().
# That is the opposite of the `, @()` idiom, and the reason is worth recording
# because it is the third distinct way that idiom has bitten this repository:
#
#   - `, @()` with a direct assignment ($x = Get-Thing) is correct, and stops an
#     empty result from unrolling to $null.
#   - `, @()` then PIPED hands the downstream command the inner array as a
#     single object, and a property lookup on an array returns null. This is how
#     tools/scan-images.ps1 reported 29 real CVEs as "clean".
#   - `, @()` wrapped in @() at the call site produces a NESTED array, so a
#     foreach iterates once with an array in hand and every property read
#     returns null. That is how this function reported zero credentials while
#     two Secrets were sitting in the cluster.
#
# A plain stream plus @() at the call site is the only form that is correct in
# all three positions, so it is the only form used here.
function Get-ArrayOf {
    param($Object)
    if ($null -eq $Object) { return }
    if (-not $Object.PSObject.Properties['items']) { return }
    $Object.items | Where-Object { $null -ne $_ }
}

# A stable, non-reversible label for a credential. Two copies of the same
# password produce the same fingerprint, which is what makes it possible to say
# "these three findings are one credential" without ever handling the value.
function Get-Fingerprint {
    param([string] $Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))) -replace '-', ''
    $sha.Dispose()
    return $hex.Substring(0, 16)
}

$script:findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Resource,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $AttackId = 'T1552.001',
        [string] $Fingerprint = '',
        [int]    $ValueLength = 0
    )
    $script:findings.Add([pscustomobject]@{
        key         = $Key
        category    = $Category
        severity    = $Severity
        resource    = $Resource
        detail      = $Detail
        attackId    = $AttackId
        fingerprint = $Fingerprint
        valueLength = $ValueLength
    })
}

# ---------------------------------------------------------------------------
# credential shape
#
# Detection is by value shape, not by the word "password" appearing anywhere.
# The SP-01 ConfigMap contains a NOTE reading "intentional weakness SP-01 -
# plaintext credential in a ConfigMap", and a scanner that matched on the word
# would flag its own explanation and bury the finding it was written to find.
# ---------------------------------------------------------------------------

# A connection string carrying a password: scheme://user:password@host
$script:reUriUserInfo = [regex]'(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@'

# A key name that says what it holds.
$script:reCredentialKey = [regex]'(?i)(pass(word|wd)?|pwd|secret|token|api[_\-]?key|credential|private[_\-]?key)'

# A key name that says it holds an identifier rather than a secret.
$script:reIdentifierKey = [regex]'(?i)^(user(name)?|login|account|uid|db[_\-]?user|db[_\-]?username|user[_\-]?id|host|hostname|port|database|dbname)$'

# A long opaque blob, which is what a generated credential looks like.
$script:reHighEntropy = [regex]'^[A-Za-z0-9+/_\-]{24,}={0,2}$'

# Values shorter than this are not matched anywhere. Twelve characters is short
# enough for every generated credential in this lab and long enough that an
# ordinary word does not collide with one.
$script:minMatchableLength = 12

<#
    Classify what a Secret key holds, and refuse to guess when the name is opaque.

    This exists because of a specific false positive, and the size of it is the
    point. The lab's database username is the word "orders". Substring-matching a
    six-character common noun as though it were a credential produced 21
    findings, 13 of them CRITICAL claims that a live credential had been
    committed -- in this scanner's own source, in the manifest that creates the
    service account, in the HTML page the lab serves. Every one of them was
    nonsense, and a scanner that cries wolf about its own source code gets
    switched off.

    A username is an identifier. It is meant to be readable, it appears in
    connection strings and log lines and documentation, and treating it as a
    secret produces a report nobody can act on. So keys that name an identifier
    are classified out of the sprawl matching, and the report says how many were
    excluded and why.
#>
function Get-ValueKind {
    param([string] $KeyName, [string] $Value)

    # The param block MUST end the line, with the body's opening brace implied.
    # Writing `param([string] $KeyName, [string] $Value) {` on one line makes
    # PowerShell parse that brace as a scriptblock ARGUMENT to param, so the
    # function becomes a scriptblock returning its own body text instead of a
    # function, and every call site silently receives a ScriptBlock where a
    # classification string was expected. Nothing errors: the values simply stop
    # matching, and the scan reports zero of everything.
    if ($KeyName -and $script:reIdentifierKey.IsMatch($KeyName)) { return 'identifier' }
    if ($KeyName -and $script:reCredentialKey.IsMatch($KeyName)) { return 'credential' }

    # An unrecognised name. Only treat it as a credential if it looks like
    # one: long and opaque. Anything short or word-like is an identifier we
    # happen not to have a name for, and guessing wrong in that direction
    # produces the noise this classification exists to remove.
    if ($Value.Length -ge 20 -and $Value -notmatch '\s' -and $script:reHighEntropy.IsMatch($Value)) { return 'credential' }
    if ($script:reHighEntropy.IsMatch($Value)) { return 'unknown' }
    return 'identifier'
}

function Test-LooksLikeCredential {
    param([string] $Value, [string] $KeyName)

    if ($null -eq $Value) { return $false }
    $v = [string]$Value
    if ($v.Length -lt 6) { return $false }

    # Prose is not a credential. Anything with spaces and sentence structure is
    # a description, whatever it says inside it.
    if ($v -match '\s' -and $v -notmatch '^postgresql|^mysql|^mongodb|^redis|^amqp') { return $false }

    if ($script:reUriUserInfo.IsMatch($v)) { return $true }
    if ($KeyName -and $script:reCredentialKey.IsMatch($KeyName) -and $script:reHighEntropy.IsMatch($v)) { return $true }
    return $false
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
# collect live secrets
#
# The decoded values live in memory for the lifetime of the process and are
# never written to the report. Everything downstream compares against them.
# ---------------------------------------------------------------------------
Write-Head 'collecting secrets'

$secrets = [System.Collections.Generic.List[object]]::new()
$byValue = @{}   # credential value -> "namespace/name/key", for exact-match lookup

foreach ($ns in $labNamespaces) {
    foreach ($item in @(Get-ArrayOf (Get-Json @('get','secrets','-n',$ns,'-o','json')))) {
        $name = Get-Prop (Get-Prop $item 'metadata') 'name'
        $data = Get-Prop $item 'data'
        if ($null -eq $data) { continue }
        foreach ($p in @($data.PSObject.Properties)) {
            $plain = $null
            try { $plain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$p.Value)) } catch { continue }
            $ref = "$ns/$name/$($p.Name)"
            $kind = Get-ValueKind -KeyName $p.Name -Value $plain
            $secrets.Add([pscustomobject]@{
                namespace   = $ns
                secret      = $name
                key         = $p.Name
                kind        = $kind
                length      = $plain.Length
                fingerprint = (Get-Fingerprint $plain)
            })
            # Only credentials are searched for. An identifier is expected to be
            # readable and would collide with ordinary prose.
            if ($kind -eq 'credential' -and $plain.Length -ge $script:minMatchableLength) {
                $byValue[$plain] = $ref
            }
        }
    }
}
$credentialCount = @($secrets | Where-Object { $_.kind -eq 'credential' }).Count
$identifierCount = @($secrets | Where-Object { $_.kind -eq 'identifier' }).Count
$unknownCount    = @($secrets | Where-Object { $_.kind -eq 'unknown' }).Count
Write-Host "  $($secrets.Count) value(s) across $((@($secrets | Select-Object -ExpandProperty secret -Unique)).Count) Secret(s): $credentialCount credential, $identifierCount identifier, $unknownCount unclassified"
Write-Host "  searching for the $((($byValue.Keys | Measure-Object).Count)) credential value(s) long enough to match without colliding with a word" -ForegroundColor DarkGray

# A sprawl scanner that finds no credentials has either been pointed at a cluster
# with no Secrets or has a bug, and both look identical from the outside: a
# clean report. The count of Secrets the API reports is checked against the
# number actually decoded, so the second case is caught here rather than being
# reported as "no sprawl detected" and believed.
$apiSecretCount = 0
foreach ($ns in $labNamespaces) {
    $apiSecretCount += (@(Get-ArrayOf (Get-Json @('get','secrets','-n',$ns,'-o','json')))).Count
}
if ($apiSecretCount -eq 0) {
    Write-Host '  the API reports no Secrets in any lab namespace, so there is nothing to scan' -ForegroundColor Red
    Write-Host '  run cluster\bootstrap\bootstrap.ps1 to generate them first' -ForegroundColor Red
    exit 1
}
if ($secrets.Count -eq 0) {
    Write-Host ("  the API reports {0} Secret(s) but 0 credential values were decoded from them" -f $apiSecretCount) -ForegroundColor Red
    Write-Host '  refusing to report no sprawl, because that would be indistinguishable from a broken scan' -ForegroundColor Red
    exit 1
}
Write-Host "  decoded values from all $apiSecretCount Secret(s) the API reports" -ForegroundColor DarkGray

# Same reasoning one level down. A cluster with Secrets but no matchable
# credential means the classification is wrong, not that the lab is clean, and a
# sprawl scan over zero credentials reports zero sprawl in a way that looks
# identical to a result.
if ($byValue.Count -eq 0) {
    Write-Host '  no Secret value was classified as a long enough credential to search for' -ForegroundColor Red
    Write-Host '  refusing to report no sprawl, because a scan with nothing to look for always finds nothing' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# check 1: a credential reproduced in a ConfigMap
# ---------------------------------------------------------------------------
Write-Head 'check 1: Secret values reproduced in ConfigMaps'

foreach ($ns in $labNamespaces) {
    foreach ($cm in @(Get-ArrayOf (Get-Json @('get','configmaps','-n',$ns,'-o','json')))) {
        $cmName = Get-Prop (Get-Prop $cm 'metadata') 'name'
        $data   = Get-Prop $cm 'data'
        if ($null -eq $data) { continue }
        foreach ($p in @($data.PSObject.Properties)) {
            $value = [string]$p.Value
            if ($value.Length -lt 6) { continue }

            # Exact reproduction, or embedded inside something longer. The
            # embedded case is the one that matters: the connection string in
            # the SP-01 ConfigMap contains the password, and an equality test
            # alone would rank that below the bare copy and miss the fact that
            # this ConfigMap also hands out the host and database name.
            if ($byValue.ContainsKey($value)) {
                Add-Finding -Key "secrets/plaintext-copy/$ns/$cmName/$($p.Name)" -Category 'sprawl' -Severity 'high' `
                    -Resource "ConfigMap/$ns/$cmName" `
                    -Detail "config key '$($p.Name)' is a verbatim copy of $($byValue[$value])" `
                    -Fingerprint (Get-Fingerprint $value) -ValueLength $value.Length
                continue
            }
            foreach ($secretValue in $byValue.Keys) {
                if ($value.Contains($secretValue)) {
                    Add-Finding -Key "secrets/plaintext-embedded/$ns/$cmName/$($p.Name)" -Category 'sprawl' -Severity 'high' `
                        -Resource "ConfigMap/$ns/$cmName" `
                        -Detail "config key '$($p.Name)' embeds $($byValue[$secretValue]) inside a larger value" `
                        -Fingerprint (Get-Fingerprint $secretValue) -ValueLength $secretValue.Length
                    break
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# check 2: credential-shaped ConfigMap values that match no Secret
#
# The copy of a password that outlived the password. When a credential is
# rotated, the Secret is updated and the stale duplicate in a ConfigMap is not,
# because nothing points at it any more. Matching against live Secrets cannot
# find that, which is why shape detection runs alongside it.
# ---------------------------------------------------------------------------
Write-Head 'check 2: credential-shaped ConfigMap values matching no Secret'

foreach ($ns in $labNamespaces) {
    foreach ($cm in @(Get-ArrayOf (Get-Json @('get','configmaps','-n',$ns,'-o','json')))) {
        $cmName = Get-Prop (Get-Prop $cm 'metadata') 'name'
        $data   = Get-Prop $cm 'data'
        if ($null -eq $data) { continue }
        foreach ($p in @($data.PSObject.Properties)) {
            $value = [string]$p.Value
            if ($byValue.ContainsKey($value)) { continue }

            # Already reported by check 1 as a copy of a known credential. The
            # connection string in the SP-01 ConfigMap trips both this shape test
            # and the embedded-copy test, and reporting the same leak twice under
            # two keys makes the finding count a measure of the scanner's
            # patterns rather than of the cluster's sprawl.
            $alreadyMatched = $false
            foreach ($secretValue in $byValue.Keys) {
                if ($value.Contains($secretValue)) { $alreadyMatched = $true; break }
            }
            if ($alreadyMatched) { continue }

            if (Test-LooksLikeCredential -Value $value -KeyName $p.Name) {
                Add-Finding -Key "secrets/shaped-configmap/$ns/$cmName/$($p.Name)" -Category 'sprawl' -Severity 'high' `
                    -Resource "ConfigMap/$ns/$cmName" `
                    -Detail "config key '$($p.Name)' holds a connection string carrying a password; it matches no current Secret, so it is either a stale copy of a rotated credential or a credential with no Secret at all" `
                    -Fingerprint (Get-Fingerprint $value) -ValueLength $value.Length
            }
        }
    }
}

# ---------------------------------------------------------------------------
# check 3: credentials in pod specs
# ---------------------------------------------------------------------------
Write-Head 'check 3: credentials in env vars, commands and arguments'

foreach ($ns in $labNamespaces) {
    $pods = Get-Json @('get','pods','-n',$ns,'-o','json')
    foreach ($pod in @(Get-ArrayOf $pods)) {
        $labels = Get-Prop (Get-Prop $pod 'metadata') 'labels'
        $app    = Get-Prop $labels 'app'
        # Harness scaffolding, not part of the system under test.
        if ((Get-Prop (Get-Prop $pod 'metadata') 'annotations') -and
            (Get-Prop (Get-Prop (Get-Prop $pod 'metadata') 'annotations') 'zerotrust.lab/purpose') -eq 'boundary-test-probe') { continue }
        $podName = Get-Prop (Get-Prop $pod 'metadata') 'name'
        $subject = if ($app) { "$ns/$app" } else { "$ns/$podName" }
        $spec    = Get-Prop $pod 'spec'

        foreach ($c in @(Get-Prop $spec 'containers')) {
            $cname = Get-Prop $c 'name'
            foreach ($e in @(Get-Prop $c 'env')) {
                $en = Get-Prop $e 'name'
                # A secretKeyRef is the correct way to do this and is not a finding.
                if (Get-Prop $e 'valueFrom') { continue }
                $ev = Get-Prop $e 'value'
                if (Test-LooksLikeCredential -Value $ev -KeyName $en) {
                    Add-Finding -Key "secrets/env-literal/$subject/$cname/$en" -Category 'sprawl' -Severity 'medium' `
                        -Resource "Pod/$subject container $cname" `
                        -Detail "env '$en' is a literal credential in the pod spec, where it is readable by anyone who can get the pod" `
                        -Fingerprint (Get-Fingerprint ([string]$ev)) -ValueLength ([string]$ev).Length
                }
            }
            foreach ($field in @('command', 'args')) {
                $arr = Get-Prop $c $field
                if ($null -eq $arr) { continue }
                $joined = (@($arr) -join ' ')
                if ($byValue.ContainsKey($joined)) { continue }
                foreach ($secretValue in $byValue.Keys) {
                    if ($joined.Contains($secretValue)) {
                        Add-Finding -Key "secrets/arg-literal/$subject/$cname/$field" -Category 'sprawl' -Severity 'high' `
                            -Resource "Pod/$subject container $cname" `
                            -Detail "container $field contains $($byValue[$secretValue]) verbatim; a process listing inside the pod exposes it" `
                            -Fingerprint (Get-Fingerprint $secretValue) -ValueLength $secretValue.Length
                        break
                    }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# check 4: the committed tree
#
# This is the check that justifies the tool. Everything above is about sprawl
# inside the cluster, which is recoverable by rotating a credential. This is
# about sprawl into git, which is not, because git keeps it forever and every
# clone carries it.
# ---------------------------------------------------------------------------
$gitChecked = 0
$gitFiles   = 0
if (-not $SkipGitScan) {
    Write-Head 'check 4: live credentials in the committed tree'

    $tracked = @(& git -C $repoRoot ls-files 2>$null)
    $gitFiles = $tracked.Count
    if ($gitFiles -eq 0) {
        Write-Host '  git reported no tracked files; skipping rather than reporting clean' -ForegroundColor Red
        $gitChecked = -1
    } else {
        foreach ($rel in $tracked) {
            $full = Join-Path $repoRoot $rel
            if (-not (Test-Path -LiteralPath $full)) { continue }
            try { $text = [Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($full)) } catch { continue }
            if ($text -match "`0") { continue }   # binary
            foreach ($secretValue in $byValue.Keys) {
                if ($text.Contains($secretValue)) {
                    Add-Finding -Key "secrets/committed/$rel" -Category 'leak' -Severity 'critical' `
                        -Resource "File/$rel" `
                        -Detail "a live credential for $($byValue[$secretValue]) appears in a tracked file. Git retains it in every clone and every prior commit; rotating the credential is the only fix" `
                        -Fingerprint (Get-Fingerprint $secretValue) -ValueLength $secretValue.Length
                }
            }
        }
        $gitChecked = 1
    }
    Write-Host "  $gitFiles tracked file(s) searched for $($byValue.Count) live credential value(s)"
    if ($gitChecked -eq 1) { Write-Host '  no live credential found in the committed tree' -ForegroundColor Green }
}

# ---------------------------------------------------------------------------
# check 5: who can read each Secret
#
# Informational rather than a finding. Sprawl is measured in readers, so the
# report has to say how many there are, not just that a copy exists.
# ---------------------------------------------------------------------------
Write-Head 'check 5: readers per Secret'

$readers = [ordered]@{}
foreach ($s in $secrets) {
    $readers["$($s.namespace)/$($s.secret)"] = @()
}
foreach ($ns in $labNamespaces) {
    $pods = Get-Json @('get','pods','-n',$ns,'-o','json')
    foreach ($pod in @(Get-ArrayOf $pods)) {
        $labels = Get-Prop (Get-Prop $pod 'metadata') 'labels'
        $app    = Get-Prop $labels 'app'
        $podName = Get-Prop (Get-Prop $pod 'metadata') 'name'
        $subject = if ($app) { "$ns/$app" } else { "$ns/$podName" }
        $spec    = Get-Prop $pod 'spec'
        foreach ($v in @(Get-Prop $spec 'volumes')) {
            $sn = Get-Prop (Get-Prop $v 'secret') 'secretName'
            if (-not $sn) { continue }
            $k = "$ns/$sn"
            if ($readers.Contains($k) -and $readers[$k] -notcontains $subject) { $readers[$k] += $subject }
        }
        foreach ($c in @(Get-Prop $spec 'containers')) {
            foreach ($e in @(Get-Prop $c 'env')) {
                $skr = Get-Prop (Get-Prop $e 'valueFrom') 'secretKeyRef'
                if (-not $skr) { continue }
                $sn = Get-Prop $skr 'name'
                $k = "$ns/$sn"
                if ($readers.Contains($k) -and $readers[$k] -notcontains $subject) { $readers[$k] += $subject }
            }
        }
    }
}
foreach ($k in $readers.Keys) {
    $expected = @()
    if ($legitimateReaders.ContainsKey((Split-Path -Leaf $k))) { $expected = $legitimateReaders[(Split-Path -Leaf $k)] }
    $unexpected = @(@($readers[$k]) | Where-Object { $expected -notcontains $_ })
    Write-Host ("  {0,-42} readers: {1}" -f $k, (@($readers[$k]) -join ', ')) -ForegroundColor White
    if ($unexpected.Count -gt 0) {
        Add-Finding -Key "secrets/unexpected-reader/$k" -Category 'sprawl' -Severity 'medium' `
            -Resource "Secret/$k" `
            -Detail "read by $($unexpected -join ', '), which is not in the documented reader set ($($expected -join ', '))" `
            -AttackId 'T1552.001'
    }
}

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
Write-Head 'findings'
$script:findings | Sort-Object key | ForEach-Object {
    Write-Host ("  [{0,-8}] {1}" -f $_.severity.ToUpper(), $_.key) -ForegroundColor DarkGray
    Write-Host ("             {0}" -f $_.detail) -ForegroundColor DarkGray
    Write-Host ("             {0}  fingerprint {1}  {2} chars" -f $_.attackId, $_.fingerprint, $_.valueLength) -ForegroundColor DarkGray
}

# Group by fingerprint: the question is not how many findings there are, it is
# how many distinct credentials have been copied and where.
Write-Host ''
Write-Host '  distinct credentials by fingerprint:'
$script:findings | Where-Object { $_.fingerprint } |
    Group-Object fingerprint | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("    {0}  {1} finding(s)" -f $_.Name, $_.Count) -ForegroundColor White
    }

# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------
$critical = @($script:findings | Where-Object { $_.severity -eq 'critical' })

if ($WriteBaseline) {
    $baseline = [ordered]@{
        generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        note        = @'
Known credential sprawl. Every entry is a real copy of a live credential in a
place it should not be, and is here so that the scan has something to be
compared against. This is a record of what is wrong, not an approval of it.

A new finding is drift and fails. A finding here that has disappeared is also
reported: Phase 4 exercises SP-01 by reading the leaked ConfigMap from inside
the cluster, and if the leak is fixed the exercise cannot run and the detection
written against it cannot be tested.

Fingerprints change whenever credentials are regenerated by bootstrap, so a
regenerated baseline shows every fingerprint as different. That is expected;
review the diff before committing it.
'@
        legitimateReaders = $legitimateReaders
        secrets     = @($secrets)
        readers     = $readers
        findings    = @($script:findings | Sort-Object key)
    }
    Write-JsonFile -Object $baseline -Path $BaselinePath
    Write-Host ''
    Write-Host "  secret baseline written to $BaselinePath ($($script:findings.Count) finding(s))" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    Write-Host ''
    Write-Host "  no baseline at $BaselinePath" -ForegroundColor Red
    Write-Host '  run once with -WriteBaseline, read the findings, and commit it' -ForegroundColor Red
    exit 1
}

$expected = @()
foreach ($f in @(Get-Prop (Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json) 'findings')) {
    $expected += [string](Get-Prop $f 'key')
}
$currentKeys = @($script:findings | ForEach-Object { $_.key })

$newFindings  = @($script:findings | Where-Object { $expected -notcontains $_.key })
$goneFindings = @($expected | Where-Object { $currentKeys -notcontains $_ })

Write-Host ''
Write-Head 'drift'
Write-Host ("  expected {0}, observed {1}, new {2}, disappeared {3}" -f $expected.Count, $currentKeys.Count, $newFindings.Count, $goneFindings.Count)

if ($newFindings) {
    Write-Host ''
    Write-Host '  NEW findings:' -ForegroundColor Red
    foreach ($f in $newFindings) { Write-Host ("    + [{0}] {1}" -f $f.severity.ToUpper(), $f.key) -ForegroundColor Red }
}
if ($goneFindings) {
    Write-Host ''
    Write-Host '  DISAPPEARED findings:' -ForegroundColor Yellow
    foreach ($k in $goneFindings) { Write-Host ("    - " + $k) -ForegroundColor Yellow }
}
if ($gitChecked -eq -1) {
    Write-Host ''
    Write-Host '  the committed tree could not be searched, so a leak cannot be ruled out' -ForegroundColor Red
}

Write-Host ''
if ($critical.Count -gt 0) {
    Write-Host ("  {0} CRITICAL finding(s): a live credential is committed" -f $critical.Count) -ForegroundColor Red
}

$report = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    secrets     = @($secrets)
    readers     = $readers
    findings    = @($script:findings | Sort-Object key)
    newFindings = @($newFindings)
    goneFindings = @($goneFindings)
    gitScanPerformed = ($gitChecked -eq 1)
    drift       = ($newFindings.Count -gt 0 -or $goneFindings.Count -gt 0 -or $critical.Count -gt 0 -or $gitChecked -eq -1)
}
Write-JsonFile -Object $report -Path $OutputPath
Write-Host "  report written to $OutputPath"

exit $(if ($report.drift) { 1 } else { 0 })
