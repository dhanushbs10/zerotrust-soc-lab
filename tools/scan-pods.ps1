<#
.SYNOPSIS
    Reports any pod in a lab namespace that no manifest declares.

.DESCRIPTION
    This check exists because of a specific, measured failure. A purple-team run
    at 19:14:03 died inside Invoke-InPod, the terminating error skipped the
    cleanup at the end of chain-purple-team.ps1, and pod/exfil-20260926-191403
    survived. It was still there six hours later, in the business zone, carrying
    app=orders-api and a service account, created by an attack script and
    declared by no manifest.

    It cost more than a dirty cluster. tools/scan-images.ps1 resolved the
    app=orders-api label, found the attacker's pod, and reported that the
    workload's image had changed from nginx to postgres. The image never
    changed. A supply-chain scanner reported the lab as tampered with because an
    attack script had left litter, and nothing in the repository could tell the
    difference.

    Twenty-eight commits of hooks, self-tests, drift scanning and boundary
    assertions all passed while that pod sat there. Every one of them was
    checking something; none of them asked what pods exist.

    Expectations are written out longhand
    --------------------------------------
    The expected inventory below is a literal list, not something derived from
    the manifests. A scanner that reads the workload YAML and reports that the
    cluster matches the workload YAML cannot fail, because the only way it can
    disagree is if the YAML is wrong in the same way twice. The list here is the
    specification, and it is short enough to read and argue with.

    kube-system is excluded on purpose
    ----------------------------------
    The cluster's own components are not this lab's business, and their names
    carry ReplicaSet hashes that change on every apply. Listing them would make
    the check fail constantly and train people to ignore it. A check that cries
    wolf is worse than no check, and that is the failure mode this one has to
    avoid.

    Drift is judged in both directions
    ----------------------------------
    An unexpected pod is drift, and so is a missing expected one. The second is
    the more likely to be missed: a workload that silently vanished looks like a
    clean cluster to every other tool here.

.PARAMETER OutputPath
    Where to write the JSON report. Defaults to .telemetry\pod-scan.json

.PARAMETER SelfTest
    Prove the comparison can fail. Runs the classifier against deliberately wrong
    inputs and requires each to be reported as drift. Exits 0 only if every case
    behaved.

.EXAMPLE
    .\tools\scan-pods.ps1

.EXAMPLE
    .\tools\scan-pods.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $SelfTest
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot '.telemetry\pod-scan.json' }

# The specification. namespace/workload-name -> what it is.
$expected = [ordered]@{
    'zerotrust/web-frontend'             = 'business web frontend (the WP-01 weakness)'
    'zerotrust/orders-api'               = 'business API (the PP-03 and PP-04 target)'
    'zerotrust/postgres'                 = 'the SP-01 database (a StatefulSet, so its pod is postgres-0)'
    'zerotrust-build/build-runner'       = 'the CI runner holding cluster-admin (PP-01)'
    'zerotrust-observe/telemetry-agent'  = 'the reachability sensor (PP-02)'
}

$labNamespaces = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

function Test-AgainstExpected {
    <#
        Pure classifier: given the observed "ns/pod" set, return the drift.

        Split out from the kubectl calls so -SelfTest can drive it with inputs
        no cluster would ever produce. That is the whole reason it is a function:
        a drift check whose only test is "run it against a correct cluster" has
        never been shown to notice an incorrect one.

        The matching rule
        -----------------
        An expected entry names a WORKLOAD; what arrives names a POD. A
        Deployment's pod carries a ReplicaSet hash and a random suffix, and a
        StatefulSet's carries an ordinal, so neither is ever equal to the
        workload name. One rule covers every case:

            expected "ns/name" is satisfied by any observed "ns/name" or "ns/name-*"

        The first version compared for equality and a second kept a separate
        prefix table for the StatefulSet. It reported all five healthy workloads
        as unexpected and all five as missing, simultaneously, on a perfectly
        correct cluster -- and it reported that with the same confident formatting
        as a real finding. Three of the six self-test cases caught it, which is
        the argument for having written them.
    #>
    param([string[]] $Observed)

    $unexpected = @()
    $missing    = @()

    $satisfies = {
        param([string] $Spec, [string] $Actual)
        if ($Spec -eq $Actual) { return $true }
        $specNs = ($Spec -split '/')[0]
        $actNs  = ($Actual -split '/')[0]
        $specNm = ($Spec -split '/')[1]
        $actNm  = ($Actual -split '/')[1]
        if ($specNs -ne $actNs) { return $false }
        return $actNm.StartsWith($specNm + '-')
    }

    foreach ($o in $Observed) {
        $matched = $false
        foreach ($e in $expected.Keys) {
            if (& $satisfies $e $o) { $matched = $true; break }
        }
        if (-not $matched) { $unexpected += $o }
    }

    foreach ($e in $expected.Keys) {
        $present = $false
        foreach ($o in $Observed) {
            if (& $satisfies $e $o) { $present = $true; break }
        }
        if (-not $present) { $missing += $e }
    }

    return [pscustomobject]@{ unexpected = $unexpected; missing = $missing }
}

# ---------------------------------------------------------------------------
if ($SelfTest) {
    $cases = @(
        @{ name = 'the correct inventory is clean'
           observed = @('zerotrust/web-frontend','zerotrust/orders-api','zerotrust/postgres-0',
                        'zerotrust-build/build-runner','zerotrust-observe/telemetry-agent')
           wantUnexpected = 0; wantMissing = 0 }
        @{ name = 'a leaked foothold is unexpected'
           observed = @('zerotrust/web-frontend','zerotrust/orders-api','zerotrust/postgres-0',
                        'zerotrust-build/build-runner','zerotrust-observe/telemetry-agent',
                        'zerotrust/exfil-20260926-191403')
           wantUnexpected = 1; wantMissing = 0 }
        @{ name = 'a probe pod is unexpected too'
           observed = @('zerotrust/web-frontend','zerotrust/orders-api','zerotrust/postgres-0',
                        'zerotrust-build/build-runner','zerotrust-observe/telemetry-agent',
                        'zerotrust/probe-orders-api')
           wantUnexpected = 1; wantMissing = 0 }
        @{ name = 'a vanished workload is missing'
           observed = @('zerotrust/web-frontend','zerotrust/postgres-0',
                        'zerotrust-build/build-runner','zerotrust-observe/telemetry-agent')
           wantUnexpected = 0; wantMissing = 1 }
        @{ name = 'both directions at once'
           observed = @('zerotrust/web-frontend','zerotrust/orders-api',
                        'zerotrust-build/build-runner','zerotrust/exfil-1')
           wantUnexpected = 1; wantMissing = 2 }
        @{ name = 'an empty cluster is entirely missing, not clean'
           observed = @()
           wantUnexpected = 0; wantMissing = 5 }
    )

    $failed = 0
    Write-Host 'scan-pods self-test' -ForegroundColor Cyan
    Write-Host ('-' * 70)
    foreach ($c in $cases) {
        $r = Test-AgainstExpected -Observed $c.observed
        $ok = ($r.unexpected.Count -eq $c.wantUnexpected) -and ($r.missing.Count -eq $c.wantMissing)
        if ($ok) {
            Write-Host ("  [ok]   {0}" -f $c.name) -ForegroundColor Green
        }
        else {
            Write-Host ("  [FAIL] {0}: got {1} unexpected / {2} missing, want {3} / {4}" -f `
                $c.name, $r.unexpected.Count, $r.missing.Count, $c.wantUnexpected, $c.wantMissing) -ForegroundColor Red
            $failed++
        }
    }
    Write-Host ('-' * 70)
    if ($failed -gt 0) {
        Write-Host ("  FAIL  {0} of {1} case(s)" -f $failed, $cases.Count) -ForegroundColor Red
        exit 1
    }
    Write-Host ("  PASS  {0} case(s); the classifier reports drift when there is drift" -f $cases.Count) -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'pod inventory' -ForegroundColor Cyan
Write-Host ('=' * 70)

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Host '  kubectl not on PATH' -ForegroundColor Red
    exit 1
}

$rows = @(& kubectl get pods -A --no-headers 2>$null | Where-Object { $_ })
if ($LASTEXITCODE -ne 0 -or $rows.Count -eq 0) {
    Write-Host '  could not list pods; is the cluster up?' -ForegroundColor Red
    exit 1
}

$observed = @()
$skipped = 0
foreach ($row in $rows) {
    $parts = ($row -split '\s+')
    if ($parts.Count -lt 3) { continue }
    $ns = $parts[0]; $name = $parts[1]
    if ($labNamespaces -notcontains $ns) { $skipped++; continue }
    $observed += "$ns/$name"
}

Write-Host ("  lab pods: {0}   (skipped {1} outside the three lab namespaces)" -f $observed.Count, $skipped) -ForegroundColor DarkGray
foreach ($o in ($observed | Sort-Object)) { Write-Host ("    {0}" -f $o) -ForegroundColor DarkGray }

$result = Test-AgainstExpected -Observed $observed

Write-Host ''
if ($result.unexpected.Count -eq 0 -and $result.missing.Count -eq 0) {
    Write-Host '  PASS  the pod inventory matches the specification exactly' -ForegroundColor Green
}
else {
    if ($result.unexpected.Count -gt 0) {
        Write-Host ("  {0} pod(s) that no manifest declares:" -f $result.unexpected.Count) -ForegroundColor Red
        foreach ($u in $result.unexpected) {
            Write-Host ("    {0}" -f $u) -ForegroundColor Red
        }
        Write-Host ''
        Write-Host '    An unexpected pod in a lab namespace is either a leaked attack artefact or a' -ForegroundColor DarkGray
        Write-Host '    change nobody recorded. Both are drift. If it came from an attack script, the' -ForegroundColor DarkGray
        Write-Host '    script leaked it; attack/chain-purple-team.ps1 sweeps its own pods before and' -ForegroundColor DarkGray
        Write-Host '    after a run and should never leave one behind.' -ForegroundColor DarkGray
    }
    if ($result.missing.Count -gt 0) {
        Write-Host ("  {0} expected workload(s) absent:" -f $result.missing.Count) -ForegroundColor Red
        foreach ($m in $result.missing) { Write-Host ("    {0}  ({1})" -f $m, $expected[$m]) -ForegroundColor Red }
    }
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$report = [pscustomobject]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    note        = 'Produced by tools/scan-pods.ps1. Pod names only; no spec, env or secret is recorded.'
    expected    = @($expected.Keys)
    observed    = @($observed | Sort-Object)
    unexpected  = @($result.unexpected)
    missing     = @($result.missing)
    passed      = ($result.unexpected.Count -eq 0 -and $result.missing.Count -eq 0)
}
[System.IO.File]::WriteAllText(
    $OutputPath,
    (($report | ConvertTo-Json -Depth 4) -replace "`r`n", "`n") + "`n",
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host ''
Write-Host ("  report written to {0}" -f $OutputPath) -ForegroundColor DarkGray

exit $(if ($report.passed) { 0 } else { 1 })
