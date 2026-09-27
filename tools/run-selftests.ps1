<#
.SYNOPSIS
    Runs every lab self-test that does not need a live cluster, and fails if
    any of them fails.

.DESCRIPTION
    The lab has two classes of test and the distinction matters, because
    conflating them is how a broken check gets reported as a passing gate.

      Cluster-free   these run anywhere, in a hook, in CI, in under a minute.
                     They are the ones that can actually block a commit.

      Needs cluster  these spawn probe pods and shell into workloads, so they
                     can only run against a live soc-lab. tools/test-boundaries.ps1
                     and the Phase 4 attack sweeps are in this class.

    Only the cluster-free set is run here. That is a deliberate limit, not an
    oversight: a hook that silently skipped the slow tests would read as
    "tests are enforced" when in fact only half of them are.

    Why this exists
    ---------------
    Commit 18a2736 changed the contract of Get-ArrayOf without updating the
    two call sites written against the old one. Every event then appeared
    untagged and the coverage report named a Phase 7 work list that was
    wrong. test-tag-attack-ids.ps1 already caught it -- its seventh fixture
    requires a clean pass -- but the suite is run by hand, so the fix shipped
    with its own test failing. af24b8c fixed the bug. This script is what
    stops the next one from shipping the same way.

.OUTPUTS
    Exit 0 when every suite passed, 1 when any suite failed. The failing
    suite's own output is passed through rather than summarised, because a
    gate that reports "something failed" makes people go and find out what.

.EXAMPLE
    .\tools\run-selftests.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

$projectRoot = Split-Path -Parent $PSScriptRoot

# Each suite is invoked as its own process on purpose. Dot-sourcing or
# in-process invocation would let one suite's Set-StrictMode and
# $ErrorActionPreference leak into the next, so a suite that passed in
# isolation could fail here for a reason that has nothing to do with it.
$suites = @(
    [pscustomobject]@{
        name = 'telemetry/test-tag-attack-ids.ps1'
        why  = 'ATT&CK registry can fail, and maps telemetry to techniques'
        path = Join-Path $projectRoot 'telemetry\test-tag-attack-ids.ps1'
        exe  = 'powershell'
        args = @()
    }
    [pscustomobject]@{
        name = 'graph/test-reachability-selftest.ps1'
        why  = 'reachability derivation can fail, under mutation'
        path = Join-Path $projectRoot 'graph\test-reachability-selftest.ps1'
        exe  = 'powershell'
        args = @()
    }
    [pscustomobject]@{
        name = 'tools/scan-pods.ps1 -SelfTest'
        why  = 'the pod inventory check can report drift, in both directions'
        path = Join-Path $projectRoot 'tools\scan-pods.ps1'
        exe  = 'powershell'
        args = @('-SelfTest')
    }
    [pscustomobject]@{
        name = 'detections/engine/test_sigmalite.py'
        why  = 'the Sigma evaluator can be wrong, under mutation'
        path = Join-Path $projectRoot 'detections\engine\test_sigmalite.py'
        exe  = 'python'
    }
    [pscustomobject]@{
        name = 'dashboard/test_redaction.py'
        why  = 'the redactor can leak a credential, under mutation'
        path = Join-Path $projectRoot 'dashboard\test_redaction.py'
        exe  = 'python'
    }
    [pscustomobject]@{
        name = 'dashboard/test_server.py'
        why  = 'no secret leaves a response, and no endpoint runs a command'
        path = Join-Path $projectRoot 'dashboard\test_server.py'
        exe  = 'python'
    }
)

$results = @()
$failed = 0

Write-Host ''
Write-Host 'cluster-free self-tests' -ForegroundColor Cyan
Write-Host '------------------------' -ForegroundColor DarkGray

foreach ($s in $suites) {
    if (-not (Test-Path -LiteralPath $s.path)) {
        Write-Host ("  [FAIL] {0} -- file not found at {1}" -f $s.name, $s.path) -ForegroundColor Red
        $results += [pscustomobject]@{ suite = $s.name; exit = 1; present = $false }
        $failed++
        continue
    }

    # Each suite is invoked as its own process on purpose. Dot-sourcing or
    # in-process invocation would let one suite's Set-StrictMode and
    # $ErrorActionPreference leak into the next, so a suite that passed in
    # isolation could fail here for a reason that has nothing to do with it.
    #
    # The three Python suites were added after an audit found they ran nowhere.
    # They need no cluster and no telemetry -- the redaction suite falls back to
    # a clearly-fake placeholder on a fresh clone and the server suite skips the
    # preconditions that need collected events -- and they cover the controls
    # that matter most here: that a credential cannot leave a response, and that
    # no endpoint accepts a command. Neither was enforced by any hook.
    if ($s.exe -eq 'python') {
        & python $s.path 2>&1 | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkGray }
    }
    else {
        $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $s.path) + @($s.args)
        & powershell @argv 2>&1 |
            ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkGray }
    }
    $code = $LASTEXITCODE

    if ($code -eq 0) {
        Write-Host ("  [ok]   {0}  ({1})" -f $s.name, $s.why) -ForegroundColor Green
    }
    else {
        Write-Host ("  [FAIL] {0} exit {1}  ({2})" -f $s.name, $code, $s.why) -ForegroundColor Red
        $failed++
    }
    $results += [pscustomobject]@{ suite = $s.name; exit = $code; present = $true }
}

Write-Host ''
Write-Host ("  {0} suite(s) run, {1} failed" -f $results.Count, $failed) -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })

# The guard the rest of this project keeps having to relearn: a runner that
# ran nothing must not report success. If the suite list is ever emptied by a
# bad merge, this fails loudly instead of passing vacuously.
if ($results.Count -eq 0) {
    Write-Host '  [FAIL] no suites ran. An empty suite list is a broken gate, not a passing one.' -ForegroundColor Red
    exit 1
}

if ($failed -gt 0) { exit 1 }
exit 0
