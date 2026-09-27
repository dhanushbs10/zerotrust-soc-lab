<#
    Runs every catalogued privilege path and reports a single verdict.

    Phase 4's bar is that each documented path is walkable by script, and this
    is what holds that bar on every commit. It is a CI gate, not a demo: exit 0
    means every path's assertions held against the live cluster, and exit 1
    means at least one of them changed shape.

    Why a runner at all
    -------------------
    Five scripts that each exit non-zero on failure are five things to remember
    to run. The value here is not convenience, it is that a path which stops
    being walkable is a *finding* -- the lab drifted, or a claim in the catalogue
    was never true -- and it should break the build the same day it happens
    rather than being noticed later by someone reading a report.

    Why a summary is written
    ------------------------
    .telemetry/walk-summary.json is the machine-readable record, and later
    phases consume it rather than re-deriving anything: the risk graph in Phase 6
    needs to know which paths were actually demonstrated, and the purple team
    chain in Phase 8 needs to know the ATT&CK IDs each one claims. Deriving
    that from five sets of console output would mean parsing human-readable
    text, which is how a lab ends up asserting things nobody measured.

    The summary deliberately records only verdicts and counts. It never records
    a credential, a token, or a password, because a file in a git repository is
    the wrong place for one even when the repository is ignored.
#>

[CmdletBinding()]
param(
    # Run one path by id, e.g. -Only PP-01. Useful when a single path is being
    # worked on; the full sweep is the default because the point is the sweep.
    [string] $Only = '',

    # Keep going after a failure so one broken path does not hide the state of
    # the others.
    #
    # This is now the DEFAULT, which is a change. It used to be opt-in, and
    # measured cost: WP-02 failed three assertions transiently at 20:17 on
    # 2026-09-26, the sweep stopped there, SP-01 never ran, and the summary
    # claimed "6 paths, 39/42 assertions, 3 failed". Re-running WP-02 alone
    # passed 5/5 and a full sweep passed 54/54, so nothing had actually drifted
    # -- but the report said the lab had regressed and said it with a confident,
    # plausible number. A single flaky path was enough to make the whole sweep
    # lie, which is the failure mode this project keeps having to relearn in a
    # new place.
    #
    # Stopping early is still available for when you want to stop at the first
    # broken path, e.g. while bisecting a change.
    [switch] $StopOnFirstFailure
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

. "$PSScriptRoot\lib\attacklib.ps1"

# The catalogue is the source of truth for which paths exist. Adding a walk
# script without adding it here means it silently never runs, so the list is
# explicit and the runner checks the catalogue agrees.
$paths = @(
    @{ id = 'PP-01'; file = 'walk-pp-01-cluster-admin.ps1';  kind = 'privilege path' }
    @{ id = 'PP-02'; file = 'walk-pp-02-sensor-reach.ps1';   kind = 'compensating control' }
    @{ id = 'PP-03'; file = 'walk-pp-03-token-mint.ps1';      kind = 'privilege path' }
    @{ id = 'PP-04'; file = 'walk-pp-04-portforward.ps1';    kind = 'privilege path' }
    @{ id = 'WP-01'; file = 'walk-wp-01-frontend-root.ps1';   kind = 'workload weakness' }
    @{ id = 'WP-02'; file = 'walk-wp-02-sensor-token.ps1';   kind = 'workload weakness' }
    @{ id = 'SP-01'; file = 'walk-sp-01-configmap-leak.ps1'; kind = 'stored secret' }
)

if ($Only) {
    $paths = @($paths | Where-Object { $_.id -eq $Only })
    if ($paths.Count -eq 0) {
        Write-Host "no path with id '$Only'. Known ids: $($paths.id -join ', ')" -ForegroundColor Red
        exit 1
    }
}

if (-not (Assert-ClusterReady)) {
    Write-Host 'cluster is not reachable; refusing to report paths as walkable' -ForegroundColor Red
    exit 1
}

# Cross-check against the catalogue so a path cannot be quietly deleted from one
# place and left in the other. The catalogue heads each path with "## PP-01 - ..."
# at level 2; the deeper "###" headings are subsections, so the pattern has to
# anchor on exactly two hashes. A pattern that matches nothing reports agreement
# just as confidently as one that matches everything, which is worse.
$catalogPath = Join-Path $PSScriptRoot 'catalog\privilege-paths.md'
$catalogIds = @()
if (Test-Path $catalogPath) {
    $catalogIds = @(Select-String -Path $catalogPath -Pattern '^##\s+([A-Z]{2}-\d{2})\b' -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
}
$scriptIds = @($paths | ForEach-Object { $_.id })
$missingFromRunner = @($catalogIds | Where-Object { $scriptIds -notcontains $_ })
$missingFromCatalog = @($scriptIds | Where-Object { $catalogIds -notcontains $_ })

Write-Host ''
Write-Host ('=' * 78)
Write-Host ("  Phase 4 privilege-path sweep: {0} path(s)" -f $paths.Count)
Write-Host ('=' * 78)

if ($missingFromRunner.Count -gt 0) {
    Write-Host ("  catalogue lists {0} but no walk script runs it: {1}" -f $missingFromRunner.Count, ($missingFromRunner -join ', ')) -ForegroundColor Red
}
if ($missingFromCatalog.Count -gt 0) {
    Write-Host ("  walk script runs {0} but the catalogue does not document it: {1}" -f $missingFromCatalog.Count, ($missingFromCatalog -join ', ')) -ForegroundColor Red
}
if ((Test-Path $catalogPath) -and $catalogIds.Count -eq 0) {
    # The heading pattern no longer matches the catalogue. Every comparison below
    # would then trivially agree, so this is reported as a failure of the check
    # rather than as a clean bill of health.
    Write-Host '  could not read any path ids out of the catalogue; the cross-check is not working' -ForegroundColor Red
}

$results = @()
foreach ($p in $paths) {
    $full = Join-Path $PSScriptRoot $p.file
    if (-not (Test-Path $full)) {
        Write-Host ("  {0}: MISSING {1}" -f $p.id, $p.file) -ForegroundColor Red
        $results += [pscustomobject]@{ id = $p.id; file = $p.file; kind = $p.kind; passed = 0; failed = 1; exitCode = 127; attackIds = @() }
        continue
    }

    Write-Host ''
    Write-Host ("  ---- {0}  ({1}) ----" -f $p.id, $p.kind)

    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $full 2>&1 | Out-String
    $code = $LASTEXITCODE

    $passed = @([regex]::Matches($out, '\[PASS\]')).Count
    $failed = @([regex]::Matches($out, '\[FAIL\]')).Count
    $attackIds = @([regex]::Matches($out, '\[(T\d{4}(?:\.\d{3})?)\]') |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique | Sort-Object)

    # A failed path is re-run once before it is called CHANGED.
    #
    # Measured twice, on two different paths. WP-02 failed three assertions
    # during a sweep at 20:17 and passed 5/5 immediately afterwards; PP-02 failed
    # one assertion during a sweep and passed 7/7 when run alone. Both are the
    # walks racing the rest of the suite -- reachability probes and API calls
    # under load. Neither was the path changing shape.
    #
    # The distinction matters because "CHANGED" is a finding. A lab that reports
    # a finding on a transient teaches its readers to discount findings, which
    # costs more than the flake ever did. So a path that fails and then passes on
    # an immediate retry is reported FLAKY, which is a different claim and a
    # truthful one: it passed, but not first time.
    $retried = $false
    $firstCode = $code
    if ($code -ne 0) {
        Write-Host ("      {0} failed; re-running once to tell CHANGED from flaky" -f $p.id) -ForegroundColor DarkGray
        $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $full 2>&1 | Out-String
        $code = $LASTEXITCODE
        $passed = @([regex]::Matches($out, '\[PASS\]')).Count
        $failed = @([regex]::Matches($out, '\[FAIL\]')).Count
        $retried = $true
        $flaky = ($code -eq 0)
    }
    else {
        $flaky = $false
    }

    # Any path that exits non-zero without reporting a failure assertion has
    # crashed rather than measured something. That is a different problem from a
    # drifted path and it is worth saying which one happened.
    $crashed = ($code -ne 0 -and $failed -eq 0)

    $verdict = if ($code -eq 0) { $(if ($flaky) { 'FLAKY' } else { 'walkable' }) }
               elseif ($crashed) { 'ERRORED' }
               else { 'CHANGED' }
    $colour = switch ($verdict) { 'walkable' { 'Green' } 'FLAKY' { 'Yellow' } 'CHANGED' { 'Yellow' } default { 'Red' } }

    Write-Host ("      {0,-9} exit={1}  {2} passed, {3} failed   ATT&CK: {4}" -f `
        $verdict, $code, $passed, $failed, ($attackIds -join ', ')) -ForegroundColor $colour

    if ($flaky) {
        Write-Host ("      FLAKY: failed with exit {0} on the first run, passed on an immediate retry." -f $firstCode) -ForegroundColor Yellow
        Write-Host '      The path is walkable, but it did not go straight to it. That is worth' -ForegroundColor DarkGray
        Write-Host '      knowing and is not the same claim as a clean pass.' -ForegroundColor DarkGray
    }

    if ($crashed) {
        ($out -split "`n" | Where-Object { $_ -match 'Exception|cannot bind|is not valid|not recognized|Unable to' } |
            Select-Object -First 3 | ForEach-Object { Write-Host ("      {0}" -f $_.Trim()) -ForegroundColor Red })
    } elseif ($failed -gt 0) {
        ($out -split "`n" | Where-Object { $_ -match '^\s*\[FAIL\]' -or $_ -match '^\s+step \d+: expected' } |
            ForEach-Object { Write-Host ("      {0}" -f $_.Trim()) -ForegroundColor Yellow })
    }

    $results += [pscustomobject]@{
        id        = $p.id
        file      = $p.file
        kind      = $p.kind
        verdict   = $verdict
        passed    = $passed
        failed    = $failed
        exitCode  = $code
        firstExitCode = $firstCode
        retried   = $retried
        attackIds = $attackIds
    }

    if ($code -ne 0 -and $StopOnFirstFailure) { break }
}

# ---------------------------------------------------------------------------
$totalPassed = ($results | Measure-Object -Property passed -Sum).Sum
$totalFailed = ($results | Measure-Object -Property failed -Sum).Sum
$notWalkable = @($results | Where-Object { $_.exitCode -ne 0 })
$flakyPaths = @($results | Where-Object { $_.verdict -eq 'FLAKY' })
$allAttackIds = @($results | ForEach-Object { $_.attackIds } | Select-Object -Unique | Sort-Object)

# A sweep that stopped early, or whose catalogue cross-check disagreed, produced
# a summary that reads exactly like a lab with fewer paths in it. Recording what
# was *supposed* to run alongside what did is what lets a consumer tell "6 of 7
# paths walked and 3 assertions failed" from "6 of 7 paths walked, the 7th never
# ran, and nothing failed". Both used to be the same file with the same numbers.
$pathsExpected = @($paths).Count
$pathsWalkedCount = $results.Count
$complete = ($pathsWalkedCount -eq $pathsExpected) -and `
            ($missingFromRunner.Count -eq 0) -and `
            ($missingFromCatalog.Count -eq 0) -and `
            (@($results | Where-Object { $_.exitCode -eq 127 }).Count -eq 0)

Write-Host ''
Write-Host ('=' * 78)
Write-Host ("  {0} path(s), {1} assertion(s) held, {2} failed" -f $results.Count, $totalPassed, $totalFailed) -ForegroundColor $(if ($totalFailed -eq 0 -and $notWalkable.Count -eq 0) { 'Green' } else { 'Red' })
if ($flakyPaths.Count -gt 0) {
    Write-Host ("  {0} path(s) were FLAKY: failed first, passed on retry ({1}). The build does not fail" -f `
        $flakyPaths.Count, (($flakyPaths | ForEach-Object { $_.id }) -join ', ')) -ForegroundColor Yellow
    Write-Host '  on these, because they are walkable -- but a path that cannot go straight to it is worth' -ForegroundColor DarkGray
    Write-Host '  knowing about, and it is a different claim from a clean pass.' -ForegroundColor DarkGray
}
if (-not $complete) {
    Write-Host ("  PARTIAL SWEEP: {0} of {1} catalogued path(s) were walked." -f $pathsWalkedCount, $pathsExpected) -ForegroundColor Yellow
    Write-Host '  Treat the totals above as covering fewer paths than the catalogue, not as a smaller lab.' -ForegroundColor Yellow
}
Write-Host ("  ATT&CK techniques walked: {0}" -f ($allAttackIds -join ', '))
if ($missingFromRunner.Count -eq 0 -and $missingFromCatalog.Count -eq 0 -and $catalogIds.Count -gt 0) {
    Write-Host ("  catalogue and runner agree on {0} path(s): {1}" -f $catalogIds.Count, ($catalogIds -join ', '))
}
Write-Host ('=' * 78)

# Machine-readable record for later phases. Verdicts and ATT&CK ids only.
$telemetryDir = Join-Path (Split-Path $PSScriptRoot -Parent) '.telemetry'
if (-not (Test-Path $telemetryDir)) { New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null }

$summary = [pscustomobject]@{
    generatedAt  = (Get-Date).ToUniversalTime().ToString('o')
    note         = 'Produced by attack/run-all.ps1. Verdicts and ATT&CK ids only; no credential, token or password is recorded here.'
    pathsWalked  = $results.Count
    pathsExpected = $pathsExpected
    complete     = $complete
    assertions   = [pscustomobject]@{ held = $totalPassed; failed = $totalFailed }
    attackIds    = $allAttackIds
    catalogAgrees = [pscustomobject]@{
        catalogOnly  = @($missingFromRunner)
        runnerOnly   = @($missingFromCatalog)
    }
    results      = @($results | ForEach-Object {
        [pscustomobject]@{
            id        = $_.id
            file      = $_.file
            kind      = $_.kind
            verdict   = $_.verdict
            exitCode  = $_.exitCode
            firstExitCode = $_.firstExitCode
            retried   = $_.retried
            passed    = $_.passed
            failed    = $_.failed
            attackIds = @($_.attackIds)
        }
    })
    flakyPaths   = @($flakyPaths | ForEach-Object { $_.id })
}
$summaryPath = Join-Path $telemetryDir 'walk-summary.json'
[System.IO.File]::WriteAllText(
    $summaryPath,
    (($summary | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n",
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  summary written to .telemetry\walk-summary.json")
Write-Host ''

exit $(if ($notWalkable.Count -gt 0) { 1 } else { 0 })
