<#
.SYNOPSIS
    Proves telemetry\tag-attack-ids.ps1 fails when it should.

.DESCRIPTION
    A coverage checker is only worth having if it can fail. The bug this project
    has hit repeatedly is a check that passes because it examined nothing, or
    because its condition is never true, and it has happened five times: four
    in the Phase 4 harness and once in Phase 5, where a counter that did not
    move was read as deduplication when the probe had never run.

    A checker is more exposed to that failure than a harness, because a checker
    that always passes looks exactly like a checker confirming the lab is
    healthy. So this script feeds the checker seven fixtures and asserts the
    exit code of each. Six must fail, and one must pass.

    The six failures are chosen to cover each distinct way the checker could
    stop discriminating:

      untagged event on a schema that must always be tagged, so the "every
        event carries a technique" claim is actually load-bearing
      a technique id that is not in the known-technique table, so a collector
        cannot invent a mapping
      a schema that is not in the registry, so unmapped telemetry cannot pass
        quietly
      an untagged token request whose requesterClass is off-baseline, which is
        the case that proves the exemption is evaluated against the event's own
        data rather than merely checking that a tag is absent
      an untagged cross-zone flow from a real workload rather than the lab's
        own sensor, which is the case that would be a missed detection
      an empty input file, which is the vacuous pass in its plainest form

    The seventh fixture is entirely valid and must pass. Without it, a checker
    that failed on everything would satisfy the other six, and that is the same
    failure wearing the opposite sign.

.EXAMPLE
    .\test-tag-attack-ids.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$checker = Join-Path $PSScriptRoot 'tag-attack-ids.ps1'
if (-not (Test-Path -LiteralPath $checker)) {
    throw "checker not found at $checker"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('tagcheck-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

$validNetwork = @'
{"schema":"network/denial-counter/v1","candidateTechniques":[{"id":"T1046","name":"Network Service Scanning"}],"chain":"c1","subject":{"pod":"p","namespace":"n"},"counter":{"deniedPackets":5}}
{"schema":"network/observed-flow/v1","scope":"lab-zone","source":{"role":"instrumentation","serviceAccount":"sa-telemetry-agent"},"dest":{"serviceAccount":"sa-orders-api"},"destPort":"8080","candidateTechniques":[{"id":"T1021","name":"Remote Services"}]}
{"schema":"network/observed-flow/v1","scope":"cluster-internal","source":{"role":"workload"},"dest":{"serviceAccount":"x"},"candidateTechniques":[]}
'@

$validRuntime = @'
{"schema":"runtime/container-exec/v1","candidateTechniques":[{"id":"T1609.001","name":"Container Administration Command"}],"command":"id"}
{"schema":"runtime/pod-log-read/v1","candidateTechniques":[{"id":"T1552.001","name":"Unsecured Credentials: Credentials In Files"}],"pod":"orders-api-1"}
{"schema":"runtime/token-request/v1","requesterClass":"kubelet","candidateTechniques":[]}
{"schema":"runtime/workload-identity/v1","serviceAccount":"sa-orders-api","candidateTechniques":[]}
'@

$smuggledSchema = '{"schema":"runtime/smuggled/v1","candidateTechniques":[{"id":"T1609.001"}]}'

$cases = @(
    [pscustomobject]@{
        name = 'untagged event on an always-tagged schema'
        net = $validNetwork
        rt = $validRuntime.Replace('"command":"id"}', '"command":"id","candidateTechniques":[]}')
        expect = 1
    }
    [pscustomobject]@{
        name = 'technique id absent from the known-technique table'
        net = $validNetwork
        rt = $validRuntime.Replace('T1609.001', 'T9999.999')
        expect = 1
    }
    [pscustomobject]@{
        name = 'schema present in telemetry but absent from the registry'
        net = $validNetwork
        rt = $validRuntime + "`n" + $smuggledSchema
        expect = 1
    }
    [pscustomobject]@{
        name = 'untagged token request whose requesterClass is off-baseline'
        net = $validNetwork
        rt = $validRuntime.Replace('"requesterClass":"kubelet"', '"requesterClass":"other"')
        expect = 1
    }
    [pscustomobject]@{
        name = 'untagged cross-zone flow from a real workload, not the sensor'
        net = $validNetwork.Replace('"role":"instrumentation"', '"role":"workload"').Replace('{"id":"T1021","name":"Remote Services"}', '[]')
        rt = $validRuntime
        expect = 1
    }
    [pscustomobject]@{
        name = 'empty input file'
        net = $validNetwork
        rt = ''
        expect = 1
    }
    [pscustomobject]@{
        name = 'all six schemas present and correctly tagged'
        net = $validNetwork
        rt = $validRuntime
        expect = 0
    }
)

$pass = 0
$fail = 0

Write-Host 'tag-attack-ids: proving the checker can fail' -ForegroundColor Cyan
Write-Host ''

foreach ($c in $cases) {
    $n = Join-Path $work 'net.jsonl'
    $r = Join-Path $work 'rt.jsonl'
    $rep = Join-Path $work 'report.json'
    Set-Content -LiteralPath $n -Value $c.net -Encoding ascii
    Set-Content -LiteralPath $r -Value $c.rt -Encoding ascii

    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $checker -NetworkEvents $n -RuntimeEvents $r -ReportPath $rep 2>&1 | Out-String
    $code = $LASTEXITCODE

    if ($code -eq $c.expect) {
        $pass++
        Write-Host ("  [ok]   exit {0}  {1}" -f $code, $c.name) -ForegroundColor Green
    }
    else {
        $fail++
        Write-Host ("  [FAIL] exit {0}, expected {1}  {2}" -f $code, $c.expect, $c.name) -ForegroundColor Red
        foreach ($line in @(($out -split "`n") | Where-Object { $_ -match 'FAIL' } | Select-Object -First 3)) {
            Write-Host ("         " + $line.Trim()) -ForegroundColor DarkGray
        }
    }
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("  {0} passed, {1} failed, of {2} case(s)" -f $pass, $fail, $cases.Count) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host '  a checker that cannot fail is a checker that has not been tested' -ForegroundColor DarkGray

exit $(if ($fail -eq 0) { 0 } else { 1 })
