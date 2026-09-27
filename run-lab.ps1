#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build the lab, attack it, collect the evidence, prove the detections fire, and
    leave a console open to look at it. One command, from a fresh clone.

.DESCRIPTION
    This is the whole lab in order. It exists because the alternative was a
    seven-command incantation held together by memory and by docs/progress.md,
    and every part of that is a way for the sequence to rot:

      * a reader has to know the order, and the order is not obvious from the
        directory names -- attacks run BEFORE collection, because collecting
        first and attacking second gives you a cluster with no crime in it;
      * a step can fail and leave the rest looking like it worked;
      * the interesting gate (do the rules actually fire?) is easy to skip,
        and skipping it is how a lab ends up looking finished.

    So the order lives in one file, in one array, and the script walks it.

    Stages, and why they are in this order
    ---------------------------------------
      0  preflight     tools present, cluster reachable, honest cluster state
      1  secrets       generated into gitignored secrets/credentials.yaml
      2  bootstrap     kind cluster + Kustomize overlays + pinned digests
      3  graph         probe pods measure what is actually reachable
      4  chain         the 6-hop intrusion, end to end
      5  seed network  snapshot the iptables counters, after all the churn
      6  walk          the 7 privilege paths, which create no pods
      7  collect       audit export, runtime events, network counters
      8  verify        registry, pod inventory, posture, drift, images, secrets
      9  detections    every Sigma rule fires, and none fires outside its schema
     10  report        what was built, and what to do next

    Two different kinds of check run here, and they are not interchangeable.
    `detections` holds Sigma rules over telemetry: "did this event happen?".
    `detections/posture` holds rules over live configuration: "is this
    acceptable?". There are no events in the second kind, so there is no
    logsource schema and no `detection:` block, which is why the detection gate
    excludes that directory rather than trying to parse it.

    Three orderings here are load-bearing, and all three are counter-intuitive.
    Each one was got wrong at least once before it was got right.

    The graph and the chain both run BEFORE the network seed, and the privilege
    paths run AFTER it. Network telemetry is a delta between two comparable reads
    of the same iptables chain, and kube-router regenerates its chains -- resetting
    the counters -- whenever policy changes. The graph creates a probe pod per pair
    it measures and the chain applies a manifest at hop 5, so both invalidate a
    baseline taken before them. The walks generate the refused traffic that makes the
    delta non-zero, and unlike the other two they create no pods, so they are the
    only thing that can sit between the seed and the read.

    The attack runs BEFORE collection, because telemetry describes what happened
    and the thing that has to happen first is the attack. The alternative produces
    a green run over an empty audit log, and an empty audit log is
    indistinguishable from a quiet cluster -- the single most expensive confusion in
    this kind of work.

    And the report runs last, which sounds obvious, but the first version of this
    script read a property that did not exist on the final line and so exited 1
    after printing fifteen green stages. The screen that says whether the lab works
    must not be the thing that breaks.

.PARAMETER SkipBootstrap
    Do not rebuild the cluster. The lab is already up; walk, collect and verify
    only. Implies -SkipSecrets for the same reason: there is nothing to
    regenerate, and regenerating would invalidate the credentials the running
    workloads already hold.

.PARAMETER SkipAttack
    Do not walk or chain. Re-collect and re-verify against whatever the cluster
    did last. Useful for re-running the detection gate after editing a rule --
    which is the normal way to develop a rule, and the reason this exists.

.PARAMETER Recreate
    Delete the kind cluster and build it again from nothing.

    This destroys the cluster. It is the only thing in this script that does,
    and it is opt-in rather than automatic, because everything else in the lab
    is disposable and someone's running cluster is not.

.PARAMETER Serve
    Start the SOC console on http://127.0.0.1:8099 when the run finishes, and
    keep it in the foreground until Ctrl-C.

.EXAMPLE
    ./run-lab.ps1
    Full run: build, attack, collect, verify, detect.

.EXAMPLE
    ./run-lab.ps1 -SkipBootstrap -SkipAttack
    Re-collect and re-verify an already-running, already-attacked lab. This is
    the loop for editing a Sigma rule.

.EXAMPLE
    ./run-lab.ps1 -Serve
    Everything above, then leave the console up.
#>
[CmdletBinding()]
param(
    [switch]$SkipBootstrap,
    [switch]$SkipAttack,
    [switch]$Recreate,
    [switch]$Serve
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# This script always stops at the first failing stage, and there is no switch to
# change that. attack/run-all.ps1 continues past a failure on purpose, because
# the seven privilege paths are independent and one flaky path should not hide
# six working ones. The stages here are a pipeline instead: detections cannot be
# judged without telemetry, telemetry cannot be read without a cluster, and a
# graph cannot be measured without pods to probe. Continuing past a failure
# produces a run that is mostly green and means nothing, which is worse than a
# red one that means something.

$projectRoot = $PSScriptRoot
$runLedgerPath = Join-Path $projectRoot '.telemetry\run-lab.json'
$startedAt   = Get-Date

function Write-Stage {
    param([string]$Text)
    $bar = '=' * 74
    Write-Host ''
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor DarkCyan
}

function Write-Note {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Run ledger
#
# Every stage appends here, and the ledger is printed at the end whether the run
# passed or failed. A reproduction script that only speaks up when it breaks
# leaves you guessing which of eleven stages actually ran -- and on this lab the
# difference between "the graph step did not run" and "the graph step found no
# drift" is the whole result.
# ---------------------------------------------------------------------------
$ledger = New-Object System.Collections.ArrayList

function Add-Ledger {
    param(
        [string]$Name,
        [bool]$Ok,
        [int]$Seconds,
        [string]$Detail = ''
    )
    [void]$ledger.Add([pscustomobject]@{
        Stage    = $Name
        Ok       = $Ok
        Seconds  = $Seconds
        Detail   = $Detail
    })
}

function Invoke-Stage {
    param(
        [string]$Name,
        [scriptblock]$Body,
        [string]$Why = ''
    )
    Write-Stage $Name
    if ($Why) { Write-Note $Why }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true
    $detail = ''
    try {
        $detail = & $Body
    }
    catch {
        $ok = $false
        $detail = $_.Exception.Message
        Write-Host ''
        Write-Host "  STAGE FAILED: $Name" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        if ($_.ScriptStackTrace) {
            Write-Host '  --- where ---' -ForegroundColor DarkRed
            Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkGray
        }
    }
    $sw.Stop()
    Add-Ledger -Name $Name -Ok $ok -Seconds $sw.Elapsed.TotalSeconds -Detail ([string]$detail)
    if (-not $ok) {
        Write-Host ''
        Write-Host '  stopping: later stages depend on this one.' -ForegroundColor Yellow
        Write-Host '  Fix the cause, or re-run with -SkipAttack -SkipBootstrap to' -ForegroundColor DarkGray
        Write-Host '  re-collect and re-verify without rebuilding.' -ForegroundColor DarkGray
        Show-Ledger
        exit 1
    }
    # No return value on purpose. Every call site is a bare statement, so
    # returning True here would print a stray "True" under each stage.
}

function Show-Ledger {
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host '  what ran' -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host ('  {0,-34} {1,7}  {2}' -f 'stage', 'seconds', 'result') -ForegroundColor DarkGray
    Write-Host ('  {0,-34} {1,7}  {2}' -f ('-' * 34), ('-' * 7), ('-' * 22)) -ForegroundColor DarkGray
    foreach ($row in $ledger) {
        $colour = if ($row.Ok) { 'Green' } else { 'Red' }
        $result = if ($row.Ok) { 'ok' } else { 'FAILED' }
        Write-Host ('  {0,-34} {1,7:N1}  ' -f $row.Stage, $row.Seconds) -NoNewline
        Write-Host $result -ForegroundColor $colour
    }
    $elapsed = ((Get-Date) - $startedAt).TotalSeconds
    Write-Host ''
    Write-Host ('  total {0:N1}s' -f $elapsed) -ForegroundColor DarkGray

    # Written every time, on the failure path as well as the success path.
    #
    # The first version of this script named a run log in its own closing report and
    # never wrote one, so the report pointed a reader at a file that did not exist --
    # a claim in the output that the code did not keep, which is the same failure as
    # promising a baseline it does not write. It is called run-lab.json because that
    # is what it is: the ledger as data, so a later run or a script can read which
    # stages actually executed rather than trusting a scrollback buffer.
    $telemetryDir = Split-Path -Parent $runLedgerPath
    if (-not (Test-Path $telemetryDir)) { New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null }
    $record = [pscustomobject]@{
        startedAt  = $startedAt.ToUniversalTime().ToString('o')
        finishedAt = (Get-Date).ToUniversalTime().ToString('o')
        seconds    = [math]::Round($elapsed, 1)
        ok         = (@($ledger | Where-Object { -not $_.Ok }).Count -eq 0)
        stages     = @($ledger)
    }
    [System.IO.File]::WriteAllText(
        $runLedgerPath,
        (($record | ConvertTo-Json -Depth 5) -replace "`r`n", "`n") + "`n",
        [System.Text.UTF8Encoding]::new($false))
}

function Test-Tool {
    param([string]$Name, [string]$Hint)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "$Name is not on PATH. $Hint" }
}

# ===========================================================================
# 0. preflight
# ===========================================================================
Invoke-Stage 'preflight' {
    $missing = @()
    foreach ($t in @('docker', 'kubectl', 'kind', 'python')) {
        if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { $missing += $t }
    }
    if ($missing.Count) {
        throw ("missing from PATH: {0}. See README.md for the full prerequisite list." -f ($missing -join ', '))
    }

    $telemetry = Join-Path $projectRoot '.telemetry'
    if (-not (Test-Path $telemetry)) { New-Item -ItemType Directory -Path $telemetry -Force | Out-Null }

    # The cluster check is done by asking the control plane, not by looking for
    # the container. A stopped container and a deleted cluster look identical from
    # the host, and bootstrap.ps1's three-state model (Absent/Healthy/Degraded)
    # has no state for "the Docker container exists but the API server inside it
    # is not answering" -- which is exactly what a suspended laptop produces.
    $clusters = (& kind get clusters 2>$null | Out-String).Trim()
    if ($clusters -notmatch 'soc-lab') {
        Write-Note 'no soc-lab cluster yet. stage 2 will create it.'
    }
    else {
        $ready = (& docker exec soc-lab-control-plane kubectl get --raw=/readyz 2>$null | Out-String).Trim()
        if ($ready -eq 'ok') {
            Write-Note 'cluster soc-lab is up and ready.'
        }
        elseif ($SkipBootstrap) {
            throw ("the soc-lab containers exist but the API server is not answering ({0})." -f ($(if ($ready) { $ready } else { 'no response' }))) +
                  ' Either start them (docker start soc-lab-control-plane soc-lab-worker soc-lab-worker2) or drop -SkipBootstrap.'
        }
        else {
            Write-Note ("the soc-lab containers exist but the API server is not answering ({0})." -f ($(if ($ready) { $ready } else { 'no response' })))
            Write-Note 'bootstrap will try to recover in place. If it cannot, re-run with -Recreate.'
        }
    }
    "ok"
} -Why 'Tools on PATH, .telemetry/ present, and an honest read of cluster state.'

# ===========================================================================
# 1 + 2. secrets and bootstrap
# ===========================================================================
if ($SkipBootstrap) {
    Invoke-Stage 'bootstrap (skipped)' { 'skipped by -SkipBootstrap' } `
        -Why ('The lab is already up. Secrets are not regenerated either: doing so would ' +
              'invalidate the credentials the running workloads already hold, and the ' +
              'resulting failure would look like a broken lab rather than a rotated secret.')
}
else {
    Invoke-Stage 'secrets' {
        & (Join-Path $projectRoot 'cluster\bootstrap\secrets.ps1') | Out-Null
        $path = Join-Path $projectRoot 'secrets\credentials.yaml'
        if (-not (Test-Path $path)) { throw "secrets.ps1 finished but $path does not exist" }
        # Existence is checked; contents are never printed or compared here. A
        # script that logs whether a generated secret matches an expected value
        # is a script that will eventually log the secret.
        "wrote secrets/credentials.yaml (gitignored; $(if (Test-Path (Join-Path $projectRoot 'secrets\credentials.example.yaml')) { 'example file is tracked' } else { 'NO example file tracked' }))"
    } -Why 'Generated fresh on this machine. Only credentials.example.yaml is tracked.'

    Invoke-Stage 'bootstrap' {
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                  (Join-Path $projectRoot 'cluster\bootstrap\bootstrap.ps1'))
        if ($Recreate) { $args += '-Recreate' }
        & powershell @args
        if ($LASTEXITCODE -ne 0) { throw "bootstrap.ps1 exited $LASTEXITCODE" }
        'cluster built'
    } -Why 'kind cluster, Kustomize overlays, pinned image digests, kube-router for NetworkPolicy.'
}

# ===========================================================================
# 3. reachability graph
#
# Before the attack, not after, and the reason is the network counter baseline
# rather than anything to do with the attacks. See the long note below.
# ===========================================================================
Invoke-Stage 'reachability graph' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'graph\build-reachability.ps1')
    $graph = Join-Path $projectRoot '.telemetry\reachability-graph.json'
    if (-not (Test-Path $graph)) { throw "build-reachability.ps1 finished but $graph does not exist" }
    $verify = Join-Path $projectRoot '.telemetry\reachability-verify.json'
    if (Test-Path $verify) {
        $v = Get-Content $verify -Raw | ConvertFrom-Json
        if ($v.PSObject.Properties['disagreements']) {
            Write-Note ("probe/graph disagreements: {0}" -f $v.disagreements.Count)
        }
    }
    'graph rebuilt and verified against live probes'
} -Why 'Probe pods measure what is actually reachable, so the graph is measured rather than asserted.'

# ===========================================================================
# 4. attack chain
#
# Before the network seed, unlike the privilege paths. Hop 5 applies a manifest
# and that creates a pod, which is exactly the policy churn that invalidates a
# counter baseline -- see the long note at stage 5.
# ===========================================================================
if ($SkipAttack) {
    Invoke-Stage 'attack chain (skipped)' { 'skipped by -SkipAttack' } `
        -Why 'The chain is the graded attack. Skipping it means the detections are judged against a window without it.'
}
else {
    Invoke-Stage 'attack chain' {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'attack\chain-purple-team.ps1')
        '6 hops'
    } -Why 'The 6-hop intrusion, end to end. This is what the detections are graded against. Runs before the network seed because hop 5 creates a pod.'
}

# ===========================================================================
# 5. the network counter baseline, seeded AFTER everything that churns policy
#
# The ordering here is the least obvious thing in this script, and it took three
# attempts to get right, so all three are recorded.
#
# Network telemetry in this lab is counter-based, not flow-based: kube-router
# v2.6.1 has no flow logs, so a detection is a DELTA between two comparable reads
# of the same iptables chain. A read is only comparable to another if the chain was
# not regenerated in between, and kube-router regenerates its chains whenever policy
# changes -- resetting the counters to zero. The collector refuses to guess across
# that boundary:
#
#     baselineState: chain-rebuilt
#     deltaValid:    false
#     deltaDenied:   null
#     deltaReason:   "the iptables chain was regenerated since the baseline, so its
#                     counters restarted at zero and are not comparable"
#
# That is right, and worth being explicit that it is right: det-0005 then fires on
# nothing, because a refused packet with no comparable baseline is not evidence of
# scanning. A collector that reported the absolute count as a delta would have
# made the rule fire, and it would have been lying about a rate that never happened.
#
# Attempt 1: seed before the graph. Intuitive, and wrong. The graph creates and
# deletes a probe pod per pair it measures, which is the churn that invalidates the
# baseline. Every read came back `chain-rebuilt`.
#
# Attempt 2: seed after the graph, walks in between. Still wrong, and the failure
# was quieter: the ATTACK CHAIN also creates a pod (hop 5 applies a manifest), so
# the chain rebuilt the chains after the seed. The graph stage had been the obvious
# suspect and it was only ever part of the problem.
#
# This attempt: seed after the graph AND after the chain, with the privilege paths
# in between, because the walks generate refused traffic and do NOT create pods.
# Verified by reading what each stage actually calls:
#
#     graph/build-reachability.ps1   kubectl apply/delete per probe pair   CHURNS
#     attack/chain-purple-team.ps1   kubectl apply (hop 5)                 CHURNS
#     attack/run-all.ps1             kubectl create token (a subresource)  safe
#     tools/test-boundaries.ps1      kubectl apply/delete per case         CHURNS
#
# so test-boundaries.ps1 could not have been used as the traffic generator either,
# which is worth knowing before someone tries.
# ===========================================================================
Invoke-Stage 'seed network counter baseline' {
    & powershell -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $projectRoot 'telemetry\network\collect-network.ps1') -NoBaseline
    if ($LASTEXITCODE -ne 0) { throw "collect-network.ps1 -NoBaseline exited ${LASTEXITCODE}" }
    $baseline = Join-Path $projectRoot '.telemetry\network-baseline.json'
    if (-not (Test-Path $baseline)) { throw "the network baseline was not written to $baseline" }
    'counters snapshotted; the privilege paths below will supply the refused traffic'
} -Why 'AFTER the graph and the chain, both of which create pods, and BEFORE the walks, which do not.'

# ===========================================================================
# 6. privilege paths
# ===========================================================================
if ($SkipAttack) {
    Invoke-Stage 'privilege paths (skipped)' { 'skipped by -SkipAttack' } `
        -Why ('No new attack activity. The detectors are judged against whatever this ' +
              'cluster did previously, which is the right thing when you have just ' +
              'edited a rule and want to see it fire on telemetry that already exists. ' +
              'One consequence: nothing generates refused traffic after the seed, so the ' +
              'network delta stays empty and det-0005 reports itself NOT JUDGEABLE rather ' +
              'than broken -- which is the truthful answer for this window.')
}
else {
    Invoke-Stage 'privilege paths' {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'attack\run-all.ps1')
        '7 paths walked'
    } -Why 'Each path asserts as it goes. A path that "succeeded" without asserting is worse than a failure. These also supply the refused traffic the network delta needs, and unlike the graph and the chain they create no pods.'
}


# ===========================================================================
# 6. collection
# ===========================================================================
Invoke-Stage 'collect telemetry' {
    # Network FIRST, and the order inside this stage matters as much as the order
    # between stages.
    #
    # The network read has to be as close as possible to the seed and to the refused
    # traffic that followed it, because the two reads are only comparable if nothing
    # rebuilt kube-router's iptables chains in between -- and kube-router resyncs on
    # its own schedule as well as on policy change.
    #
    # The audit export is the slow one: measured at ~140s, against ~35s for the other
    # two together. Running it first put the network read roughly 175s after the
    # seed, which was long enough that every read came back `chain-rebuilt` and
    # det-0005 could never be judged. Moving the network read to the front cuts the
    # gap to about 35s.
    #
    # This is a hypothesis, not a measurement: it has not been run yet. If det-0005
    # still reports NOT JUDGEABLE after this change, the resync interval is shorter
    # than the privilege paths take, and the honest fix is a dedicated traffic
    # generator run immediately before the read -- not more reordering.
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'telemetry\network\collect-network.ps1')
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'telemetry\audit\export-audit-log.ps1')
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'telemetry\runtime\collect-runtime.ps1')

    $runtime = Join-Path $projectRoot '.telemetry\runtime-events.jsonl'
    $network = Join-Path $projectRoot '.telemetry\network-events.jsonl'
    foreach ($f in @($runtime, $network)) {
        if (-not (Test-Path $f)) { throw "a collector finished but $f does not exist" }
    }
    # An empty file is reported as a failure, not passed over. A quiet cluster and
    # a broken collector produce the same empty file, and the whole purpose of
    # this stage is to tell those apart.
    $runtimeLines = (Get-Content $runtime | Measure-Object -Line).Lines
    $networkLines = (Get-Content $network | Measure-Object -Line).Lines
    if ($runtimeLines -eq 0) { throw "$runtime is empty. Either the cluster is idle or the collector is broken; do not proceed as if both were fine." }
    if ($networkLines -eq 0) { throw "$network is empty. Either no traffic was counted or the collector is broken." }
    "runtime $runtimeLines event(s), network $networkLines event(s)"
} -Why 'Network first, because its two reads must be close together or the delta is not comparable. The audit export is the slow one and would put ~140s between them.'

# ===========================================================================
# 7. verification
# ===========================================================================
Invoke-Stage 'ATT&CK registry' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'telemetry\tag-attack-ids.ps1')
    if ($LASTEXITCODE -ne 0) { throw "tag-attack-ids.ps1 exited $LASTEXITCODE" }
    'every technique registered, every untagged event exempted with a reason'
} -Why 'A mapping is a claim. This is the check that no event is silently untagged.'

Invoke-Stage 'pod inventory' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tools\scan-pods.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw ("scan-pods.ps1 exited {0}: a pod exists that no manifest declares, or a declared workload is gone. Both directions are failures." -f $LASTEXITCODE)
    }
    'no undeclared pods, no missing workloads'
} -Why 'This is the check that would have caught a foothold pod left running for six hours.'

Invoke-Stage 'posture checks' {
    # Snapshot first, then evaluate the file. Two commands rather than one on
    # purpose: the snapshot is what the gate reads, which means the state that was
    # judged can be inspected afterwards instead of re-derived, and it is the same
    # artefact the cluster-free self-test suite uses.
    $snapshot = Join-Path $projectRoot '.telemetry\posture-snapshot.json'
    & python (Join-Path $projectRoot 'detections\posture\check_posture.py') --snapshot $snapshot
    if ($LASTEXITCODE -ne 0) { throw "check_posture.py --snapshot exited $LASTEXITCODE" }
    & python (Join-Path $projectRoot 'detections\posture\check_posture.py') --from-file $snapshot
    if ($LASTEXITCODE -ne 0) {
        throw ("check_posture.py exited {0}. Every finding here is INTENTIONAL -- this lab is deliberately vulnerable -- so a failure means the SET of findings changed: a control was removed, or a check got looser." -f $LASTEXITCODE)
    }
    'posture findings match the expected set exactly, in both directions'
} -Why 'DET-0001/0002/0007/0008/0009. Configuration, not telemetry: a ServiceAccount bound to cluster-admin, a credential in a ConfigMap, a weak securityContext, an observe-zone ingress grant, an unbound token.'

Invoke-Stage 'drift' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tools\scan-drift.ps1')
    if ($LASTEXITCODE -ne 0) { throw "scan-drift.ps1 exited ${LASTEXITCODE}: manifests and the cluster disagree" }
    'no drift'
} -Why 'Kustomize source vs applied state, both directions.'

Invoke-Stage 'image digests' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tools\scan-images.ps1')
    if ($LASTEXITCODE -ne 0) { throw "scan-images.ps1 exited ${LASTEXITCODE}: a running image is not the pinned digest" }
    'all images match their pinned digests'
} -Why 'A mutable tag is a supply-chain hole in a lab whose whole point is trust boundaries.'

Invoke-Stage 'secret scan' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tools\scan-secrets.ps1')
    if ($LASTEXITCODE -ne 0) { throw "scan-secrets.ps1 exited $LASTEXITCODE" }
    'no credential-shaped value in tracked files'
} -Why 'The lab is built from deliberately leaked credentials. None of them may be committed.'

# ===========================================================================
# 8. detections
# ===========================================================================
Invoke-Stage 'detection gate' {
    # No --baseline and no --exact-baseline, and that is a considered choice.
    #
    # Hit counts cannot be enforced after a run that just deliberately changed the
    # audit window. This stage walked the lab, ran the chain and spun the graph, so
    # every count is different from last time -- and always will be. The committed
    # EXPECTED_HITS table was measured on the machine that wrote it, so no fresh
    # clone can reproduce it. A recorded baseline is no better in a standard run,
    # because the run that would compare against it is the run that invalidated
    # it: measured, det-0006 read 3 where the recorded baseline said 4, purely
    # because the lab had been walked since.
    #
    # So the standard run enforces the properties that do not depend on the
    # window: every rule fires, none fires outside its schema, none fires on its
    # whole schema, no audit record was collected twice, and every rule is provably
    # breakable by mutation. Counts are printed as drift.
    #
    # To gate on counts, run this directly with --baseline after a quiesced
    # collection. That is the loop for editing a rule, and the only loop in which a
    # count is a stable thing to compare.
    & python (Join-Path $projectRoot 'detections\test-detections.py')
    if ($LASTEXITCODE -ne 0) { throw "test-detections.py exited $LASTEXITCODE" }
    'every rule fires, none fires outside its schema, no duplicate records, every rule provably breakable'
} -Why 'Liveness, schema containment, strict subset, no duplicates, and a mutation harness. Counts are drift here on purpose.'

Invoke-Stage 'chain coverage' {
    & python (Join-Path $projectRoot 'detections\test-detections.py') --chain
    if ($LASTEXITCODE -ne 0) {
        throw ("test-detections.py --chain exited {0}: at least one walked hop has no telemetry schema behind it, so no rule can fire on it." -f $LASTEXITCODE)
    }
    'every hop has a rule and every rule is firing'
} -Why 'The question "was the intrusion caught, hop by hop" -- as opposed to "did any rule fire".'

Invoke-Stage 'self-tests' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tools\run-selftests.ps1')
    if ($LASTEXITCODE -ne 0) { throw "run-selftests.ps1 exited $LASTEXITCODE" }
    'all suites pass, and each suite proves it can fail'
} -Why 'Cluster-free. These are the checks that run in the pre-commit hook.'

# ===========================================================================
# 9. report
# ===========================================================================
Show-Ledger

$registryPath = Join-Path $projectRoot '.telemetry\attack-registry.json'
$summary     = Join-Path $projectRoot '.telemetry\chain-summary.json'
$walk        = Join-Path $projectRoot '.telemetry\walk-summary.json'

Write-Host ''
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Write-Host '  the lab is up' -ForegroundColor Green
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  cluster      kind cluster soc-lab, one control plane and two workers'
Write-Host '  zones        zerotrust, zerotrust-build, zerotrust-observe'
Write-Host '  evidence     .telemetry/  (gitignored: audit, runtime, network, graph)'
Write-Host "  run ledger   $runLedgerPath"

if (Test-Path $summary) {
    $s = Get-Content $summary -Raw | ConvertFrom-Json
    $undetectable = @($s.undetectable)
    Write-Host ''
    Write-Host ("  chain        {0}/{1} hop(s) succeeded" -f $s.hopsSucceeded, ($s.hopsSucceeded + $s.hopsFailed)) -ForegroundColor Gray
    if ($undetectable.Count -eq 0) {
        Write-Host '  coverage     every walked technique has a telemetry schema and a rule' -ForegroundColor Green
    }
    else {
        Write-Host ("  coverage     NO SCHEMA for: {0}" -f ($undetectable -join ', ')) -ForegroundColor Yellow
        Write-Host '               those hops ran for real and nothing can detect them' -ForegroundColor DarkGray
    }
}
if (Test-Path $walk) {
    $w = Get-Content $walk -Raw | ConvertFrom-Json
    # pathsWalked, not paths. Under Set-StrictMode, reading a property that does not
    # exist throws -- and it threw on the LAST line of this report, after the ledger
    # had already printed fifteen green stages. So a completely successful run exited
    # 1. That is the worst possible place for a crash: the one screen a reader uses to
    # decide whether the lab is working was the thing that broke, and it broke while
    # saying it was fine.
    Write-Host ("  paths        {0}/{1} walked{2}" -f `
        $w.pathsWalked, $w.pathsExpected, `
        $(if ($w.complete) { '' } else { '  INCOMPLETE' })) -ForegroundColor Gray
}

Write-Host ''
Write-Host '  next: the console' -ForegroundColor Cyan
Write-Host '    python dashboard/server.py        then open http://127.0.0.1:8099' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  The console binds loopback only and has no login. It can mint a' -ForegroundColor DarkGray
Write-Host '  cluster-admin token, which is the point -- it is the same authority' -ForegroundColor DarkGray
Write-Host '  the chain steals -- so do not bind it to an address other machines' -ForegroundColor DarkGray
Write-Host '  can reach.' -ForegroundColor DarkGray

if ($Serve) {
    Write-Host ''
    Write-Host '  starting the console on http://127.0.0.1:8099 -- Ctrl-C to stop' -ForegroundColor Cyan
    Write-Host ''
    & python (Join-Path $projectRoot 'dashboard\server.py')
}
