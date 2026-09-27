#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generate refused network traffic without touching the cluster's configuration.

.DESCRIPTION
    Exists for one reason: det-0005 (T1046) needs a *comparable* counter delta, and
    a comparable delta needs two reads of the same iptables chain with no policy
    change in between. Everything else in this lab that generates refused traffic
    also changes policy:

        graph/build-reachability.ps1    creates and deletes a probe pod per pair
        attack/chain-purple-team.ps1    applies a manifest at hop 5
        tools/test-boundaries.ps1       creates a probe pod per case

    kube-router reprograms its chains whenever policy changes and the counters
    restart at zero, so the collector reports `chain-rebuilt`, sets `deltaDenied` to
    null, and det-0005 correctly fires on nothing. That is the right behaviour -- a
    refused packet with no comparable baseline is not evidence of scanning -- but it
    means one of the seven rules is never exercised.

    So this is the missing ingredient: refused traffic from pods that ALREADY EXIST.
    `kubectl exec` only. No pod is created, none is deleted, no policy is touched, so
    the chains stay put and the delta stays computable.

    Where the targets come from
    ---------------------------
    The reachability graph, not a hardcoded list. For every modelled-open edge A->B
    this attempts B->A on the same port, which the policies do not permit. That gives
    refused traffic derived from the actual trust model rather than from a list that
    silently stops matching when the lab changes, and it scales with the graph.

    Honesty about what counts as refused
    ------------------------------------
    Every attempt is classified the same way build-reachability.ps1 classifies its
    probes: the exit code first, then elapsed time measured INSIDE the pod from
    /proc/uptime. `nc` reports nothing on failure, so a dropped SYN and a refused
    one are told apart by how long the answer took. The cut is at 600ms, chosen from
    measurement: the slowest attempt that drew an answer was 100ms, the fastest
    silent drop was 1010ms.

    An attempt that is NOT refused is reported as such and does not count toward the
    total. A generator that claimed refusals it did not get would be worse than one
    that produced nothing, because the detection it feeds would then be asserting
    something untrue.

    Each source pod also gets a DNS positive control. If DNS fails from that pod, the
    pod proved nothing about the port it was testing.

.PARAMETER Repeat
    Attempts per pair. More refused packets makes the delta larger and therefore
    harder to lose to rounding. Default 3.

.PARAMETER Quiet
    Verdict only.

.EXAMPLE
    tools/generate-refused-traffic.ps1
    Confirm which attempts are refused, without collecting anything.

.EXAMPLE
    tools/scan-pods.ps1 -SelfTest
    (n/a -- this script has no self-test; it needs a live cluster, which is why the
    logic that CAN be tested without one lives in the collector and the gate instead.)
#>
[CmdletBinding()]
param(
    [int]$Repeat = 3,
    [string]$GraphPath,
    [switch]$Quiet
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $GraphPath) { $GraphPath = Join-Path $projectRoot '.telemetry\reachability-graph.json' }

# The measured gap between "drew an answer" and "silent drop". From
# build-reachability.ps1: slowest answer 100ms, fastest silent drop 1010ms.
$DropThresholdMs = 600

if (-not (Test-Path $GraphPath)) {
    throw "$GraphPath not found. Run graph/build-reachability.ps1 first -- the targets are derived from the graph."
}
# kubectl is resolved from PATH, the same way graph/build-reachability.ps1 and
# telemetry/network/collect-network.ps1 do. A hardcoded `docker exec <cp> kubectl`
# would work on this machine and fail on any other, and would quietly bypass
# whichever kubeconfig the rest of the lab uses.
if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    throw 'kubectl is not on PATH. The rest of this lab resolves it from PATH too.'
}
$graph = Get-Content $GraphPath -Raw | ConvertFrom-Json

$nodes = @{}
foreach ($n in $graph.nodes) { $nodes[$n.id] = $n }
$edges = @($graph.edges)

if ($edges.Count -eq 0) { throw 'the graph has no edges, so there is no modelled-open path to reverse.' }

Write-Host 'refused traffic generator' -ForegroundColor Cyan
Write-Host ('=' * 74) -ForegroundColor Cyan
Write-Host ''
Write-Host ("  graph        {0} node(s), {1} modelled-open edge(s)" -f $nodes.Count, $edges.Count) -ForegroundColor DarkGray
Write-Host ("  method       reverse each open edge and attempt it; policies do not permit the reverse")
Write-Host ("  policy       UNCHANGED. kubectl exec into existing pods only -- no pod is created or deleted,")
Write-Host ("               which is the whole point: kube-router would rebuild its chains and reset the")
Write-Host ("               counters, and the delta would be uncomparable again.")
Write-Host ("  drop cut     {0}ms" -f $DropThresholdMs) -ForegroundColor DarkGray

# --------------------------------------------------------------------------- #
# Build the attempt list: the reverse of every modelled-open edge.
#
# Deduped on (source pod, dest ip, port), because a graph can carry more than one
# edge between the same pair and a repeated attempt is just a slower run.
# --------------------------------------------------------------------------- #
# Every forward edge the graph knows about, so a reversal can be CHECKED rather
# than assumed. See the guard below.
$forward = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($e in $edges) { [void]$forward.Add("$($e.from)|$($e.to)|$([int]$e.port)") }

$attempts = @{}
foreach ($e in $edges) {
    $fromId = $e.from
    $toId   = $e.to
    $port   = [int]$e.port
    if ($fromId -eq $toId) { continue }   # a self-edge reversed is still a self-edge
    if (-not $nodes.ContainsKey($fromId) -or -not $nodes.ContainsKey($toId)) { continue }

    # REVERSED, and the reversal is the entire point.
    #
    # The source of the attempt is the edge's DESTINATION, and the host it dials is
    # the edge's SOURCE. The first version of this block read $from/$to straight
    # off the edge without swapping, so it exec'd into the forward source and
    # dialled the forward destination -- which the policies permit. Every attempt
    # came back PERMITTED with an elapsed time of 0-10ms, the generator produced
    # zero refused packets, and its own error banner explained that away as "the
    # policies are not symmetric". A finding used to hide a bug in the tool that
    # produced the finding.
    $src = $nodes[$toId]
    $dst = $nodes[$fromId]

    # Guard, so the reversal cannot silently stop happening. If the pair about to
    # be attempted is one the graph already records as OPEN, this tool is about to
    # dial a permitted path and call the result a policy finding.
    if ($forward.Contains("$($src.id)|$($dst.id)|$port")) {
        throw ("refusing to run: {0} -> {1}:{2} is a FORWARD edge the graph already " +
               "records as open. Attempting it would produce a permitted result " +
               "that means nothing. The reversal in this script is broken." -f `
               $src.id, $dst.id, $port)
    }

    $key = "$($src.namespace)/$($src.pod)|$($dst.podIp)|$port"
    if (-not $attempts.ContainsKey($key)) {
        $attempts[$key] = [pscustomobject]@{
            sourceNs      = $src.namespace
            sourcePod     = $src.pod
            sourceId      = $src.id
            destId        = $dst.id
            destNs        = $dst.namespace
            destPod       = $dst.pod
            destIp        = $dst.podIp
            port          = $port
            denied        = 0
            answered      = 0
            unknown       = 0
        }
    }
}

$list = @($attempts.Values)
if ($list.Count -eq 0) { throw 'no reversible edges found; the graph is not in the expected shape.' }

Write-Host ("  attempts     {0} reversed pair(s) x {1}" -f $list.Count, $Repeat) -ForegroundColor DarkGray
Write-Host ''

# --------------------------------------------------------------------------- #
# The in-pod command
#
# Raw `kubectl exec` rather than attacklib's Invoke-InPod, which is the right tool
# everywhere else and unusable here: it REJECTS any command containing $ { } ( ) or
# backtick, precisely because PowerShell's native marshalling mangles them. The
# timing idiom needs $ and {}, so it cannot go through Invoke-InPod. That is a real
# constraint, stated rather than worked around silently.
#
# The command contains no double quotes at all. PowerShell strips embedded double
# quotes before a native executable sees them -- the same trap that made grep die
# with "Trailing backslash" in the audit collector -- so the whole thing is built
# from a single-quoted template with no quoting to lose.
# --------------------------------------------------------------------------- #
function Invoke-Remote {
    param([string]$Ns, [string]$Pod, [string]$ShCmd)
    # Plain `kubectl exec`, not `docker exec <cp> kubectl exec`.
    #
    # graph/build-reachability.ps1 uses plain kubectl and is known to work with
    # this exact command shape -- the `$S ${S%% *}` idiom, the bare `echo $S $E $R`
    # output, the whole thing. Matching a proven pattern beats inventing one that
    # has never been executed, which is the situation this whole file is in.
    $out = (& kubectl exec -n $Ns $Pod -- sh -c $ShCmd 2>&1 | Out-String).Trim()
    return @{ rc = $LASTEXITCODE; out = $out }
}

# kube-dns ClusterIP, resolved rather than hardcoded. Resolving it costs one call
# and means the script keeps working if the Service is recreated on a different IP,
# which a hardcoded address would silently get wrong.
$dnsIp = (& kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' 2>$null | Out-String).Trim()
if (-not $dnsIp) { throw 'could not resolve the kube-dns ClusterIP; the positive control needs it' }
$DnsPort = 53

# The probe. Byte-for-byte the shape build-reachability.ps1 uses, including the
# bare `echo $S $E $R` output: uptime at start, uptime at end, exit code. $S and $E
# are seconds since boot, so their difference is elapsed time measured INSIDE the
# pod. Measuring across `kubectl exec` would measure kubectl's own latency, which
# is seconds -- the reason the graph reads /proc/uptime at all.
#
# `echo $S $E $R` rather than `echo rc=$R s=$S e=$E`: three bare values with no
# labels, so a truncated or interleaved line fails to parse rather than parsing
# into the wrong field.
# Built by CONCATENATION, never with -f or String.Format.
#
# The template contains `${S%% *}`, a bash parameter expansion. `-f` hands the
# string to .NET String.Format, which reads `{S%% *}` as a format item and throws
# FormatError: "Input string was not in a correct format." It died on the first
# pair, so the generator produced zero refused packets and looked like it had run.
#
# This is the same class of bug as the PowerShell native-marshalling hazard
# documented just above, one layer down: a string that is correct for bash is not
# correct for .NET. Concatenation has no format parser in it, which is the whole
# reason build-reachability.ps1 builds this command the same way.
$probeHead = 'S=$(cat /proc/uptime); S=${S%% *}; nc -w 3 '
$probeTail = ' >/dev/null 2>&1; R=$?; E=$(cat /proc/uptime); E=${E%% *}; echo $S $E $R'

# Positive control: a TCP connect to kube-dns on 53, which no lab policy governs.
# Same shape as the probes themselves, which is the point -- a control that
# exercised a different mechanism would not prove the mechanism under test works.
$controlHead = 'nc -w 3 '
$controlTail = ' >/dev/null 2>&1; echo $?'

$results = @()

foreach ($a in $list) {
    if (-not $Quiet) {
        Write-Host ("  {0} -> {1}:{2}" -f $a.sourceId, $a.destId, $a.port) -ForegroundColor DarkGray
    }

    $ctl = Invoke-Remote -Ns $a.sourceNs -Pod $a.sourcePod -ShCmd ($controlHead + $dnsIp + ' ' + [string]$DnsPort + $controlTail)
    $dnsOk = ($ctl.out.Trim() -eq '0')
    if (-not $dnsOk) {
        Write-Host ("    [skip] control failed from {0} (got '{1}'); this pod cannot test a port" -f $a.sourcePod, $ctl.out) -ForegroundColor DarkYellow
        # Every result object carries the SAME properties. The first version omitted
        # the counters here, and the summary below reads them off every entry -- so
        # under Set-StrictMode, one pod failing its control made the summary line
        # throw on a property that does not exist. The report died on the case it
        # was meant to be reporting.
        $results += [pscustomobject]@{
            attempt = $a; verdict = 'no-dns-control'; elapsedMs = $null
            denied = 0; answered = 0; unknown = 0
        }
        continue
    }

    $denied = 0; $answered = 0; $unknown = 0; $lastMs = $null
    for ($i = 0; $i -lt $Repeat; $i++) {
        $r = Invoke-Remote -Ns $a.sourceNs -Pod $a.sourcePod -ShCmd ($probeHead + $a.destIp + ' ' + [string]$a.port + $probeTail)
        $parts = ($r.out -split '\s+') | Where-Object { $_ -ne '' }
        if ($parts.Count -lt 3) {
            $unknown++
            if (-not $Quiet) { Write-Host ("    [?] unparseable: '{0}'" -f $r.out) -ForegroundColor DarkYellow }
            continue
        }
        $s   = [double]$parts[0]
        $e   = [double]$parts[1]
        $rc  = $parts[2]
        $ms  = [math]::Round(($e - $s) * 1000, 0)
        $lastMs = $ms

        # Exit code is tested FIRST, so a slow success can never be recorded as a
        # drop. Only a silent non-zero result is a candidate refusal, and then the
        # elapsed time decides whether it was a drop or a connection refused.
        if ($rc -eq '0') { $answered++ }
        elseif ($ms -ge $DropThresholdMs) { $denied++ }
        else { $unknown++ }
    }

    $verdict =
        if ($denied -eq $Repeat) { 'refused' }
        elseif ($denied -gt 0)    { 'partially-refused' }
        elseif ($answered -gt 0)  { 'PERMITTED' }
        else                      { 'inconclusive' }

    $results += [pscustomobject]@{ attempt = $a; verdict = $verdict; elapsedMs = $lastMs; denied = $denied; answered = $answered; unknown = $unknown }

    if (-not $Quiet) {
        $colour = switch ($verdict) {
            'refused'            { 'Green' }
            'partially-refused'  { 'Yellow' }
            'PERMITTED'          { 'Red' }
            default              { 'DarkYellow' }
        }
        Write-Host ("    [{0}] {1}/{2} refused, {3} answered, {4} inconclusive, last {5}ms" -f `
            $verdict, $denied, $Repeat, $answered, $unknown, $lastMs) -ForegroundColor $colour
    }
}

# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #
$refusedPairs = @($results | Where-Object { $_.verdict -eq 'refused' })
$permitted    = @($results | Where-Object { $_.verdict -eq 'PERMITTED' })
$partial      = @($results | Where-Object { $_.verdict -eq 'partially-refused' })
$noControl    = @($results | Where-Object { $_.verdict -eq 'no-dns-control' })

Write-Host ''
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Write-Host '  what this produced' -ForegroundColor Cyan
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Write-Host ''
Write-Host ("  fully refused      {0}" -f $refusedPairs.Count) -ForegroundColor Green
Write-Host ("  partially refused  {0}" -f $partial.Count) -ForegroundColor Yellow
Write-Host ("  PERMITTED          {0}" -f $permitted.Count) -ForegroundColor $(if ($permitted.Count) { 'Red' } else { 'DarkGray' })
Write-Host ("  skipped, no DNS    {0}" -f $noControl.Count) -ForegroundColor DarkGray
Write-Host ("  refused packets    {0}" -f (@($results | ForEach-Object { [int]$_.denied }) | Measure-Object -Sum).Sum) -ForegroundColor Green
Write-Host ''

if ($permitted.Count -gt 0) {
    Write-Host '  A REVERSED edge was PERMITTED.' -ForegroundColor Red
    Write-Host '  Two possible causes, and they need different responses:' -ForegroundColor DarkGray
    Write-Host '    1. The policies really are symmetric here, and the reachability graph' -ForegroundColor DarkGray
    Write-Host '       is understating what is open. That is a finding about the lab.' -ForegroundColor DarkGray
    Write-Host '    2. This tool is not actually reversing. Verify with:' -ForegroundColor DarkGray
    Write-Host '         kubectl exec -n <ns> <pod> -- sh -c "nc -w 3 <ip> <port>"' -ForegroundColor DarkGray
    Write-Host '       and compare the direction against the graph before believing it.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Do not assume cause 1. The first version of this script reversed' -ForegroundColor DarkGray
    Write-Host '  nothing, every attempt came back PERMITTED, and this banner reported' -ForegroundColor DarkGray
    Write-Host '  that as a policy finding. A tool bug wearing a finding''s clothes is' -ForegroundColor DarkGray
    Write-Host '  worse than a crash, because it is believed.' -ForegroundColor DarkGray
}

if ($refusedPairs.Count -eq 0 -and $partial.Count -eq 0) {
    Write-Host '  No refused traffic was produced.' -ForegroundColor Red
    Write-Host '  det-0005 stays unjudgeable. That is the correct and honest outcome for' -ForegroundColor DarkGray
    Write-Host '  a window with no comparable refusal, but it means the rule is not being' -ForegroundColor DarkGray
    Write-Host '  exercised -- so treat this as a failure of this tool until proven otherwise.' -ForegroundColor DarkGray
    exit 1
}

Write-Host '  The chains were not touched, so a network collection taken now is comparable' -ForegroundColor DarkGray
Write-Host '  to one taken before this ran. That is what det-0005 needs.' -ForegroundColor DarkGray
exit 0
