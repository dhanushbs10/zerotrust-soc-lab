#Requires -Version 5.1
<#
.SYNOPSIS
    Collects network telemetry from the enforcement point, where the packets
    were actually decided.

.DESCRIPTION
    This lab has no flow logs. kube-router v2.6.1 is run with --run-router,
    --run-firewall and --run-service-proxy and nothing else, and it exposes no
    metrics port and no policy-name API. So "who talked to whom" has to come
    from somewhere, and the honest somewhere is the kernel.

    Two real sources, both read from the node rather than inferred from config:

      1. iptables packet counters on the KUBE-POD-FW-* chains. kube-router
         builds one chain per pod, and the rules inside carry the pod's identity
         and the names of the policies applied to it, verbatim:

             run through nw policy default-deny-all
             rule to REJECT traffic destined for POD name:build-runner-7cb5c4877
               namespace: zerotrust-build

         That matters: the policy-to-pod mapping is READ, not derived. A
         collector that inferred it by matching rule content against manifests
         would be guessing, and would report a guess with the same confidence as
         a measurement.

      2. conntrack, for the connections that were permitted. /proc/net/nf_conntrack
         on each node holds live 5-tuples with state, so allowed traffic is
         observed rather than inferred from a policy that should have allowed it.

    What a counter can and cannot say
    ---------------------------------
    A REJECT rule is policy-agnostic: "traffic not marked allowed". So a counter
    tells you THAT a pod's traffic was refused, HOW MANY packets, and WHICH POD.
    It does not tell you which port or which destination was attempted. That
    information is genuinely not present at the enforcement point.

    The limitation is stated in every event this script writes, via the
    "resolution" field, rather than left for a reader to discover. Getting the
    destination of a denied attempt requires the audit log or a probe, not this.

    Which pod gets the blame
    ------------------------
    Whichever pod's policy did the refusing. An egress refusal is counted on the
    source's chain, so it names the pod that initiated the traffic. An ingress
    refusal is counted on the TARGET's chain instead, which is why a target's
    counter cannot be used to answer "was anything aimed at me", and why the
    sensor's probe of build-runner registers against build-runner.

    What the counters actually count
    ---------------------------------
    Measured on this cluster, addressing the postgres pod IP directly:

        3 attempts to the same brand-new port   -> REJECT +2, +2, +2
        4 attempts to 4 different brand-new ports -> REJECT +8

    So the counter counts PACKETS, at a steady 2 per refused connection
    attempt, and a retry to an already-refused port is counted again. An
    earlier reading of this lab suggested the opposite -- that conntrack
    deduplicates retries so only distinct flows are counted -- and that reading
    was wrong. It came from probes to a hostname that does not resolve
    (postgres.zerotrust.svc is NXDOMAIN; the resolvable name is the full
    postgres.zerotrust.svc.cluster.local), so nothing was sent at all and the
    counter correctly did not move. A counter that did not move was read as
    deduplication when it was really a probe that never ran.

    A refusal is only visible if policy evaluation happened
    ---------------------------------------------------------
    kube-proxy/kube-router install a DNAT rule per exposed Service port, and
    that translation happens BEFORE the pod's policy chain is evaluated. So a
    connection to a Service ClusterIP on a port the Service does not expose is
    dropped before any policy is consulted, and never appears in these
    counters. Measured: pod IP on an unexposed port gave REJECT +3; the same
    pod's Service ClusterIP on the same port gave +0.

        pod IP      :10.244.1.2 -> 12401   REJECT +3
        ClusterIP   :10.96.19.167 -> 12402 REJECT +0   (no DNAT for that port)

    This is a trap for detection tests. A scan written against Service DNS
    names can walk every port it likes and register nothing, while looking like
    it is generating hostile traffic. To make a refusal observable, address the
    pod IP, or a port the Service actually exposes.

    Which chain carries the refusal
    -------------------------------
    A refusal is counted on the chain of the pod where the policy that refused
    it is enforced. Egress refused by the source's own policy lands on the
    source's chain. Ingress refused by the target's policy lands on the
    TARGET's chain, so the sensor probing build-runner shows up as a denial
    against build-runner, not against the sensor. The sensor's egress policy
    permits any pod on ports 80, 8080 and 5432, and build-runner exposes 8080,
    so that probe is permitted outbound and refused inbound.

    Counters are not monotonic
    -------------------------
    kube-router tears down and rebuilds the pod chains when it reprograms the
    firewall, and the rebuilt chain restarts at zero. Measured: every one of
    the eight pod chains had a different name, and a lower counter, between two
    collections taken minutes apart, with no kube-router restart in between.
    The chain name is therefore not a usable identity -- it is regenerated --
    and a counter read after a rebuild is not comparable to a counter read
    before it.

    This script therefore keys its baseline on node plus pod name, which is
    stable, and records the chain name only so a rebuild can be detected. Each
    event states which of four states it is in:

        no-baseline     first time this subject has been seen
        compared        counters are continuous with the previous collection
        chain-rebuilt   the chain was regenerated; only the absolute is valid
        counter-reset  counters went backwards on the same chain

    A delta is emitted only in the compared state. In the other three it is
    null with a stated reason, because a number computed across a reset is
    wrong in a way that looks right.

.PARAMETER ClusterName
    kind cluster name. Defaults to soc-lab.

.PARAMETER OutputPath
    Normalized JSON Lines destination.
    Defaults to .telemetry\network-events.jsonl

.PARAMETER BaselinePath
    Counter baseline for delta reporting.
    Defaults to .telemetry\network-baseline.json

.PARAMETER NoBaseline
    Ignore and do not write a baseline. Every event reports its counter as
    absolute with a null delta, which is the honest thing to do when comparing
    two arbitrary collections.

.EXAMPLE
    .\collect-network.ps1

.EXAMPLE
    .\collect-network.ps1 -NoBaseline
#>

[CmdletBinding()]
param(
    [string]$ClusterName = 'soc-lab',
    [string]$OutputPath,
    [string]$BaselinePath,
    [switch]$NoBaseline
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot '.telemetry\network-events.jsonl' }
if (-not $BaselinePath) { $BaselinePath = Join-Path $projectRoot '.telemetry\network-baseline.json' }

function Assert-Prerequisites {
    $server = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
    if ($server -notmatch '^\d') {
        throw 'Docker engine is not responding. Start Docker Desktop and retry.'
    }
    $clusters = (& kind get clusters 2>$null | Out-String)
    if ($clusters -notmatch [regex]::Escape($ClusterName)) {
        throw "kind cluster '$ClusterName' not found. Run bootstrap.ps1 first."
    }
}

# ---------------------------------------------------------------------------
# Pod identity, from the API. Pod IPs are the join key between the kernel's
# view and Kubernetes' view, so this map is what turns 10.244.1.3 into
# "the sensor in the observe zone". Resolved fresh each run because pod IPs are
# reassigned on restart and a stale map would attribute traffic to a pod that no
# longer exists.
# ---------------------------------------------------------------------------
# A missing key is not an error here, it is a fact about the object. Under
# Set-StrictMode a bare $obj.missing throws, and "this pod has no app label" or
# "this pod does not set serviceAccountName" is not worth aborting a telemetry
# collection over. kube-system pods routinely have no app label, and any pod
# using the default service account omits the field entirely rather than sending
# it as empty.
function Get-PropOrNull {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function Get-PodIpMap {
    $raw = (& kubectl get pods -A -o json 2>$null | Out-String)
    if (-not $raw.Trim()) { throw 'kubectl returned no pods; refusing to emit unattributed telemetry.' }
    $list = $raw | ConvertFrom-Json

    $map = @{}
    foreach ($p in $list.items) {
        $ip = $p.status.podIP
        if (-not $ip) { continue }
        $labels = $p.metadata.labels
        $map[$ip] = [pscustomobject]@{
            ip        = $ip
            namespace = $p.metadata.namespace
            name      = $p.metadata.name
            app       = Get-PropOrNull $labels 'app'
            # The identity that actually authenticates to the API server. This
            # is what a detection needs to pivot from a packet to a credential.
            serviceAccount = Get-PropOrNull $p.spec 'serviceAccountName' 'default'
            zone           = $p.metadata.namespace
            phase          = Get-PropOrNull $p.status 'phase'
            node           = Get-PropOrNull $p.spec 'nodeName'
        }
    }
    return $map
}

# ---------------------------------------------------------------------------
# Read one node's iptables state.
#
# Two calls per node, both quote-free. PowerShell strips embedded double quotes
# before the argument reaches a native executable, so any shell construct
# needing them -- a loop, a pipe into cut, a quoted grep pattern -- arrives
# mangled. The chain list is therefore fetched once with a bare pattern and then
# read one chain at a time, rather than in a single in-container loop.
# ---------------------------------------------------------------------------
function Get-NodeChainNames {
    param([string] $Node)
    $out = (& docker exec $Node iptables -t filter -S 2>&1) | Out-String
    $names = @()
    foreach ($line in ($out -split "`n")) {
        if ($line -match '^-N (KUBE-POD-FW-\S+)') { $names += $Matches[1] }
    }
    return $names
}

function Get-NodeChainRules {
    param([string] $Node, [string] $Chain)
    $out = (& docker exec $Node iptables -t filter -S $Chain 2>&1) | Out-String
    $rules = @()
    foreach ($line in ($out -split "`n")) {
        if ($line -match '^-A ') { $rules += $line.Trim() }
    }
    return $rules
}

function Get-NodeChainCounters {
    param([string] $Node, [string] $Chain)
    $out = (& docker exec $Node iptables -t filter -L $Chain -n -v -x 2>&1) | Out-String
    $rows = @()
    foreach ($line in ($out -split "`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -match '^Chain ') { continue }
        $f = $t -split '\s+'
        if ($f.Count -lt 3) { continue }
        if ($f[0] -notmatch '^\d+$') { continue }
        $rows += [pscustomobject]@{
            packets = [int64]$f[0]
            bytes   = [int64]$f[1]
            text    = $t
        }
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Parse one pod chain into a record.
#
# The identity comes from the comment on the REJECT rule, which kube-router
# writes as "POD name:<pod> namespace:<ns>". That is the authoritative statement
# of which pod this chain governs. The policy list comes from the
# "run through nw policy <name>" comments, in rule order, which is the order
# kube-router evaluates them.
# ---------------------------------------------------------------------------
function ConvertTo-PodChainRecord {
    param(
        [string] $Node,
        [string] $Chain,
        [string[]] $Rules,
        [object[]] $Counters,
        [hashtable] $IpMap
    )

    $podName = $null
    $podNs = $null
    $policies = @()
    $podIps = @()

    foreach ($r in $Rules) {
        if ($r -match 'POD name:(\S+)\s+namespace:\s*([A-Za-z0-9._-]+)') {
            if (-not $podName) { $podName = $Matches[1]; $podNs = $Matches[2] }
        }
        if ($r -match 'run through nw policy (\S+)') { $policies += $Matches[1] }
        if ($r -match '(-[sd]) (\d+\.\d+\.\d+\.\d+)/32') { $podIps += $Matches[2] }
    }

    # The counters we care about, matched by target rather than by position,
    # because rule order is kube-router's business and not this script's.
    $denied = 0
    $logged = 0
    $accepted = 0
    $total = 0
    $first = $true
    foreach ($c in $Counters) {
        if ($first) { $total = $c.packets; $first = $false; continue }
        if ($c.text -match '\sREJECT\s') { $denied = $c.packets }
        elseif ($c.text -match '\sNFLOG\s') { $logged = $c.packets }
        elseif ($c.text -match 'or 0x20000') { $accepted = $c.packets }
    }

    # Resolve the governing pod to a live API object. The chain comment is
    # authoritative for which pod this is; the API is authoritative for that
    # pod's current IP and identity. If they disagree the pod was replaced
    # between the two reads, and saying so beats silently reporting a stale
    # identity against fresh counters.
    $identity = $null
    $ipResolved = $null
    $stale = $false
    if ($podIps.Count -gt 0 -and $IpMap.ContainsKey($podIps[0])) {
        $identity = $IpMap[$podIps[0]]
        $ipResolved = $podIps[0]
        if ($podName -and $identity.name -ne $podName) { $stale = $true }
    } elseif ($podName) {
        foreach ($kv in $IpMap.GetEnumerator()) {
            if ($kv.Value.name -eq $podName -and $kv.Value.namespace -eq $podNs) {
                $identity = $kv.Value; $ipResolved = $kv.Value.ip; break
            }
        }
    }

    return [pscustomobject]@{
        node       = $Node
        chain      = $Chain
        podName    = $podName
        podNs      = $podNs
        podIp      = $ipResolved
        identity   = $identity
        stale      = $stale
        policies   = @($policies | Select-Object -Unique)
        total      = $total
        denied     = $denied
        logged     = $logged
        accepted   = $accepted
    }
}

# ---------------------------------------------------------------------------
# conntrack: the permitted connections, observed rather than assumed.
# ---------------------------------------------------------------------------
function Get-NodeConntrack {
    param([string] $Node, [hashtable] $IpMap)

    $out = (& docker exec $Node cat /proc/net/nf_conntrack 2>$null) | Out-String
    $flows = @()
    foreach ($line in ($out -split "`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -notmatch 'src=(\S+)\s+dst=(\S+)\s') { continue }
        $src = $Matches[1]
        $dst = $Matches[2]
        $state = if ($t -match '\s(\w+)\s+src=') { $Matches[1] } else { $null }
        $dport = if ($t -match 'dport=(\d+)') { $Matches[1] } else { $null }

        # Only flows between two known pods are lab traffic. Everything else is
        # node-to-node, kubelet, or Docker's own plumbing, and labelling it as a
        # workload connection would be a fabrication.
        $srcPod = if ($IpMap.ContainsKey($src)) { $IpMap[$src] } else { $null }
        $dstPod = if ($IpMap.ContainsKey($dst)) { $IpMap[$dst] } else { $null }
        if (-not $srcPod -or -not $dstPod) { continue }

        $flows += [pscustomobject]@{
            source = $srcPod
            dest   = $dstPod
            dport  = $dport
            state  = $state
        }
    }
    return $flows
}

# ---------------------------------------------------------------------------

Assert-Prerequisites

Write-Host 'Resolving pod identities from the API...' -ForegroundColor Cyan
$ipMap = Get-PodIpMap
Write-Host ("  {0} pods with an IP" -f $ipMap.Count) -ForegroundColor DarkGray

$nodes = @()
$nodeJson = (& kubectl get nodes -o json 2>$null | Out-String) | ConvertFrom-Json
foreach ($n in $nodeJson.items) {
    $short = $n.metadata.name -replace ('^' + [regex]::Escape($ClusterName) + '-'), ''
    $nodes += [pscustomobject]@{ short = $short; container = $n.metadata.name; internal = $n.status.addresses[0].address }
}
Write-Host ("  {0} nodes: {1}" -f $nodes.Count, (($nodes | ForEach-Object { $_.short }) -join ', ')) -ForegroundColor DarkGray

Write-Host 'Reading iptables counters from the enforcement point...' -ForegroundColor Cyan
$chainRecords = @()
$chainCount = 0
foreach ($n in $nodes) {
    $chains = Get-NodeChainNames -Node $n.container
    foreach ($ch in $chains) {
        $rules = Get-NodeChainRules -Node $n.container -Chain $ch
        $counters = Get-NodeChainCounters -Node $n.container -Chain $ch
        $chainRecords += ConvertTo-PodChainRecord -Node $n.short -Chain $ch -Rules $rules -Counters $counters -IpMap $ipMap
        $chainCount++
    }
    Write-Host ("  {0,-14} {1} pod chain(s)" -f $n.short, $chains.Count) -ForegroundColor DarkGray
}

Write-Host 'Reading conntrack for permitted connections...' -ForegroundColor Cyan
$flows = @()
foreach ($n in $nodes) {
    $f = Get-NodeConntrack -Node $n.container -IpMap $ipMap
    $flows += $f
    Write-Host ("  {0,-14} {1} pod-to-pod flow(s)" -f $n.short, $f.Count) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Baseline and deltas.
# ---------------------------------------------------------------------------
$previous = $null
if (-not $NoBaseline -and (Test-Path -LiteralPath $BaselinePath)) {
    $prevRaw = ([System.IO.File]::ReadAllText($BaselinePath) | ConvertFrom-Json)
    $previous = @{}
    foreach ($b in $prevRaw.counters) { $previous[$b.key] = $b }
}

$hadBaseline = ($null -ne $previous)
$collectedAt = (Get-Date).ToUniversalTime().ToString('o')

# ---------------------------------------------------------------------------
# Emit. Three event kinds, each labelled with what it can and cannot support.
# ---------------------------------------------------------------------------
$events = @()
$newCounters = @()

foreach ($c in $chainRecords) {
    # Keyed on node plus pod name, NOT on the chain name. The chain name is
    # regenerated every time kube-router reprograms the firewall -- all eight
    # were observed changing between two collections minutes apart -- so keying
    # on it would silently make every subject look new and hide counter resets
    # behind a null delta.
    $key = '{0}|{1}/{2}' -f $c.node, $c.podNs, $c.podName
    $absDenied = [int64]$c.denied
    $absLogged = [int64]$c.logged
    $absTotal = [int64]$c.total
    $absAccepted = [int64]$c.accepted

    $prior = $null
    if ($previous -and $previous.ContainsKey($key)) { $prior = $previous[$key] }

    # Four states, and a delta is only defined in one of them. Guessing at the
    # other three is how a telemetry collector ends up reporting a rate that
    # never happened.
    $baselineState = 'no-baseline'
    $deltaInvalidReason = 'no prior collection for this subject'
    if ($prior) {
        if ($prior.chain -ne $c.chain) {
            $baselineState = 'chain-rebuilt'
            $deltaInvalidReason = 'the iptables chain was regenerated since the baseline, so its counters restarted at zero and are not comparable'
        }
        elseif ($absTotal -lt [int64]$prior.total -or $absDenied -lt [int64]$prior.denied) {
            $baselineState = 'counter-reset'
            $deltaInvalidReason = 'counters moved backwards on an unchanged chain, so the previous reading is not a valid starting point'
        }
        else {
            $baselineState = 'compared'
            $deltaInvalidReason = $null
        }
    }

    $dDenied = $null; $dLogged = $null; $dTotal = $null; $dAccepted = $null
    if ($baselineState -eq 'compared') {
        $dDenied = $absDenied - [int64]$prior.denied
        $dLogged = $absLogged - [int64]$prior.logged
        $dTotal = $absTotal - [int64]$prior.total
        $dAccepted = $absAccepted - [int64]$prior.accepted
    }

    $newCounters += [pscustomobject]@{
        key = $key; node = $c.node; chain = $c.chain; podIp = $c.podIp
        pod = $c.podName; namespace = $c.podNs
        total = $absTotal; denied = $absDenied; logged = $absLogged; accepted = $absAccepted
    }

    if (-not $c.identity) { continue }

    $events += [pscustomobject]@{
        schema        = 'network/denial-counter/v1'
        collectedAt   = $collectedAt

        node          = $c.node
        chain         = $c.chain
        subject       = [pscustomobject]@{
            ip = $c.podIp; pod = $c.podName; namespace = $c.podNs
            app = $c.identity.app; serviceAccount = $c.identity.serviceAccount
            zone = $c.identity.zone
        }
        identityStale = $c.stale

        # The only case in which a delta means anything, spelled out so a
        # consumer does not have to infer it from a null.
        baselineState = $baselineState
        deltaValid    = ($baselineState -eq 'compared')
        deltaReason   = $deltaInvalidReason

        counter       = [pscustomobject]@{
            deniedPackets   = $absDenied
            loggedPackets   = $absLogged
            acceptedPackets = $absAccepted
            totalPackets    = $absTotal
            deltaDenied     = $dDenied
            deltaLogged     = $dLogged
            deltaAccepted   = $dAccepted
            deltaTotal      = $dTotal
        }

        policiesApplied = @($c.policies)

        # Stated on every event, because the alternative is a reader inferring a
        # capability this source does not have.
        resolution     = 'count and attributed pod only; port and destination are not recorded at the enforcement point, and a Service ClusterIP on a port the Service does not expose is dropped before policy evaluation so it is never counted here'
        attribution    = 'counted on the chain of the pod whose policy refused the traffic: the source for its own egress policy, the target for its ingress policy'
        packetsPerRefusal = 'measured at 2 per refused connection attempt; retries to an already-refused pod IP and port are counted again, so the counter approximates attempts rather than distinct flows'

        candidateTechniques = @(
            [pscustomobject]@{ id = 'T1046'; name = 'Network Service Scanning'; why = 'a pod repeatedly attempting connections policy refuses' }
        )
        note           = 'candidate technique, not a detection. Firing is Phase 7 and is not claimed here.'
    }
}

# The three trust zones this lab is about. Anything outside them is cluster
# plumbing -- coredns, the local path provisioner, kubelet -- and is real, but it
# is not what a detection on this lab should be reading.
$LabZones = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

foreach ($f in $flows) {
    $bothLab = (($LabZones -contains $f.source.namespace) -and ($LabZones -contains $f.dest.namespace))
    $scope = if ($bothLab) { 'lab-zone' } else { 'cluster-internal' }

    $events += [pscustomobject]@{
        schema        = 'network/observed-flow/v1'
        collectedAt   = $collectedAt
        scope         = $scope

        source        = [pscustomobject]@{
            ip = $f.source.ip; pod = $f.source.name; namespace = $f.source.namespace
            app = $f.source.app; serviceAccount = $f.source.serviceAccount; zone = $f.source.zone
        }
        dest          = [pscustomobject]@{
            ip = $f.dest.ip; pod = $f.dest.name; namespace = $f.dest.namespace
            app = $f.dest.app; serviceAccount = $f.dest.serviceAccount; zone = $f.dest.zone
        }
        destPort      = $f.dport
        state         = $f.state

        resolution    = 'observed 5-tuple from conntrack; transient by nature and not a historical record'
        attribution   = 'direct: both endpoints resolved to live pods'

        # Only lab-zone flows are candidates for a detection on this lab. Marking
        # cluster-internal traffic as a candidate would be a rule that fires on
        # DNS and says nothing about the lab.
        candidateTechniques = if ($bothLab) {
            @([pscustomobject]@{ id = 'T1021'; name = 'Remote Services'; why = 'an established pod-to-pod connection between trust zones' })
        } else { @() }
        note           = if ($bothLab) { 'candidate technique, not a detection. Firing is Phase 7.' }
                        else { 'cluster plumbing, not lab traffic; retained rather than dropped so the count stays auditable' }
    }
}

# ---------------------------------------------------------------------------

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
try {
    foreach ($e in $events) {
        $writer.WriteLine(($e | ConvertTo-Json -Compress -Depth 6))
    }
}
finally { $writer.Dispose() }

if (-not $NoBaseline) {
    $baseline = [pscustomobject]@{
        collectedAt = $collectedAt
        keyedOn     = 'node + namespace/podName'
        note        = @(
            'Absolute iptables counters, for delta reporting. Not a credential store; no secrets here.'
            'Deliberately NOT keyed on the iptables chain name: kube-router regenerates those names when it'
            'reprograms the firewall, which silently reset counters and would be reported here as a new subject.'
        )
        counters    = @($newCounters)
    }
    [System.IO.File]::WriteAllText(
        $BaselinePath,
        (($baseline | ConvertTo-Json -Depth 5) -replace "`r`n", "`n") + "`n",
        [System.Text.UTF8Encoding]::new($false))
}

$denialEvents = @($events | Where-Object { $_.schema -eq 'network/denial-counter/v1' })
$flowEvents = @($events | Where-Object { $_.schema -eq 'network/observed-flow/v1' })
$labFlows = @($flowEvents | Where-Object { $_.scope -eq 'lab-zone' })
$withDeny = @($denialEvents | Where-Object { $_.counter.deniedPackets -gt 0 })
$staleCount = @($denialEvents | Where-Object { $_.identityStale }).Count
$comparable = @($denialEvents | Where-Object { $_.baselineState -eq 'compared' })
$rebuilt = @($denialEvents | Where-Object { $_.baselineState -eq 'chain-rebuilt' })
$reset = @($denialEvents | Where-Object { $_.baselineState -eq 'counter-reset' })
$newSubjects = @($denialEvents | Where-Object { $_.baselineState -eq 'no-baseline' })

Write-Host ''
Write-Host "Chains read          : $chainCount"
Write-Host "Denial counter events: $($denialEvents.Count)  (pods with at least one refused packet: $($withDeny.Count))"
Write-Host "Observed flow events : $($flowEvents.Count)  (lab-zone: $($labFlows.Count), cluster-internal: $($($flowEvents.Count) - $labFlows.Count))"
if ($staleCount -gt 0) { Write-Host "Stale identity       : $staleCount chain(s) -- pod replaced mid-collection" -ForegroundColor Yellow }
Write-Host "Baseline             : $(if (-not $hadBaseline) { 'WRITTEN (first collection; nothing to compare against)' } elseif ($NoBaseline) { 'skipped' } else { 'updated' })"
Write-Host "Output               : $OutputPath"

# The baseline-state breakdown is the part that decides whether any number in
# this file may be read as a rate. Reported even when it is all zeroes, because
# a reader told "delta: 0" has been told something quite different from a
# reader told "delta unavailable: chain was rebuilt".
Write-Host ''
Write-Host 'Deltas by basis:' -ForegroundColor Cyan
Write-Host ("  comparable      : {0}  (delta is meaningful)" -f $comparable.Count)
Write-Host ("  chain rebuilt   : {0}" -f $rebuilt.Count)
Write-Host ("  counter reset   : {0}" -f $reset.Count)
Write-Host ("  new subject     : {0}" -f $newSubjects.Count)
foreach ($s in @($rebuilt) + @($reset)) {
    Write-Host ("    {0,-44} {1}" -f "$($s.subject.namespace)/$($s.subject.pod)", $s.baselineState) -ForegroundColor DarkYellow
}

# A pod that sent traffic and had none of it admitted is the strongest thing
# this collector can say, because it is a count from the enforcement point
# rather than an inference from a policy that should have blocked it. It stays
# valid across a chain rebuild, since it is a ratio within one reading.
$sealed = @($denialEvents | Where-Object {
    $_.counter.totalPackets -gt 0 -and $_.counter.acceptedPackets -eq 0 -and $_.counter.deniedPackets -gt 0
})
if ($sealed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Pods that sent traffic and had none of it admitted:' -ForegroundColor Cyan
    foreach ($s in $sealed) {
        Write-Host ("  {0,-40} {1} sent, {2} refused, 0 admitted" -f "$($s.subject.namespace)/$($s.subject.pod)", $s.counter.totalPackets, $s.counter.deniedPackets)
    }
}

# Report what moved only where a delta is actually defined.
$activity = @($comparable | Where-Object { $_.counter.deltaDenied -gt 0 })
if ($activity.Count -gt 0) {
    Write-Host ''
    Write-Host 'Refusals since the previous collection (comparable chains only):' -ForegroundColor Cyan
    foreach ($a in $activity) {
        Write-Host ("  {0,-40} +{1} denied, +{2} accepted, +{3} total" -f `
            "$($a.subject.namespace)/$($a.subject.pod)", $a.counter.deltaDenied, $a.counter.deltaAccepted, $a.counter.deltaTotal)
    }
}

Write-Host ''
if (-not $hadBaseline) {
    Write-Host 'First collection: counters are cumulative since each pod chain was built.' -ForegroundColor Yellow
    Write-Host 'They are NOT a rate. Collect again after some activity to get deltas.' -ForegroundColor Yellow
}
