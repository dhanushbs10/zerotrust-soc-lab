<#
.SYNOPSIS
    Builds the who-can-reach-what graph, then proves the graph answers correctly.

.DESCRIPTION
    Phase 6 exists to answer one question correctly: given an identity in this
    cluster, what can it reach, and on which ports. Everything downstream is
    built on that answer, so the answer is the deliverable and the diagram is
    only its output.

    The graph is derived, not drawn
    -------------------------------
    Nodes are the running lab workloads, read from the API: namespace, zone
    label, service account, pod IP, and the ports their Service exposes. Edges
    are computed by evaluating the live NetworkPolicies with Kubernetes
    semantics, including the parts that are easy to get wrong:

      - a connection needs BOTH sides to agree. The source's egress policy and
        the destination's ingress policy must each permit it. One-sided
        permission is not permission.
      - selecting a pod for a direction isolates it in that direction. If any
        policy selects the pod with Ingress in its policyTypes and no rule
        matches, the answer is deny regardless of what any other rule says.
      - a bare podSelector means the policy's own namespace. A
        namespaceSelector alone spans namespaces. Both together mean pods
        matching the selector inside namespaces matching the namespace selector.
      - an omitted ports list means every port, which is how
        telemetry-agent-ingress admits its whole zone.

    A graph derived from policy is only a claim until it is checked, so every
    edge is measured
    --------------------------------
    Each modelled pair is compared against a real TCP connection opened from a
    probe pod carrying that source's service account, dialling the destination
    Service's ClusterIP -- the address a real client uses, so the service proxy
    and DNAT path are exercised rather than bypassed.

    Both directions are checked. A model that permits something the datapath
    refuses is an over-approximation and is the dangerous kind, because it
    invents access that does not exist. A model that refuses something the
    datapath permits is an under-approximation and hides real access. Neither is
    acceptable, and checking only the permitted edges would find the first kind
    and never the second.

    The positive control, and why it is not optional
    -----------------------------------------------
    A verification harness in which every probe returns "blocked" looks exactly
    like a perfectly isolated cluster. Those two states are indistinguishable
    from the output alone, and a broken probe mechanism would be reported as a
    security result.

    So before any comparison is believed, every probe pod is required to open a
    TCP connection to kube-dns on port 53. DNS egress is permitted in all three
    lab namespaces and kube-system carries no policies at all, so that
    connection is open independently of everything this script models. If DNS
    fails, the probe mechanism is broken, and the script aborts rather than
    reporting the lab as unreachable from itself.

    What this does not cover
    -----------------------
    Network reachability is not the whole of access. RBAC is not modelled here;
    identities/20-rbac.yaml grants sa-build-runner cluster-admin, which is the
    single most consequential permission in the lab and is invisible to a
    network graph, because cluster-admin is not a network flow. That gap is
    deliberate and it is the subject of PP-01.

    The API server is also not a node. No pod can reach it, because kube-router
    DNATs the ClusterIP before the policy chain is consulted -- see the long
    comment in identities/34-networkpolicy-zones.yaml. The control plane is
    therefore reached by an authenticated client from outside the cluster, and
    an exec-based detection cannot use "who" as a discriminator here. Both are
    properties of the lab, not gaps in this script.

.PARAMETER GraphPath
    Graph JSON destination. Defaults to .telemetry\reachability-graph.json

.PARAMETER ReportPath
    Verification report destination, which the dashboard reads for the
    modelled-versus-observed table. Defaults to .telemetry\reachability-verify.json

.PARAMETER Namespace
    Restrict the graph to one namespace.

.PARAMETER SkipProbes
    Emit the model without verifying it. The output is marked unverified and
    says so in every field a consumer would read, because an unverified
    reachability graph presented as a reachability graph is worse than none.

.PARAMETER KeepProbes
    Leave the probe pods running for inspection. They are deleted otherwise.

.EXAMPLE
    .\build-reachability.ps1

.EXAMPLE
    .\build-reachability.ps1 -Namespace zerotrust
#>

[CmdletBinding()]
param(
    [string]$GraphPath,
    [string]$ReportPath,
    [string]$Namespace,
    [switch]$SkipProbes,
    [switch]$KeepProbes,
    [switch]$SelfTest
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $GraphPath) { $GraphPath = Join-Path $projectRoot '.telemetry\reachability-graph.json' }
if (-not $ReportPath) { $ReportPath = Join-Path $projectRoot '.telemetry\reachability-verify.json' }

# Digest-pinned, and the same image tools/test-boundaries.ps1 uses. The probe
# exists to open a TCP connection and nothing else, so its contents are
# irrelevant as long as they cannot differ between runs.
$PROBE_IMAGE = 'alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc'

$DnsService = 'kube-dns'
$DnsNamespace = 'kube-system'
$DnsPort = 53

# nc's own timeout. It does not decide when an attempt ends -- busybox ends it
# when the kernel finishes its own SYN retry, around one second, regardless of
# this value -- but it is kept as a bound so no probe can hang.
$script:ProbeTimeoutSeconds = 3

# How long a connection attempt must take before it is called dropped rather
# than refused. Measured from inside the pod, so no host constant is involved.
# Across two full 25-pair runs:
#
#   answered            0ms 10ms 30ms 50ms 100ms 100ms 100ms 210ms 440ms
#                       500ms 600ms          (the slow ones are all DNS controls)
#   refused, no listener 0ms 100ms
#   dropped, no answer  1000ms .. 1120ms, and one at 2070ms
#
# Two populations with an empty decade between them: nothing that answered
# returned a failure, and nothing that failed came back in under 1000ms. 600ms
# sits in the middle of the gap.
#
# The exit code is tested FIRST, so a successful connection is 'open' however
# slow it was, and this number only ever decides what a FAILURE was. That is
# what makes the margin safe rather than lucky, because the answered population
# is not as tidy as the failure population: a busy run answered a DNS control in
# 600ms, which would be alarming if a slow success could be called a drop. It
# cannot. The failure that has to be classified correctly is a refusal, and a
# refusal is a RST raised by the kernel on the far side, which network latency
# cannot stretch.
#
# The dropped cluster sits at ~1s because that is when the kernel finishes its
# own SYN retry and gives up; the 2070ms outlier is it doing a second one. -w
# has no effect on any of it. Changing this number without re-measuring would
# move a real decision, so the measurement is recorded here rather than left as
# folklore, and -SelfTest pins the boundary to the measured extremes.
$script:DropThresholdMs = 600

function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('-' * $Text.Length) -ForegroundColor DarkGray
}

# ConvertFrom-Json hands matchLabels back as a PSCustomObject, not a hashtable
# and not a dictionary, so .Keys and .GetEnumerator() both fail on it. Every
# label map in this script goes through here.
function Get-LabelMap {
    param($Object)
    $map = @{}
    if ($null -eq $Object) { return $map }
    foreach ($p in $Object.PSObject.Properties) {
        if ($null -ne $p.Value) { $map[$p.Name] = [string]$p.Value }
    }
    return $map
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Returns a real array, never $null, so that .Count is meaningful.
#
# The leading comma is load-bearing. A PowerShell function that "returns" an
# empty array emits nothing at all, so the caller receives $null rather than an
# empty array, and under Set-StrictMode the first .Count on it throws. Writing
# `return @()` looks correct and is not. `return , @()` wraps the array so that
# even an empty one is emitted as a single object.
#
# This is why the helper exists at all rather than a bare @($x) at the call
# site: @($null) is a one-element array containing null, so a filter written as
# "@($x).Count -gt 0" matches everything instead of nothing.
function Get-ArrayOf {
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [string]) { return , @($Value) }
    if ($Value -is [array]) { return , @($Value) }
    return , @($Value)
}

# A selector matches when every label it names is present and equal. A null or
# empty selector matches everything, which is what an omitted
# namespaceSelector: {} means and is the single most misread field in
# NetworkPolicy.
function Test-LabelSelector {
    param($Selector, [hashtable]$Target)
    $want = Get-LabelMap $Selector
    if ($want.Count -eq 0) { return $true }
    foreach ($k in $want.Keys) {
        if (-not $Target.ContainsKey($k)) { return $false }
        if ($Target[$k] -ne $want[$k]) { return $false }
    }
    return $true
}

function Test-PolicySelectsPod {
    param($Policy, $Pod)
    if ($Policy.namespace -ne $Pod.namespace) { return $false }
    return (Test-LabelSelector (Get-Prop $Policy.spec.podSelector 'matchLabels') $Pod.labels)
}

# One peer entry inside a from/to list. $PolicyNamespace matters: a bare
# podSelector is scoped to the policy's own namespace, not to the peer pod's.
function Test-PeerMatches {
    param($Peer, [string]$PolicyNamespace, $PeerPod, $NamespaceLabels)
    $podSel = Get-Prop $Peer 'podSelector'
    $nsSel = Get-Prop $Peer 'namespaceSelector'

    $hasPod = ($null -ne $podSel)
    $hasNs = ($null -ne $nsSel)

    if (-not $hasPod -and -not $hasNs) {
        # A from/to entry with neither selector admits every source. Legal, and
        # almost never what a reviewer means.
        return $true
    }

    if ($hasNs) {
        # The namespace selector is matched against the LABELS OF THE PEER'S
        # OWN NAMESPACE, not against the map of every namespace in the cluster.
        # Passing the whole map here is a type-compatible mistake that silently
        # denies everything: ContainsKey('zerotrust.lab/zone') is false against a
        # map keyed by namespace name, so every cross-zone rule stops matching
        # and the three PP-02 observation edges disappear from the graph.
        $peerNsLabels = $NamespaceLabels[$PeerPod.namespace]
        if ($null -eq $peerNsLabels) { return $false }
        if (-not (Test-LabelSelector (Get-Prop $nsSel 'matchLabels') $peerNsLabels)) { return $false }
    }
    else {
        # No namespaceSelector: the policy's own namespace only.
        if ($PeerPod.namespace -ne $PolicyNamespace) { return $false }
    }

    if ($hasPod) {
        if (-not (Test-LabelSelector (Get-Prop $podSel 'matchLabels') $PeerPod.labels)) { return $false }
    }

    return $true
}

function Test-PortMatches {
    param($Ports, [int]$Port, [string]$Protocol)
    $list = Get-ArrayOf $Ports
    if ($list.Count -eq 0) { return $true }
    foreach ($p in $list) {
        $endPort = Get-Prop $p 'endPort'
        if ($null -ne $endPort) {
            throw "policy port range (endPort) is not supported by this model; refusing to guess at a range"
        }
        $proto = [string](Get-Prop $p 'protocol')
        if (-not $proto) { $proto = 'TCP' }
        if ($proto -ne $Protocol) { continue }
        $portVal = Get-Prop $p 'port'
        if ($null -eq $portVal) { return $true }
        if ([string]$portVal -eq [string]$Port) { return $true }
    }
    return $false
}

# Decides one direction for one pair.
#
# Returns a record rather than a boolean, because "denied" is only useful to a
# reader if it can be traced to the policy that denied it. An unexplained deny
# is indistinguishable from a modelling error, and this lab has already produced
# one of those.
function Get-DirectionDecision {
    param($Direction, $SubjectPod, $PeerPod, [int]$Port, [string]$Protocol, $Policies, $NamespaceLabels)

    # Two spellings, and conflating them is silent. policyTypes is a Kubernetes
    # enum and is capitalised ('Ingress'); the spec field holding the rules is
    # lower case ('ingress'). Comparing the capitalised value against a lower
    # case key matches nothing, which makes every pod look unisolated and turns
    # the whole graph into 25/25 open without a single error being raised.
    if ($Direction -eq 'ingress') {
        $policyType = 'Ingress'
        $specField = 'ingress'
    }
    else {
        $policyType = 'Egress'
        $specField = 'egress'
    }

    $selecting = @($Policies | Where-Object {
            (Test-PolicySelectsPod $_ $SubjectPod) -and
            (@(Get-Prop $_.spec 'policyTypes') -contains $policyType)
        })

    if ($selecting.Count -eq 0) {
        # No policy selects this pod for this direction, so nothing isolates it.
        return [pscustomobject]@{
            direction = $Direction; allowed = $true; isolated = $false
            decidedBy = @(); reason = 'no policy selects this pod for this direction, so it is not isolated'
        }
    }

    $allowBy = @()
    foreach ($pol in $selecting) {
        $rules = Get-ArrayOf (Get-Prop $pol.spec $specField)
        foreach ($r in $rules) {
            $peers = Get-ArrayOf (Get-Prop $r ($(if ($specField -eq 'ingress') { 'from' } else { 'to' })))
            $peerHit = $false
            if ($peers.Count -eq 0) {
                # A rule with no from/to admits every peer on the listed ports.
                $peerHit = $true
            }
            else {
                foreach ($peer in $peers) {
                    if (Test-PeerMatches -Peer $peer -PolicyNamespace $pol.namespace -PeerPod $PeerPod -NamespaceLabels $NamespaceLabels) {
                        $peerHit = $true
                        break
                    }
                }
            }
            if ($peerHit -and (Test-PortMatches (Get-Prop $r 'ports') $Port $Protocol)) {
                $allowBy += $pol.name
            }
        }
    }

    if ($allowBy.Count -gt 0) {
        return [pscustomobject]@{
            direction = $Direction; allowed = $true; isolated = $true
            decidedBy = @($allowBy | Sort-Object -Unique)
            reason = 'a rule in a selecting policy admits this peer on this port'
        }
    }

    return [pscustomobject]@{
        direction = $Direction; allowed = $false; isolated = $true
        decidedBy = @()
        reason = "selected for $Direction by $(@($selecting | ForEach-Object { $_.name }) -join ', ') and no rule admits this peer on this port"
    }
}

# Opens one TCP connection from inside a probe pod and reports what happened.
#
# The ErrorActionPreference dance is required, not defensive. A refused
# connection is the expected result for most of this matrix, and nc exits
# non-zero and writes to stderr when refused. Under the script-wide
# $ErrorActionPreference = 'Stop', that combination is raised as a terminating
# PowerShell error and kills the run on the first blocked pair -- which is
# exactly the result the script is trying to measure. So the preference is
# relaxed for the call and the exit code is read directly.
#
# A failed connection has two completely different causes, and nc reports them
# identically:
#
#   the firewall DROPPED the SYN  -> nothing ever comes back
#   the path was fine and the far
#   end sent RST                   -> the answer is immediate
#
# Collapsing those two into "blocked" is not a cosmetic imprecision. It turns a
# real policy finding into a fake security result, and it does so silently.
#
# The case that forced this: the model says telemetry-agent can reach
# telemetry-agent on 8080, because telemetry-agent-ingress admits its whole
# zone. The datapath agreed. Nothing was listening -- netstat -lnt in the sensor
# returns no sockets at all, because the sensor runs a shell probe loop and no
# server -- so the connection was refused at the application layer and the first
# version of this function reported a policy violation that did not exist.
#
# How the two are told apart
# --------------------------
# busybox nc -v prints "open" on success and NOTHING on failure, so the reason
# is not available from nc at all. The only remaining signal is how long the
# attempt took, and it has to be measured for the right reason.
#
# Timing it from the host with Stopwatch does not work. kubectl exec overhead
# alone measured 630ms on this machine, and the real gap underneath it is small:
#
#   refused   697ms  959ms  710ms  589ms  603ms   (nc -w 1, 2, 3, 5, 8)
#   dropped  1547ms 1619ms 1685ms 1602ms 1882ms
#
# Two problems. Once the constant is subtracted the gap is well under a second,
# which is inside the noise of a loaded machine, and -w does not move it at all
# -- the attempt ends when the kernel finishes its own SYN retry, not when nc's
# timeout expires. A threshold fitted to those numbers would be a
# machine-specific constant dressed up as a measurement.
#
# So the clock is read inside the pod instead, from /proc/uptime, immediately
# before and after nc. That removes the host from the measurement entirely. Over
# two full 25-pair runs:
#
#   open / refused     0ms .. 600ms         (something answered)
#   dropped         1000ms .. 2070ms        (the kernel's SYN retry, unanswered)
#
# Two populations with an empty decade between them. See $script:DropThresholdMs
# for the full distribution and where the cut sits in it.
#
# The classifier is also checked against the model rather than trusted. A
# misclassification cannot pass silently, because a verdict that contradicts the
# model is reported as a mismatch and fails the run, and because the run refuses
# to finish if no probe anywhere came back 'dropped' -- a classifier that never
# distinguishes a drop has demonstrated nothing.
# Does an observation support what the model claimed?
#
# Three outcomes, not two, and the third is the one that decides this lab's
# self-edge. 'permitted-refused' means the network allowed the connection and
# the far end actively refused it: a policy-permitted path with nothing
# listening behind it. That agrees with a model that says open, because the
# model is about the network and not about whether a server is deployed.
#
# The function is named for the question it answers rather than returning a bare
# boolean, because the two failure directions are opposites and only one of them
# gets noticed: a model that permits what the firewall drops invents access that
# does not exist, while a model that denies what the firewall permits hides
# access that does.
function Test-ObservationAgrees {
    param([string]$Modelled, [string]$Observed)
    return ($Observed -eq 'open' -and $Modelled -eq 'open') -or
    ($Observed -eq 'dropped' -and $Modelled -eq 'blocked') -or
    ($Observed -eq 'permitted-refused' -and $Modelled -eq 'open')
}

function Invoke-TcpProbe {
    param([string]$Namespace, [string]$Pod, [string]$Ip, [int]$Port)

    $ErrorActionPreference = 'Continue'

    # Quote-free by necessity: PowerShell strips embedded double quotes before a
    # native executable sees them, so the field is taken with parameter expansion
    # instead of cut -d" " -f1. $S%% * strips everything from the first space on,
    # leaving the uptime figure. /proc/uptime has two decimals, so resolution is
    # 10ms -- ample against a 1s signal.
    $cmd = 'S=$(cat /proc/uptime); S=${S%% *}; nc -w ' + $script:ProbeTimeoutSeconds + ' ' +
    $Ip + ' ' + $Port +
    ' >/dev/null 2>&1; R=$?; E=$(cat /proc/uptime); E=${E%% *}; echo $S $E $R'

    $raw = (& kubectl exec -n $Namespace $Pod -- sh -c $cmd 2>&1 | Out-String).Trim()
    $kubectlCode = $LASTEXITCODE

    # sh -c ends with echo, so kubectl exits 0 whatever nc did. Anything else,
    # or output that is not three numbers, means the measurement did not happen.
    # That is a broken probe mechanism and must never be read as a result: a
    # refused connection and a failed exec both look like "not open", and only
    # one of them is a fact about the network.
    $parts = @($raw -split '\s+' | Where-Object { $_ -ne '' })
    if ($kubectlCode -ne 0 -or $parts.Count -ne 3) {
        throw ("probe measurement failed for {0}:{1} in {2}/{3}: kubectl exit {4}, output '{5}'" -f `
                $Ip, $Port, $Namespace, $Pod, $kubectlCode, $raw)
    }

    $elapsedMs = [math]::Round(([double]$parts[1] - [double]$parts[0]) * 1000)
    $rc = [int]$parts[2]

    $verdict = if ($rc -eq 0) { 'open' }
    elseif ($elapsedMs -ge $script:DropThresholdMs) { 'dropped' }
    else { 'permitted-refused' }

    return [pscustomobject]@{
        verdict   = $verdict
        elapsedMs = $elapsedMs
        rc        = $rc
    }
}

# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
#
# A reachability checker that cannot report a disagreement is worse than no
# checker, because it is trusted. Every bug this script has had was silent: it
# reported a confident, plausible, wrong answer. Nothing about running it against
# a live cluster would have caught any of them, because a wrong model and a
# working one look the same from the output.
#
# So the pure decision logic is exercised here against fixtures where the right
# answer is known, before a single packet moves. These are the real functions
# from this file, not a reimplementation: a test that checked a copy would pass
# while the thing that ships stayed broken.
#
# The fixtures are chosen so that an inverted or collapsed rule fails loudly.
# Three of them assert DISAGREEMENT, which is the case a broken checker loses
# first, and two assert that something throws rather than guessing.
if ($SelfTest) {

    Write-Head 'self-test: the decision logic, against known answers'

    $script:SelfTestPass = 0
    $script:SelfTestFail = 0

    function Assert-That {
        param([string]$Name, [bool]$Condition, [string]$Why)
        if ($Condition) {
            Write-Host ("    [ok  ] {0}" -f $Name) -ForegroundColor DarkGray
            $script:SelfTestPass++
        }
        else {
            Write-Host ("    [FAIL] {0}" -f $Name) -ForegroundColor Red
            Write-Host ("           {0}" -f $Why) -ForegroundColor Red
            $script:SelfTestFail++
        }
    }

    # --- the agreement rule, which is the heart of the verification ---------
    # Defined once, at file scope, and used by both the fixtures and the run. An
    # earlier draft inlined it at the call site as well, which is precisely the
    # duplication this test exists to catch.
    $fixtures = @(
        @{ m = 'open'; o = 'open'; want = $true; why = 'modelled open, a server answered' }
        @{ m = 'blocked'; o = 'dropped'; want = $true; why = 'modelled blocked, the SYN was dropped' }
        @{ m = 'open'; o = 'permitted-refused'; want = $true; why = 'modelled open, permitted, nothing listening' }
        @{ m = 'open'; o = 'dropped'; want = $false; why = 'a model that permits something the firewall drops is the dangerous direction and must disagree' }
        @{ m = 'blocked'; o = 'open'; want = $false; why = 'a real path the model denies is hidden access and must disagree' }
        @{ m = 'blocked'; o = 'permitted-refused'; want = $false; why = 'a refused connection is not a dropped one, and reading it as blocked hides permitted access' }
        @{ m = 'open'; o = 'blocked'; want = $false; why = 'the old two-valued verdict no longer exists' }
    )
    foreach ($f in $fixtures) {
        $got = Test-ObservationAgrees -Modelled $f.m -Observed $f.o
        Assert-That ("modelled={0,-8} observed={1,-18} -> {2}" -f $f.m, $f.o, $(if ($f.want) { 'agree' } else { 'DISAGREE' })) `
            ($got -eq $f.want) ("expected " + $(if ($f.want) { 'agree' } else { 'disagreement' }) + " but got " + $got + ". " + $f.why)
    }

    # --- the drop classifier ------------------------------------------------
    function Get-Verdict {
        param([int]$Rc, [double]$ElapsedMs)
        if ($Rc -eq 0) { return 'open' }
        if ($ElapsedMs -ge $script:DropThresholdMs) { return 'dropped' }
        return 'permitted-refused'
    }

    # The elapsed values are the ones actually observed on this cluster, not
    # round numbers, so the threshold is tested against the real distribution and
    # not against a caricature of it. The two boundary cases pin the decision
    # exactly: 599ms is still a refusal and 600ms is already a drop.
    $classify = @(
        @{ rc = 0; ms = 0.0; want = 'open'; n = 'answered immediately' }
        @{ rc = 0; ms = 210.0; want = 'open'; n = 'the slowest answer ever observed, a DNS control' }
        @{ rc = 1; ms = 0.0; want = 'permitted-refused'; n = 'refused instantly' }
        @{ rc = 1; ms = 100.0; want = 'permitted-refused'; n = 'the slowest refusal ever observed' }
        @{ rc = 1; ms = 599.0; want = 'permitted-refused'; n = 'just below the threshold' }
        @{ rc = 1; ms = 600.0; want = 'dropped'; n = 'just at the threshold' }
        @{ rc = 1; ms = 1000.0; want = 'dropped'; n = 'the fastest drop ever observed' }
        @{ rc = 1; ms = 1110.0; want = 'dropped'; n = 'the slowest drop ever observed' }
    )
    foreach ($c in $classify) {
        $got = Get-Verdict -Rc $c.rc -ElapsedMs $c.ms
        Assert-That ("rc={0} {1,7}ms -> {2}" -f $c.rc, $c.ms, $got) ($got -eq $c.want) ("expected " + $c.want + " but got " + $got + " for " + $c.n)
    }

    # --- helpers that have each produced a silent wrong answer -------------
    #
    # Get-ArrayOf returning nothing instead of an empty array. `return @()`
    # emits no object at all, so the caller received $null and .Count threw under
    # Set-StrictMode. The symptom was a crash, but only on the path where the
    # result was empty -- which is to say, only where the answer was "nothing",
    # the one case nobody was looking at.
    $empty = Get-ArrayOf -Value $null
    Assert-That 'Get-ArrayOf on $null returns an array, not $null' `
        ($null -ne $empty -and $empty.Count -eq 0) ("got " + $(if ($null -eq $empty) { '$null' } else { "count " + $empty.Count }))

    $emptyList = Get-ArrayOf -Value @()
    Assert-That 'Get-ArrayOf on an empty list returns an array, not $null' `
        ($null -ne $emptyList -and $emptyList.Count -eq 0) ("got " + $(if ($null -eq $emptyList) { '$null' } else { "count " + $emptyList.Count }))

    $one = Get-ArrayOf -Value 'single'
    Assert-That 'Get-ArrayOf on a scalar returns a one-element array' ($one.Count -eq 1 -and $one[0] -eq 'single') 'a scalar was not wrapped'

    # Get-Prop on an absent property. Under Set-StrictMode a direct $obj.prop
    # throws, which is correct, but the graph reads properties that are optional
    # in the API (a Service with no labels) and must not die on them.
    $noLabels = [pscustomobject]@{ metadata = [pscustomobject]@{ name = 'x' } }
    $got2 = Get-Prop (Get-Prop $noLabels 'metadata' 'labels') 'app'
    Assert-That 'Get-Prop returns $null for an absent property instead of throwing' ($null -eq $got2) ("got " + $got2)

    # Get-LabelMap on a matchLabels that ConvertFrom-Json turned into a
    # PSCustomObject. .Keys and .GetEnumerator() both fail on one, and both fail
    # the same way a real policy would.
    $ml = Get-LabelMap ([pscustomobject]@{ app = 'orders-api' })
    Assert-That 'Get-LabelMap reads a PSCustomObject matchLabels' ($ml['app'] -eq 'orders-api') ("got " + $ml['app'])

    # Test-PortMatches must refuse a range rather than guess. An endPort rule
    # evaluated as if it were a single port produces a confidently wrong edge.
    $threw = $false
    try {
        $null = Test-PortMatches -Ports @([pscustomobject]@{ protocol = 'TCP'; port = 8080; endPort = 8090 }) -Port 8085 -Protocol 'TCP'
    }
    catch { $threw = $true }
    Assert-That 'Test-PortMatches throws on an endPort range rather than guessing' $threw 'a port range was silently evaluated as a single port'

    # A single port must still match itself, and must not match a neighbour.
    $single = @([pscustomobject]@{ protocol = 'TCP'; port = 8080 })
    Assert-That 'Test-PortMatches matches the exact port' (Test-PortMatches -Ports $single -Port 8080 -Protocol 'TCP') 'exact port did not match'
    Assert-That 'Test-PortMatches rejects a different port' (-not (Test-PortMatches -Ports $single -Port 8081 -Protocol 'TCP')) 'a neighbouring port matched'

    # An omitted ports list means every port. This is how telemetry-agent-ingress
    # admits its whole zone, and a model that got it wrong would either invent
    # edges or lose that one.
    Assert-That 'Test-PortMatches treats an omitted ports list as every port' `
        (Test-PortMatches -Ports $null -Port 65000 -Protocol 'TCP') 'an omitted ports list was not treated as unrestricted'

    # TCP and UDP are different ports as far as a policy is concerned, and
    # conflating them would claim a UDP path exists because a TCP one does.
    Assert-That 'Test-PortMatches does not match TCP against a UDP rule' `
        (-not (Test-PortMatches -Ports @([pscustomobject]@{ protocol = 'UDP'; port = 53 }) -Port 53 -Protocol 'TCP')) 'a UDP rule matched a TCP connection'

    # --- policyTypes casing, the bug that broke the whole model ------------
    #
    # policyTypes is an enum and is capitalised ('Ingress'); the spec field
    # holding the rules is lower case ('ingress'). Conflating the two made every
    # pod look unisolated and produced a graph of 25/25 open with no error
    # raised anywhere -- a model that permits everything is indistinguishable
    # from a badly configured cluster, and neither can be caught by reading it.
    #
    # These two fixtures pin both halves. If a policy that selects for Ingress
    # stops being seen as selecting, the first fails and the model invents
    # access. If the rule list stops being found under the lower-case field, the
    # first fails the other way. Note that -contains is case-insensitive in
    # PowerShell, so the selection test alone would NOT catch a casing mistake;
    # it is the paired assertion that does the work.
    $testNs = @{ zerotrust = @{ 'zerotrust.lab/zone' = 'workload' } }
    $subject = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'web-frontend-1'
        labels = @{ app = 'web-frontend' }
    }
    $peerOther = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'build-runner-1'
        labels = @{ app = 'build-runner' }
    }
    $peerOwn = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'orders-api-1'
        labels = @{ app = 'orders-api' }
    }

    $ingPolicy = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'web-frontend-ingress'
        spec = [pscustomobject]@{
            podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'web-frontend' } }
            policyTypes = @('Ingress')
            ingress = @(
                [pscustomobject]@{
                    from = @([pscustomobject]@{ podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'orders-api' } } })
                    ports = @([pscustomobject]@{ protocol = 'TCP'; port = 80 })
                }
            )
        }
    }

    $d1 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subject -PeerPod $peerOwn `
        -Port 80 -Protocol 'TCP' -Policies @($ingPolicy) -NamespaceLabels $testNs
    Assert-That 'a capitalised policyTypes is seen as selecting, and its lower-case ingress rules are found' `
        ($d1.allowed -and $d1.isolated) ("got allowed=" + $d1.allowed + " isolated=" + $d1.isolated)

    $d2 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subject -PeerPod $peerOther `
        -Port 80 -Protocol 'TCP' -Policies @($ingPolicy) -NamespaceLabels $testNs
    Assert-That 'a selecting policy whose rule does not admit the peer denies it' `
        (-not $d2.allowed -and $d2.isolated) ("got allowed=" + $d2.allowed + " isolated=" + $d2.isolated + " reason=" + $d2.reason)

    # The same policy must not be treated as selecting for egress. If the
    # direction were ignored, this policy would start governing outbound
    # traffic and the model would lose the default-deny that makes the lab
    # interesting.
    $egPolicy = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'web-frontend-egress'
        spec = [pscustomobject]@{
            podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'web-frontend' } }
            policyTypes = @('Egress')
            egress = @(
                [pscustomobject]@{
                    to = @([pscustomobject]@{ podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'orders-api' } } })
                    ports = @([pscustomobject]@{ protocol = 'TCP'; port = 8080 })
                }
            )
        }
    }
    $d3 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subject -PeerPod $peerOther `
        -Port 80 -Protocol 'TCP' -Policies @($egPolicy) -NamespaceLabels $testNs
    Assert-That 'an Egress-only policy does not isolate the pod for ingress' `
        ($d3.allowed -and -not $d3.isolated) ("got allowed=" + $d3.allowed + " isolated=" + $d3.isolated)

    # And the mirror image, so neither direction can be silently dropped.
    $d4 = Get-DirectionDecision -Direction 'egress' -SubjectPod $subject -PeerPod $peerOwn `
        -Port 8080 -Protocol 'TCP' -Policies @($egPolicy) -NamespaceLabels $testNs
    Assert-That 'an Egress policy is seen as selecting for egress' `
        ($d4.allowed -and $d4.isolated) ("got allowed=" + $d4.allowed + " isolated=" + $d4.isolated)

    # A bare podSelector is scoped to the policy's own namespace. Admitting a pod
    # by label while ignoring the namespace would let any pod anywhere with that
    # label in, which is the mistake that makes a zone boundary decorative.
    $crossNs = [pscustomobject]@{
        namespace = 'zerotrust-observe'
        name = 'telemetry-agent-1'
        labels = @{ app = 'orders-api' }
    }
    $d5 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subject -PeerPod $crossNs `
        -Port 80 -Protocol 'TCP' -Policies @($ingPolicy) -NamespaceLabels $testNs
    Assert-That 'a bare podSelector does not admit the same label in another namespace' `
        (-not $d5.allowed -and $d5.isolated) ("got allowed=" + $d5.allowed + " isolated=" + $d5.isolated)

    # --- namespaceSelector, and which namespace's labels it reads ----------
    #
    # This is the shape PP-02 depends on: the sensor admits its whole zone and
    # nothing else. It is also where a real bug hid. The peer check was handed
    # the map of every namespace in the cluster instead of the labels of the
    # peer's own namespace. That is type-compatible, so it compiled, ran, and
    # matched nothing -- silently denying every cross-zone rule, so the three
    # observation edges the whole PP-02 path exists to permit simply vanished
    # from the graph with no error anywhere.
    #
    # Both polarities are asserted, because a selector that admits nothing and a
    # selector that admits everything fail in opposite directions and only one
    # of them is likely to be noticed.
    $zoneNs = @{
        zerotrust          = @{ 'zerotrust.lab/zone' = 'workload' }
        'zerotrust-observe' = @{ 'zerotrust.lab/zone' = 'observe' }
        'zerotrust-build'   = @{ 'zerotrust.lab/zone' = 'build' }
    }
    $subjectZone = [pscustomobject]@{
        namespace = 'zerotrust-observe'
        name = 'telemetry-agent-1'
        labels = @{ app = 'telemetry-agent' }
    }
    $zonePolicy = [pscustomobject]@{
        namespace = 'zerotrust-observe'
        name = 'telemetry-agent-ingress'
        spec = [pscustomobject]@{
            podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'telemetry-agent' } }
            policyTypes = @('Ingress')
            # No ports list at all, which means every port. That is how the
            # sensor admits its whole zone.
            ingress = @(
                [pscustomobject]@{
                    from = @([pscustomobject]@{
                            namespaceSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ 'zerotrust.lab/zone' = 'observe' } }
                        })
                }
            )
        }
    }
    $peerInZone = [pscustomobject]@{
        namespace = 'zerotrust-observe'
        name = 'another-observe-pod'
        labels = @{ app = 'other-observer' }
    }
    $peerOutOfZone = [pscustomobject]@{
        namespace = 'zerotrust'
        name = 'orders-api-1'
        labels = @{ app = 'orders-api' }
    }
    $peerBuildZone = [pscustomobject]@{
        namespace = 'zerotrust-build'
        name = 'build-runner-1'
        labels = @{ app = 'build-runner' }
    }

    $z1 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subjectZone -PeerPod $peerInZone `
        -Port 8080 -Protocol 'TCP' -Policies @($zonePolicy) -NamespaceLabels $zoneNs
    Assert-That 'a namespaceSelector admits a peer in the labelled zone' `
        ($z1.allowed -and $z1.isolated) ("got allowed=" + $z1.allowed + " isolated=" + $z1.isolated)

    $z2 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subjectZone -PeerPod $peerOutOfZone `
        -Port 8080 -Protocol 'TCP' -Policies @($zonePolicy) -NamespaceLabels $zoneNs
    Assert-That 'a namespaceSelector refuses a peer in a differently labelled zone' `
        (-not $z2.allowed -and $z2.isolated) ("got allowed=" + $z2.allowed + " isolated=" + $z2.isolated)

    $z3 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subjectZone -PeerPod $peerBuildZone `
        -Port 8080 -Protocol 'TCP' -Policies @($zonePolicy) -NamespaceLabels $zoneNs
    Assert-That 'a namespaceSelector refuses a third zone it does not name' `
        (-not $z3.allowed -and $z3.isolated) ("got allowed=" + $z3.allowed + " isolated=" + $z3.isolated)

    # A namespaceSelector with no matchLabels is the single most misread field in
    # NetworkPolicy. It means EVERY namespace, not "none" and not "this one", and
    # reading it as a restriction is how a policy ends up closed in a way nobody
    # intended. The peer's namespace here carries no zone label at all, so a
    # selector that accidentally required one would deny it.
    $unlabelledNs = @{ mystery = @{} }
    $anyNsPolicy = [pscustomobject]@{
        namespace = 'zerotrust-observe'
        name = 'any-namespace-ingress'
        spec = [pscustomobject]@{
            podSelector = [pscustomobject]@{ matchLabels = [pscustomobject]@{ app = 'telemetry-agent' } }
            policyTypes = @('Ingress')
            ingress = @(
                [pscustomobject]@{
                    from = @([pscustomobject]@{ namespaceSelector = [pscustomobject]@{} })
                    ports = @([pscustomobject]@{ protocol = 'TCP'; port = 8080 })
                }
            )
        }
    }
    $peerUnlabelled = [pscustomobject]@{
        namespace = 'mystery'
        name = 'unlabelled-namespace-pod'
        labels = @{ app = 'anything' }
    }
    $z4 = Get-DirectionDecision -Direction 'ingress' -SubjectPod $subjectZone -PeerPod $peerUnlabelled `
        -Port 8080 -Protocol 'TCP' -Policies @($anyNsPolicy) -NamespaceLabels $unlabelledNs
    Assert-That 'an empty namespaceSelector means every namespace, including an unlabelled one' `
        ($z4.allowed -and $z4.isolated) ("got allowed=" + $z4.allowed + " isolated=" + $z4.isolated)

    Write-Host ''
    Write-Host ("  {0} assertion(s): {1} pass, {2} fail" -f ($script:SelfTestPass + $script:SelfTestFail), $script:SelfTestPass, $script:SelfTestFail)
    if ($script:SelfTestFail -gt 0) {
        Write-Host ''
        Write-Host '  FAIL  the decision logic does not do what the graph says it does.' -ForegroundColor Red
        exit 1
    }
    Write-Host ''
    Write-Host '  PASS  the decision logic agrees with every known answer.' -ForegroundColor Green
    exit 0
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

$kr = & kubectl get daemonset kube-router -n kube-system -o jsonpath='{.status.numberReady}' 2>$null
if ($kr -ne $nodes.ToString()) {
    Write-Host "  kube-router ready on $kr of $nodes nodes. NetworkPolicy is not fully" -ForegroundColor Red
    Write-Host '  enforced, so every reachability answer below would be a guess.' -ForegroundColor Red
    exit 1
}
Write-Host "  kube-router ready on all $nodes nodes (NetworkPolicy is enforced)"

# ---------------------------------------------------------------------------
# live state
# ---------------------------------------------------------------------------

Write-Head 'reading live cluster state'

$LabZones = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

$nsJson = (& kubectl get namespaces -o json 2>$null | Out-String) | ConvertFrom-Json
$namespaceLabels = @{}
foreach ($n in $nsJson.items) { $namespaceLabels[$n.metadata.name] = Get-LabelMap (Get-Prop $n.metadata 'labels') }

$podsRaw = (& kubectl get pods -A -o json 2>$null | Out-String) | ConvertFrom-Json
$pods = @()
foreach ($p in $podsRaw.items) {
    if ($LabZones -notcontains $p.metadata.namespace) { continue }
    if ($p.status.phase -ne 'Running') { continue }
    # Probe pods are excluded by their annotation, not by their app label. They
    # deliberately carry the workload's real app label so the firewall treats
    # them as that workload, which means a label-based filter would no longer
    # find them and the graph would gain a duplicate node per probe.
    #
    # The check is for any zerotrust.lab/purpose value rather than this
    # script's own value, so probes left behind by tools/test-boundaries.ps1
    # (boundary-test-probe) are excluded too. Those carry the same real app
    # labels, so they would otherwise appear as duplicate nodes whenever a
    # boundary run overlapped this one.
    $purpose = Get-Prop (Get-Prop $p.metadata 'annotations') 'zerotrust.lab/purpose'
    if ($purpose) { continue }
    $pods += [pscustomobject]@{
        name = $p.metadata.name
        app = [string](Get-Prop (Get-Prop $p.metadata 'labels') 'app')
        namespace = $p.metadata.namespace
        zone = [string](Get-Prop $namespaceLabels[$p.metadata.namespace] 'zerotrust.lab/zone')
        serviceAccount = [string](Get-Prop $p.spec 'serviceAccountName')
        podIp = [string](Get-Prop $p.status 'podIP')
        labels = Get-LabelMap (Get-Prop $p.metadata 'labels')
    }
}
if ($Namespace) { $pods = @($pods | Where-Object { $_.namespace -eq $Namespace }) }
if ($pods.Count -lt 2) {
    Write-Host "  found $($pods.Count) lab pod(s). The graph needs at least two to have an edge." -ForegroundColor Red
    exit 1
}
Write-Host ("  {0} lab pod(s) running" -f $pods.Count)

$svcRaw = (& kubectl get svc -A -o json 2>$null | Out-String) | ConvertFrom-Json
$servicePorts = @{}
foreach ($s in $svcRaw.items) {
    if ($LabZones -notcontains $s.metadata.namespace) { continue }
    $app = [string](Get-Prop (Get-Prop $s.metadata 'labels') 'app')
    if (-not $app) { $app = $s.metadata.name }
    $pl = @()
    foreach ($port in (Get-ArrayOf $s.spec.ports)) {
        $pl += [pscustomobject]@{
            port = [int](Get-Prop $port 'port')
            protocol = [string](Get-Prop $port 'protocol')
            clusterIp = [string]$s.spec.clusterIP
            service = $s.metadata.name
        }
    }
    $servicePorts[$app] = $pl
}
Write-Host ("  {0} service(s) with exposed ports" -f $servicePorts.Count)

$npRaw = (& kubectl get networkpolicy -A -o json 2>$null | Out-String) | ConvertFrom-Json
$policies = @()
foreach ($p in $npRaw.items) {
    if ($LabZones -notcontains $p.metadata.namespace) { continue }
    $policies += [pscustomobject]@{
        name = $p.metadata.name
        namespace = $p.metadata.namespace
        spec = $p.spec
    }
}
Write-Host ("  {0} NetworkPolicy object(s) in the lab namespaces" -f $policies.Count)

# ---------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------

Write-Head 'modelled reachability'

$comparisons = @()

foreach ($src in $pods) {
    foreach ($dst in $pods) {
        if (-not $servicePorts.ContainsKey($dst.app)) { continue }
        foreach ($sp in $servicePorts[$dst.app]) {
            $port = [int]$sp.port
            $proto = if ($sp.protocol) { $sp.protocol } else { 'TCP' }

            $egress = Get-DirectionDecision -Direction 'egress' -SubjectPod $src -PeerPod $dst -Port $port -Protocol $proto -Policies $policies -NamespaceLabels $namespaceLabels
            $ingress = Get-DirectionDecision -Direction 'ingress' -SubjectPod $dst -PeerPod $src -Port $port -Protocol $proto -Policies $policies -NamespaceLabels $namespaceLabels

            # Both sides must agree. This is the rule the lab already lost an
            # afternoon to: a policy that looks permissive can still match no
            # packet because the other side never agreed to send.
            $allowed = ($egress.allowed -and $ingress.allowed)

            $why = @()
            if ($egress.allowed) { $why += "egress ok ($($egress.reason))" } else { $why += "egress denied: $($egress.reason)" }
            if ($ingress.allowed) { $why += "ingress ok ($($ingress.reason))" } else { $why += "ingress denied: $($ingress.reason)" }

            $comparisons += [pscustomobject]@{
                source = $src
                dest = $dst
                destApp = $dst.app
                port = $port
                protocol = $proto
                clusterIp = $sp.clusterIp
                service = $sp.service
                modelled = $(if ($allowed) { 'open' } else { 'blocked' })
                egressAllowed = $egress.allowed
                ingressAllowed = $ingress.allowed
                decidedBy = @(@($egress.decidedBy) + @($ingress.decidedBy) | Sort-Object -Unique)
                explanation = ($why -join '; ')
            }
        }
    }
}

Write-Host ("  {0} pair(s) modelled: {1} open, {2} blocked" -f `
        $comparisons.Count,
        @($comparisons | Where-Object { $_.modelled -eq 'open' }).Count,
        @($comparisons | Where-Object { $_.modelled -eq 'blocked' }).Count)

foreach ($c in $comparisons | Where-Object { $_.modelled -eq 'open' }) {
    Write-Host ("    open    {0,-16} -> {1,-16} :{2,-6} {3}" -f $c.source.app, $c.destApp, $c.port, (@($c.decidedBy) -join ',')) -ForegroundColor DarkGreen
}

# Anti-vacuity. A model that modelled nothing would report a clean, empty,
# entirely fictional graph.
if ($comparisons.Count -eq 0) {
    Write-Host ''
    Write-Host '  refusing to emit a graph: no pairs were modelled, so every answer would be vacuous' -ForegroundColor Red
    exit 1
}
if (@($comparisons | Where-Object { $_.modelled -eq 'open' }).Count -eq 0) {
    Write-Host ''
    Write-Host '  refusing to emit a graph: the model permits nothing at all. Either every' -ForegroundColor Red
    Write-Host '  policy is genuinely closed, or the model is wrong. Guessing which is not' -ForegroundColor Red
    Write-Host '  an option, so this is reported rather than written out as a result.' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

# One row per modelled pair, carrying the model's reasoning whether or not a
# probe was run. Seeding the table from the model rather than from the probe
# loop means the report explains itself even when verification is skipped, and
# it means a row can exist without an observation -- which is reported as
# unverified rather than quietly absent.
$results = @()
foreach ($c in $comparisons) {
    $results += [pscustomobject]@{
        source = $c.source.app
        sourceNamespace = $c.source.namespace
        sourceServiceAccount = $c.source.serviceAccount
        dest = $c.destApp
        destNamespace = $c.dest.namespace
        port = $c.port
        protocol = $c.protocol
        target = "$($c.clusterIp):$($c.port)"
        modelled = $c.modelled
        observed = $null
        elapsedMs = $null
        agreed = $false
        verified = $false
        explanation = $c.explanation
        decidedBy = $c.decidedBy
    }
}

$dnsControl = @()
$verificationRan = $false

if ($SkipProbes) {
    Write-Head 'verification skipped'
    Write-Host '  -SkipProbes was given. Every result below is modelled only and unproven.' -ForegroundColor Yellow
}
else {
    Write-Head 'verification: positive control, then modelled versus observed'

    $dnsIp = & kubectl get service $DnsService -n $DnsNamespace -o jsonpath='{.spec.clusterIP}' 2>$null
    if (-not $dnsIp) {
        Write-Host "  service $DnsNamespace/$DnsService not found, so there is no independent control" -ForegroundColor Red
        Write-Host '  and no way to tell a locked-down lab from a broken probe mechanism.' -ForegroundColor Red
        exit 1
    }
    $dnsIp = $dnsIp.Trim()
    Write-Host "  control target: $DnsNamespace/$DnsService at $dnsIp`:$DnsPort"
    Write-Host '  kube-system carries no NetworkPolicy and all three lab namespaces permit DNS'
    Write-Host '  egress, so this is open independently of the model. If it fails, the probe'
    Write-Host '  mechanism is broken and every result below would be meaningless.'
    Write-Host ''
    Write-Host '  each identity is probed alone: one probe pod alive at a time, its own control'
    Write-Host '  checked before its results are believed, then deleted before the next is made.'

    foreach ($src in $pods) {
        $probeName = "probe-graph-$($src.app)"

        # Delete any probe left by an interrupted run, and wait for it to be
        # gone. Deleting asynchronously and immediately re-applying races with
        # the deletion: kubectl reports "Detected changes to resource ... which
        # is currently being deleted", that warning arrives on stderr, and
        # under the script-wide Stop preference it kills the run. The failure
        # looks like a policy problem and is a teardown ordering problem.
        $ErrorActionPreference = 'Continue'
        & kubectl delete pod $probeName -n $src.namespace --ignore-not-found --wait=true 2>&1 | Out-Null
        for ($w = 0; $w -lt 30; $w++) {
            $still = (& kubectl get pod $probeName -n $src.namespace -o jsonpath='{.metadata.name}' 2>$null | Out-String).Trim()
            if (-not $still) { break }
            Start-Sleep -Seconds 1
        }

        # The securityContext is required, not decorative: zerotrust-observe
        # enforces the restricted Pod Security Standard and rejects a probe
        # without these fields outright. Backticks are forbidden inside this
        # double-quoted here-string because a here-string treats them as escape
        # characters, which corrupts any value written markdown-style.
        # The app label must be the workload's own, not "probe".
        #
        # NetworkPolicy selects pods by LABEL, not by service account. A probe
        # carrying sa-orders-api but labelled app=probe is not orders-api to the
        # firewall: orders-api-egress does not select it, so only default-deny-all
        # does, and every egress is refused.
        #
        # That failure is easy to misread. Measured on the first run: all five
        # DNS controls passed, because allow-dns-egress selects every pod in the
        # namespace regardless of label, and all five app-specific edges came
        # back blocked, including the two the boundary harness independently
        # asserts are open. A working probe to one address and a refused
        # connection to every other is what a mislabelled probe looks like, and
        # without the DNS control it would have been reported as a finding about
        # the network.
        #
        # The probe differs from the real workload in its container and nothing
        # else that the datapath can see. That is what makes it a valid stand-in
        # for a network question, and it is why the answer is about the pod's
        # labels and identity rather than about the image.
        $manifest = @"
apiVersion: v1
kind: Pod
metadata:
  name: $probeName
  namespace: $($src.namespace)
  labels:
    app: $($src.app)
  annotations:
    zerotrust.lab/purpose: reachability-graph-probe
spec:
  serviceAccountName: $($src.serviceAccount)
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $PROBE_IMAGE
      command: ["sleep", "3600"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {cpu: 50m, memory: 32Mi}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
"@

        $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('probe-' + [System.IO.Path]::GetRandomFileName() + '.yaml')
        [System.IO.File]::WriteAllText($temp, $manifest, (New-Object System.Text.UTF8Encoding($false)))
        $applyCode = 0
        $applyOut = ''
        # Relaxed for the same reason as the probe: kubectl writes warnings to
        # stderr on paths that are not failures, and the exit code is what
        # actually decides whether the probe was accepted.
        $ErrorActionPreference = 'Continue'
        try {
            $applyOut = (& kubectl apply -f $temp 2>&1 | Out-String)
            $applyCode = $LASTEXITCODE
        }
        finally {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
        if ($applyCode -ne 0) {
            Write-Host ("  probe for {0} was rejected: {1}" -f $src.app, ($applyOut | Out-String).Trim()) -ForegroundColor Red
            Write-Host '  a rejected probe means no answer for this identity, not a blocked one.' -ForegroundColor Red
            exit 1
        }

        $phase = ''
        for ($i = 0; $i -lt 40; $i++) {
            $phase = (& kubectl get pod $probeName -n $src.namespace -o jsonpath='{.status.phase}' 2>$null | Out-String).Trim()
            if ($phase -eq 'Running') { break }
            if ($phase -eq 'Failed') { break }
            Start-Sleep -Seconds 2
        }
        if ($phase -ne 'Running') {
            $reason = (& kubectl get pod $probeName -n $src.namespace -o jsonpath='{.status.containerStatuses[*].state.waiting.reason}' 2>$null | Out-String).Trim()
            Write-Host ("  probe for {0} never reached Running (phase={1} reason={2})" -f $src.app, $phase, $reason) -ForegroundColor Red
            exit 1
        }

        $dnsResult = Invoke-TcpProbe -Namespace $src.namespace -Pod $probeName -Ip $dnsIp -Port $DnsPort
        $dnsUp = ($dnsResult.verdict -eq 'open')
        $dnsControl += [pscustomobject]@{
            app = $src.app
            namespace = $src.namespace
            dnsReachable = $dnsUp
            dnsVerdict = $dnsResult.verdict
            dnsElapsedMs = $dnsResult.elapsedMs
        }
        Write-Host ("  {0,-16} -> {1}:{2}  {3} ({4}ms, {5})" -f $src.app, $dnsIp, $DnsPort, `
                $(if ($dnsUp) { 'reachable' } else { 'UNREACHABLE' }), $dnsResult.elapsedMs, $dnsResult.verdict) -ForegroundColor $(if ($dnsUp) { 'DarkGreen' } else { 'Red' })

        # The control is judged per probe, not once for the run. A probe that
        # cannot open any connection at all cannot produce a meaningful
        # "blocked", so its own results are discarded rather than believed.
        if (-not $dnsUp) {
            Write-Host ''
            Write-Host ("  the probe for {0} could not reach DNS. That is not a finding" -f $src.app) -ForegroundColor Red
            Write-Host '  about the lab: it means this probe cannot open connections, and' -ForegroundColor Red
            Write-Host '  reporting its refusals as policy decisions would invent a result.' -ForegroundColor Red
            & kubectl delete pod $probeName -n $src.namespace --ignore-not-found --wait=true 2>&1 | Out-Null
            exit 1
        }

        $mine = @($comparisons | Where-Object { $_.source.app -eq $src.app })
        if ($mine.Count -gt 0) {
            Write-Host ("  from {0} ({1})" -f $src.app, $src.namespace) -ForegroundColor Cyan
            foreach ($c in $mine) {
                $probeResult = Invoke-TcpProbe -Namespace $src.namespace -Pod $probeName -Ip $c.clusterIp -Port $c.port
                $observed = $probeResult.verdict
                $verificationRan = $true

                # Three outcomes, not two; see Test-ObservationAgrees.
                $ok = Test-ObservationAgrees -Modelled $c.modelled -Observed $observed
                $tag = if ($ok) { 'ok  ' } else { 'MISMATCH' }
                $color = if ($ok) { 'DarkGray' } else { 'Red' }

                $row = @($results | Where-Object {
                        $_.source -eq $src.app -and $_.dest -eq $c.destApp -and $_.port -eq $c.port
                    })[0]
                if ($null -ne $row) {
                    $row.observed = $observed
                    $row.elapsedMs = $probeResult.elapsedMs
                    $row.agreed = $ok
                    $row.verified = $true
                }

                Write-Host ("    [{0}] {1,-16} -> {2,-16} :{3,-6} modelled={4,-8} observed={5,-18} {6}ms" -f `
                        $tag, $src.app, $c.destApp, $c.port, $c.modelled, $observed, $probeResult.elapsedMs) -ForegroundColor $color
            }
        }

        # Tear this probe down before creating the next one.
        #
        # This is not tidiness. A probe carries the workload's real app label so
        # the firewall treats it as that workload, and every lab Service selects
        # on exactly that label -- so a live probe is an ENDPOINT of its own
        # Service. Leave probes running and the orders-api probe joins the
        # orders-api endpoint list, and a later test of web-frontend ->
        # orders-api:8080 may then be answered by an alpine container with no
        # server on 8080. The result flips to "blocked" for a reason that has
        # nothing to do with the policy under test.
        #
        # One probe at a time removes the hazard: the only Service a live probe
        # pollutes is its own, and a probe is never the destination of another
        # probe's test.
        if (-not $KeepProbes) {
            & kubectl delete pod $probeName -n $src.namespace --ignore-not-found --wait=true 2>&1 | Out-Null
        }
        else {
            Write-Host ("    probe {0} left running because -KeepProbes was given" -f $probeName) -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host '  every identity passed its own control, and each probe was measured only' -ForegroundColor DarkGray
    Write-Host '  while that control was green. A blocked result is therefore a property' -ForegroundColor DarkGray
    Write-Host '  of the network and not of the harness.' -ForegroundColor DarkGray
}

# Anti-vacuity on the verification itself. A verification that ran no
# comparisons and reported agreement has verified nothing, and "0 mismatches"
# is exactly what a harness prints when its loop never executes.
# Only rows that were actually probed can disagree. A row with no observation
# is unverified, which is a different state from a disagreement, and counting it
# as a mismatch would make -SkipProbes report 25 failures for a model that has
# not been tested at all.
$mismatch = @($results | Where-Object { $_.verified -and -not $_.agreed })
$agreed = @($results | Where-Object { $_.agreed })
$unverified = @($results | Where-Object { -not $_.verified })

Write-Host ''
Write-Host ("  {0} comparison(s): {1} agree, {2} mismatch" -f $results.Count, $agreed.Count, $mismatch.Count)

$verificationTrustworthy = $true
if ((-not $SkipProbes) -and $results.Count -eq 0) {
    Write-Host '  no comparisons ran, so this verification proves nothing and is reported as such' -ForegroundColor Red
    $verificationTrustworthy = $false
}
if ((-not $SkipProbes) -and -not $verificationRan) {
    Write-Host '  no probe was executed, so no observation exists to compare against' -ForegroundColor Red
    $verificationTrustworthy = $false
}

# Anti-vacuity on the classifier. Invoke-TcpProbe separates a dropped SYN from a
# refused one purely on elapsed time, and a classifier that never returns
# 'dropped' has not been shown to make that distinction at all -- it may simply
# be calling everything refused, which would turn every closed port into
# "permitted, nothing listening" and quietly empty the blocked set.
#
# This is checkable because the model expects blocked pairs. If it does, and no
# probe anywhere produced a drop, then either the classifier is not
# discriminating or the datapath is not enforcing, and neither can be signed off
# by reporting agreement.
if ((-not $SkipProbes) -and $verificationRan) {
    $expectBlocked = @($results | Where-Object { $_.modelled -eq 'blocked' }).Count
    $sawDrop = @($results | Where-Object { $_.observed -eq 'dropped' }).Count
    if ($expectBlocked -gt 0 -and $sawDrop -eq 0) {
        Write-Host ("  the model expects {0} blocked pair(s) but no probe was ever dropped," -f $expectBlocked) -ForegroundColor Red
        Write-Host '  so the drop-versus-refuse classifier has not been shown to work and none' -ForegroundColor Red
        Write-Host '  of its blocked verdicts can be trusted. Not signing this off.' -ForegroundColor Red
        $verificationTrustworthy = $false
    }
    else {
        Write-Host ("  classifier saw {0} dropped and {1} answered attempt(s), so it did discriminate" -f `
                $sawDrop, @($results | Where-Object { $_.observed -ne 'dropped' }).Count) -ForegroundColor DarkGray
    }
}

foreach ($m in $mismatch) {
    Write-Host ("    MISMATCH {0} -> {1}:{2}  modelled={3} observed={4}" -f $m.source, $m.dest, $m.port, $m.modelled, $m.observed) -ForegroundColor Red
    Write-Host ("      model said: {0}" -f $m.explanation) -ForegroundColor DarkGray
    Write-Host '      This is either a modelling error or a policy that does not do what it says.' -ForegroundColor DarkGray
    Write-Host '      Both are findings, and neither is resolved by assuming the model is right.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# graph output
# ---------------------------------------------------------------------------

Write-Head 'graph'

$nodesOut = @()
foreach ($p in $pods) {
    $ports = @()
    if ($servicePorts.ContainsKey($p.app)) {
        $ports = @($servicePorts[$p.app] | ForEach-Object { "$($_.protocol)/$($_.port)" })
    }
    $nodesOut += [pscustomobject]@{
        id = $p.app
        pod = $p.name
        namespace = $p.namespace
        zone = $p.zone
        serviceAccount = $p.serviceAccount
        podIp = $p.podIp
        exposedPorts = $ports
    }
}

$edgesOut = @()

# Edges come from pairs that are BOTH agreed AND modelled open.
#
# `agreed` on its own is not enough, and getting this wrong is the sort of thing
# that survives review because every individual number in the file is correct.
# A pair the model called blocked and the datapath dropped is an AGREEMENT --
# the model was right -- so it lands in $agreed alongside the genuinely open
# pairs. Selecting on $agreed alone therefore emitted all 25 pairs as
# `kind: reachable`, including the 19 the firewall had just refused, and the
# graph claimed twenty-five paths across a cluster that has six.
#
# Nothing in the run failed. The tally said 25/25 agree, 0 mismatches, exit 0,
# and the wrong answer was printed as `edges: 25`. Only reading the output
# caught it, which is the argument for reading it.
$openEdges = @($agreed | Where-Object { $_.modelled -eq 'open' })

$modelledOpen = @($results | Where-Object { $_.modelled -eq 'open' })

foreach ($r in $openEdges) {
    # An agreed edge is still described by how it agreed. "permitted-refused"
    # means the policy allows the flow and nothing is listening on the far end,
    # which is a different fact from "a server answered", and a graph that
    # flattened the two would send a reader looking for a service that does not
    # exist. The one edge in this lab like it is the sensor reaching itself: the
    # policy admits its whole zone, and the sensor runs a probe loop rather than
    # a server, so the connection is permitted and then refused by the kernel.
    $noListener = ($r.observed -eq 'permitted-refused')
    $evidence = if ($noListener) {
        'modelled from live NetworkPolicy and confirmed permitted by the datapath: the SYN was not dropped, and the far end refused it because nothing is listening on that port. The path is real; the server is not deployed'
    }
    else {
        'modelled from live NetworkPolicy and confirmed by an observed TCP connection'
    }

    $edgesOut += [pscustomobject]@{
        from = $r.source
        to = $r.dest
        port = $r.port
        protocol = $r.protocol
        kind = 'reachable'
        noListener = $noListener
        observed = $r.observed
        elapsedMs = $r.elapsedMs
        evidence = $evidence
        decidedBy = $r.decidedBy
    }
}
foreach ($r in $mismatch) {
    $edgesOut += [pscustomobject]@{
        from = $r.source
        to = $r.dest
        port = $r.port
        protocol = $r.protocol
        kind = $(if ($r.modelled -eq 'open') { 'disputed-open' } else { 'disputed-blocked' })
        observed = $r.observed
        elapsedMs = $r.elapsedMs
        evidence = "model and datapath disagree: modelled=$($r.modelled) observed=$($r.observed). Not treated as an edge until this is explained"
        decidedBy = $r.decidedBy
    }
}

# ---------------------------------------------------------------------------
# integrity check on the emitted edge list
# ---------------------------------------------------------------------------
# The bug this guards against was found by reading the output, not by any test
# failing: the run reported 25/25 agree, 0 mismatches and exit 0, while the
# graph listed all 25 pairs as reachable edges. Nothing about the run was
# internally inconsistent, which is exactly why nothing caught it.
#
# The invariant is therefore stated and enforced rather than left to be noticed:
# every reachable edge corresponds to a modelled-open pair, and every
# modelled-open pair has exactly one. Run against $edgesOut, the thing that
# actually ships, rather than against the intermediate set -- the first version
# of this check ran too early, against rows that carry `source` and `dest`, and
# reached for `from` and `to` before anything had created them.
#
# That version also exposed something worth recording: PowerShell raised a
# strict-mode error for the missing property, printed it, and carried on to a
# clean exit 0 with the graph written. $ErrorActionPreference = 'Stop' did not
# stop it, because the access was inside a Where-Object scriptblock. So a
# property error here is a warning, not a wall, and no check in this file may
# rely on one halting the run. Each check has to set its own flag and report.
$edgeIntegrityOk = $true
$emittedEdges = @($edgesOut | Where-Object { $_.kind -eq 'reachable' })

if (-not $SkipProbes) {
    if ($emittedEdges.Count -ne $modelledOpen.Count) {
        Write-Host ''
        Write-Host ("  INTEGRITY  {0} edge(s) emitted for {1} modelled-open pair(s)." -f $emittedEdges.Count, $modelledOpen.Count) -ForegroundColor Red
        Write-Host '  The edge list and the model disagree, so the graph cannot be read.' -ForegroundColor Red
        $edgeIntegrityOk = $false
    }

    foreach ($e in $emittedEdges) {
        $row = @($results | Where-Object { $_.source -eq $e.from -and $_.dest -eq $e.to -and $_.port -eq $e.port })[0]
        if ($null -eq $row) {
            Write-Host ("  INTEGRITY  edge {0} -> {1}:{2} has no matching modelled pair." -f $e.from, $e.to, $e.port) -ForegroundColor Red
            $edgeIntegrityOk = $false
        }
        elseif ($row.modelled -ne 'open') {
            Write-Host ("  INTEGRITY  edge {0} -> {1}:{2} is modelled {3}, not open." -f $e.from, $e.to, $e.port, $row.modelled) -ForegroundColor Red
            $edgeIntegrityOk = $false
        }
    }

    foreach ($row in $modelledOpen) {
        $e = @($emittedEdges | Where-Object { $_.from -eq $row.source -and $_.to -eq $row.dest -and $_.port -eq $row.port })
        if ($e.Count -ne 1) {
            Write-Host ("  INTEGRITY  {0} edge(s) for modelled-open pair {1} -> {2}:{3}, expected 1." -f $e.Count, $row.source, $row.dest, $row.port) -ForegroundColor Red
            $edgeIntegrityOk = $false
        }
    }
}

if ($SkipProbes) {
    Write-Host ''
    Write-Host '  edge list not checked: with -SkipProbes nothing was observed, so there is' -ForegroundColor DarkGray
    Write-Host '  nothing for an edge to be consistent with. The model below is unverified.' -ForegroundColor DarkGray
}
elseif ($edgeIntegrityOk) {
    Write-Host ''
    Write-Host ("  edge list is consistent: {0} modelled-open pair(s), {1} edge(s), none invented, none missing" -f `
            $modelledOpen.Count, $emittedEdges.Count) -ForegroundColor DarkGray
}
else {
    $verificationTrustworthy = $false
}

# The classifier's own behaviour, described from THIS run's measurements rather
# than from a sentence someone typed once. The previous version hardcoded
# "nothing that answered exceeded 210ms" and went stale the moment a busier run
# answered a DNS control in 600ms -- a description of the method that no longer
# described the method is worse than none, because it still looks authoritative.
$answeredRows = @($results | Where-Object { $_.observed -eq 'open' -or $_.observed -eq 'permitted-refused' })
$droppedRows = @($results | Where-Object { $_.observed -eq 'dropped' })
$maxAnswered = 0
foreach ($a in $answeredRows) { if ($a.elapsedMs -gt $maxAnswered) { $maxAnswered = $a.elapsedMs } }
$minDropped = 0
foreach ($d in $droppedRows) { if ($minDropped -eq 0 -or $d.elapsedMs -lt $minDropped) { $minDropped = $d.elapsedMs } }

$classifierText = 'not run'
if ($answeredRows.Count -gt 0 -and $droppedRows.Count -gt 0) {
    $classifierText = ('busybox nc reports nothing on failure, so a dropped SYN is told from a refused one by elapsed time measured inside the pod from /proc/uptime. This run: the slowest attempt that drew an answer was {0}ms, the fastest silent drop was {1}ms, and the cut is at {2}ms. The exit code is tested first, so a slow success can never be recorded as a drop.' -f `
            $maxAnswered, $minDropped, $script:DropThresholdMs)
}

$graph = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    verified = ($verificationTrustworthy -and $mismatch.Count -eq 0)
    verification = [ordered]@{
        ran = (-not $SkipProbes)
        trustworthy = $verificationTrustworthy
        comparisons = $results.Count
        agreed = $agreed.Count
        mismatched = $mismatch.Count
        edges = $openEdges.Count
        edgeListConsistent = $(if ($SkipProbes) { 'not checked, nothing was observed' } else { $edgeIntegrityOk })
        method = 'one ephemeral probe pod per source identity at a time, carrying that identity''s service account and the workload''s own app label, dialling the destination Service ClusterIP so the DNAT path is exercised rather than bypassed'
        positiveControl = $(if ($SkipProbes) { 'not run' } else { 'each probe pod was required to reach kube-dns on TCP 53, which no lab policy governs, and its results were discarded if that failed' })
        dropClassifier = $classifierText
    }
    note = @'
Who can reach what, derived from the live NetworkPolicies and confirmed against the
datapath. Edges are connections that were both modelled open and observed permitted.
"Observed permitted" is broader than "connected on purpose": an edge marked
noListener=true is a real policy-permitted path where nothing is listening, which is
true of the sensor reaching its own Service, and is recorded as such rather than
folded in with the edges that answered.

Two axes are not in this graph and both matter. RBAC is absent: sa-build-runner
holds cluster-admin, which is the most consequential permission in the lab and is
invisible here because cluster-admin is not a network flow. And the API server is
absent as a node, because kube-router DNATs its ClusterIP before the policy chain
is consulted, so no pod can reach it and no in-cluster client can be observed
reaching it.
'@
    nodes = @($nodesOut)
    edges = @($edgesOut)
    blockedPairs = @($results | Where-Object { $_.observed -eq 'dropped' } | ForEach-Object {
            [pscustomobject]@{
                from = $_.source
                to = $_.dest
                port = $_.port
                why = $_.explanation
                evidence = "the SYN was dropped after $(@($_.elapsedMs)[0])ms with no answer, which no listening service can produce"
            }
        })
}

$dir = Split-Path -Parent $GraphPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$json = ($graph | ConvertTo-Json -Depth 8) -replace '[^\x00-\x7F]', ''
[System.IO.File]::WriteAllText($GraphPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  graph written to {0}" -f $GraphPath)

$report = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    comparisons = $results.Count
    agreed = $agreed.Count
    mismatched = $mismatch.Count
    trustworthy = $verificationTrustworthy
    dnsControl = $dnsControl
    detail = $results
}
$json2 = ($report | ConvertTo-Json -Depth 8) -replace '[^\x00-\x7F]', ''
[System.IO.File]::WriteAllText($ReportPath, $json2, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  report written to {0}" -f $ReportPath)

# Permitted paths with nothing behind them are reported on their own, because
# they are the edges a reader is most likely to misread. A diagram showing a
# sensor pointing at itself invites the conclusion that the sensor exposes a
# service; it does not, and the reason is worth stating rather than leaving to
# be discovered.
$noListenerEdges = @($edgesOut | Where-Object { $_.noListener })
if ($noListenerEdges.Count -gt 0) {
    Write-Host ''
    Write-Host ("  {0} permitted edge(s) have no server behind them:" -f $noListenerEdges.Count) -ForegroundColor Yellow
    foreach ($e in $noListenerEdges) {
        Write-Host ("    {0} -> {1}:{2}   refused in {3}ms rather than answered" -f $e.from, $e.to, $e.port, $e.elapsedMs) -ForegroundColor Yellow
    }
}

Write-Host ''
if ($mismatch.Count -gt 0) {
    Write-Host ("  FAIL  {0} of {1} modelled pair(s) disagree with the datapath" -f $mismatch.Count, $results.Count) -ForegroundColor Red
    exit 1
}
if (-not $verificationTrustworthy) {
    Write-Host '  FAIL  the verification did not run to completion, so the graph is unproven' -ForegroundColor Red
    exit 1
}
if ($SkipProbes) {
    Write-Host ("  PASS  {0} pair(s) modelled, unverified because -SkipProbes was given" -f $comparisons.Count) -ForegroundColor Yellow
    exit 0
}

Write-Host ("  PASS  {0} pair(s) modelled, {1} confirmed against the datapath, 0 mismatches" -f $comparisons.Count, $agreed.Count) -ForegroundColor Green
Write-Host ("        {0} permitted path(s), {1} blocked, {2} disputed" -f $openEdges.Count, @($results | Where-Object { $_.observed -eq 'dropped' }).Count, $mismatch.Count) -ForegroundColor Green
exit 0
