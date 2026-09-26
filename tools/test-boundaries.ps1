<#
.SYNOPSIS
    Verifies the lab's trust boundaries against a running cluster.

.DESCRIPTION
    Two things are checked, and neither can be verified by reading YAML:

      1. Network enforcement. For every (source identity, target, port) pair
         the harness expects either "open" or "blocked", opens a real TCP
         connection, and compares. A NetworkPolicy that was accepted by the API
         server but never programmed into a packet path -- which is exactly what
         happens under kindnet -- passes every static check and fails this one.

      2. Authorization. `kubectl auth can-i` is run for each identity against
         permissions that must be denied, permissions that must be allowed, and
         the planted privilege path PP-01, which must be allowed. A detection
         for an over-privileged service account is only meaningful if the
         over-privilege is real, so PP-01's presence is itself a test.

    How a source identity is emulated: NetworkPolicy selects on pod labels, not
    on service accounts. So each probe is a pod carrying the label set of the
    workload it stands in for, running in that workload's namespace. It is not
    a simulation of the workload; it is the workload as far as the network is
    concerned, which is the only thing being tested here.

.PARAMETER Namespace
    Limit the network tests to one namespace. RBAC checks always run.

.PARAMETER KeepProbes
    Leave probe pods running for inspection. Useful when something fails and
    you want to exec into the failing probe yourself.

.PARAMETER OutputPath
    Where to write the JSON result. Defaults to .telemetry\boundary-tests.json.
    That path is gitignored; results are derived data.

.EXAMPLE
    .\tools\test-boundaries.ps1
    .\tools\test-boundaries.ps1 -Namespace zerotrust
    .\tools\test-boundaries.ps1 -KeepProbes
#>
[CmdletBinding()]
param(
    [string] $Namespace,
    [switch] $KeepProbes,
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot   = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot '.telemetry\boundary-tests.json'
}

# Pinned to the same digest the workloads use, so a probe pod and the workload
# it emulates cannot differ by image.
$alpineImage = 'alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc'

# ---------------------------------------------------------------------------
# The expected matrix.
#
# This table is the specification. It is written out longhand rather than
# computed from the manifests, because the whole point is to catch the case
# where a policy and its documentation disagree. Deriving expectations from the
# policy files would make the test agree with whatever the policy says, and a
# test that cannot fail is not a test.
#
# It has already earned its keep. Two rows in the first draft asserted that
# web-frontend and orders-api could both connect to web-frontend:80, because
# web-frontend-ingress admitted them. Both failed. Ingress and egress are
# independent axes, and neither workload had an egress rule to the frontend, so
# those ingress allowances matched no packet at all. The policies were right and
# the assertions were wrong, so the assertions changed and the dead rules were
# deleted rather than made live. See identities/33-networkpolicy-workloads.yaml.
# ---------------------------------------------------------------------------
$PROBE_IMAGE = $alpineImage

$identities = @(
    @{ name = 'web-frontend'; namespace = 'zerotrust'; sa = 'sa-web-frontend' }
    @{ name = 'orders-api';   namespace = 'zerotrust'; sa = 'sa-orders-api' }
    @{ name = 'postgres';     namespace = 'zerotrust'; sa = 'sa-postgres' }
    @{ name = 'build-runner'; namespace = 'zerotrust-build'; sa = 'sa-build-runner' }
    @{ name = 'telemetry-agent'; namespace = 'zerotrust-observe'; sa = 'sa-telemetry-agent' }
)

# target|port|expected
$matrix = @{
    'web-frontend' = @(
        @{ target = 'orders-api';   port = 8080; expected = 'open';    why = '33: web-frontend-egress' }
        @{ target = 'postgres';     port = 5432; expected = 'blocked'; why = '33: web-frontend-egress has no rule to the DB' }
        @{ target = 'web-frontend'; port = 80;   expected = 'blocked'; why = '33: no egress rule to itself; single replica, no sidecar' }
        @{ target = 'build-runner'; port = 8080; expected = 'blocked'; why = '31/32: build zone is DNS-only' }
    )
    'orders-api' = @(
        @{ target = 'postgres';     port = 5432; expected = 'open';    why = '33: orders-api-egress' }
        @{ target = 'web-frontend'; port = 80;   expected = 'blocked'; why = '33: orders-api-egress has no rule to the frontend' }
        @{ target = 'build-runner'; port = 8080; expected = 'blocked'; why = '31/32: build zone is DNS-only' }
    )
    'postgres' = @(
        @{ target = 'orders-api';   port = 8080; expected = 'blocked'; why = '33: postgres-ingress admits only orders-api' }
        @{ target = 'web-frontend'; port = 80;   expected = 'blocked'; why = 'default-deny egress' }
        @{ target = 'build-runner'; port = 8080; expected = 'blocked'; why = '31/32: build zone is DNS-only' }
    )
    'build-runner' = @(
        @{ target = 'orders-api';   port = 8080; expected = 'blocked'; why = '34: no egress beyond DNS' }
        @{ target = 'postgres';     port = 5432; expected = 'blocked'; why = '34: no egress beyond DNS' }
        @{ target = 'web-frontend'; port = 80;   expected = 'blocked'; why = '34: no egress beyond DNS' }
    )
    'telemetry-agent' = @(
        @{ target = 'web-frontend'; port = 80;   expected = 'open';    why = 'PP-02' }
        @{ target = 'orders-api';   port = 8080; expected = 'open';    why = 'PP-02' }
        @{ target = 'postgres';     port = 5432; expected = 'open';    why = 'PP-02' }
        @{ target = 'build-runner'; port = 8080; expected = 'blocked'; why = '34: build zone refuses everything' }
    )
}

# identity|verb|resource|namespace|expected|why
$rbacCases = @(
    # Least privilege: every one of these must be denied.
    @{ who = 'zerotrust:sa-orders-api';      verb = 'list';   resource = 'secrets';      ns = 'zerotrust';  expect = 'no';  why = 'least privilege: enumerate all secrets' }
    @{ who = 'zerotrust:sa-orders-api';      verb = 'get';    resource = 'pods';         ns = 'zerotrust';  expect = 'no';  why = 'least privilege: no API reads' }
    @{ who = 'zerotrust:sa-orders-api';      verb = 'create'; resource = 'pods';         ns = 'zerotrust';  expect = 'no';  why = 'least privilege: no writes' }
    @{ who = 'zerotrust:sa-orders-api';      verb = 'get';    resource = 'configmaps';   ns = 'zerotrust';  expect = 'no';  why = 'resourceNames must scope this to one configmap' }
    @{ who = 'zerotrust:sa-web-frontend';   verb = 'get';    resource = 'secrets';      ns = 'zerotrust';  expect = 'no';  why = 'WP-01 is about pod security, not about API rights' }
    @{ who = 'zerotrust:sa-web-frontend';   verb = 'create'; resource = 'pods';         ns = 'zerotrust';  expect = 'no';  why = 'least privilege' }
    @{ who = 'zerotrust:sa-postgres';        verb = 'list';   resource = 'secrets';      ns = 'zerotrust';  expect = 'no';  why = 'a database has no business calling the API' }
    @{ who = 'zerotrust-observe:sa-telemetry-agent'; verb = 'get';    resource = 'secrets'; ns = 'zerotrust'; expect = 'no'; why = 'sensor holds no API permissions by design' }
    @{ who = 'zerotrust-observe:sa-telemetry-agent'; verb = 'list';   resource = 'pods';    ns = 'zerotrust'; expect = 'no'; why = 'sensor holds no API permissions by design' }
    @{ who = 'zerotrust-observe:sa-telemetry-agent'; verb = 'create'; resource = 'pods';    ns = 'zerotrust'; expect = 'no'; why = 'sensor holds no API permissions by design' }

    # The narrow grants, which must work.
    @{ who = 'zerotrust:sa-orders-api'; verb = 'get'; resource = 'configmaps/orders-api-config'; ns = 'zerotrust'; expect = 'yes'; why = 'the one intended grant' }
    @{ who = 'zerotrust:sa-orders-api'; verb = 'get'; resource = 'secrets/postgres-credentials';  ns = 'zerotrust'; expect = 'yes'; why = 'the one intended credential read' }

    # PP-01. These must be ALLOWED. If they are denied the lab's headline
    # weakness is gone and every detection written against it is untestable.
    @{ who = 'zerotrust-build:sa-build-runner'; verb = 'list';   resource = 'secrets';      ns = 'zerotrust'; expect = 'yes'; why = 'PP-01: cluster-admin reads every secret' }
    @{ who = 'zerotrust-build:sa-build-runner'; verb = 'create'; resource = 'pods';         ns = 'zerotrust'; expect = 'yes'; why = 'PP-01: cluster-admin creates pods anywhere' }
    @{ who = 'zerotrust-build:sa-build-runner'; verb = 'delete'; resource = 'pods';         ns = 'zerotrust'; expect = 'yes'; why = 'PP-01: cluster-admin deletes pods' }
    # Cluster-scoped: ns is empty on purpose. Passing -n for a cluster-scoped
    # resource makes kubectl emit a warning line before the answer, and a naive
    # reader takes the warning for the answer.
    @{ who = 'zerotrust-build:sa-build-runner'; verb = 'create'; resource = 'clusterroles'; ns = '';         expect = 'yes'; why = 'PP-01: full control plane' }
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
$script:pass = 0
$script:fail = 0
$results = [System.Collections.Generic.List[object]]::new()

function Write-Head { param([string]$Text)
    Write-Host ''
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}
function Write-Result {
    param([string]$Name, [string]$Expected, [string]$Observed, [string]$Detail)
    $ok = ($Expected -eq $Observed)
    if ($ok) { $script:pass++; $tag = 'PASS' } else { $script:fail++; $tag = 'FAIL' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    $suffix = if ($Detail) { "  ($Detail)" } else { '' }
    Write-Host ("  [{0}] {1,-58} expected={2,-8} observed={3}{4}" -f $tag, $Name, $Expected, $Observed, $suffix) -ForegroundColor $color
    $results.Add([pscustomobject]@{
        name     = $Name
        expected = $Expected
        observed = $Observed
        detail   = $Detail
        passed   = $ok
    })
}

# Resolves a Service name to its ClusterIP, because that is the address a
# client in another namespace actually dials. Testing pod IPs would bypass the
# service proxy and miss the DNAT path entirely.
function Get-ServiceIp {
    param([string]$Name, [string]$Ns)
    $ip = & kubectl get service $Name -n $Ns -o jsonpath='{.spec.clusterIP}' 2>$null
    if (-not $ip) { throw "service $Ns/$Name not found" }
    $ip.Trim()
}

function Test-TcpFromProbe {
    param([string]$Pod, [string]$Ns, [string]$Ip, [int]$Port)
    & kubectl exec -n $Ns $Pod -- nc -w 3 $Ip $Port 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { 'open' } else { 'blocked' }
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
    Write-Host '  enforced, so every network test below would report false results.' -ForegroundColor Red
    exit 1
}
Write-Host "  kube-router ready on all $nodes nodes (NetworkPolicy is enforced)"

# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------
Write-Head 'authorization (kubectl auth can-i)'
foreach ($case in $rbacCases) {
    $as = "system:serviceaccount:$($case.who)"
    if ($case.ns) {
        $out = & kubectl auth can-i $case.verb $case.resource --as=$as -n $case.ns 2>&1
    } else {
        $out = & kubectl auth can-i $case.verb $case.resource --as=$as 2>&1
    }
    # Take the last non-empty line. kubectl puts warnings on stderr and the
    # answer on stdout, and $ErrorActionPreference = 'Continue' interleaves them.
    $answer = ($out | ForEach-Object { $_.ToString() } | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1)
    if (-not $answer) { $answer = 'no output' }
    $observed = if ($answer.Trim() -eq 'yes') { 'yes' } elseif ($answer.Trim() -eq 'no') { 'no' } else { "error: $answer" }
    Write-Result "$($case.who) $($case.verb) $($case.resource)" $case.expect $observed $case.why
}

# ---------------------------------------------------------------------------
# network
# ---------------------------------------------------------------------------
$toProbe = $identities
if ($Namespace) { $toProbe = $identities | Where-Object { $_.namespace -eq $Namespace } }

foreach ($id in $toProbe) {
    Write-Head "network from $($id.name) ($($id.namespace))"

    $probeName = "probe-$($id.name)"
    & kubectl delete pod $probeName -n $id.namespace --ignore-not-found --wait=false 2>&1 | Out-Null

    # The pod-level securityContext below is not decoration: zerotrust-observe
    # enforces the restricted Pod Security Standard, and a probe without these
    # fields is rejected outright. An empty phase in the readiness loop is the
    # only symptom, which is a slow way to learn a namespace has a PSA label.
    #
    # This explanation is a PowerShell comment rather than YAML comments inside
    # the here-string for a reason that cost an hour: a double-quoted here-string
    # treats a backtick as an escape character. Writing `restricted` in markdown
    # style inside one turns `r into a carriage return and `e into an ESC byte,
    # which splits the line and produces
    #     yaml: line 16: could not find expected ':'
    # from a manifest that looks perfectly correct in the source. Single quotes
    # around the whole here-string would avoid it, but then none of the values
    # interpolate. So: no backticks between @" and "@.
    $manifest = @"
apiVersion: v1
kind: Pod
metadata:
  name: $probeName
  namespace: $($id.namespace)
  labels:
    app: $($id.name)
  annotations:
    zerotrust.lab/purpose: boundary-test-probe
spec:
  serviceAccountName: $($id.sa)
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
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("probe-" + [System.IO.Path]::GetRandomFileName() + ".yaml")
    [System.IO.File]::WriteAllText($temp, $manifest, (New-Object System.Text.UTF8Encoding($false)))
    $applyOutput = $null
    $applyCode   = 0
    try {
        $applyOutput = & kubectl apply -f $temp 2>&1
        $applyCode   = $LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    if ($applyCode -ne 0) {
        # Report it and stop. The earlier version piped this to Out-Null, so a
        # rejected probe produced only "not ready: phase=" 80 seconds later, with
        # the actual reason -- a Pod Security denial, a bad field -- discarded.
        # A harness that hides its own setup errors is worse than no harness.
        $reason = ($applyOutput | ForEach-Object { $_.ToString() } | Where-Object { $_.Trim() -ne '' }) -join '; '
        Write-Result "probe $($id.name) applied" 'exit 0' "exit $applyCode : $reason" | Out-Null
        continue
    }

    $ready = $false
    $phase = ''
    for ($i = 0; $i -lt 40; $i++) {
        $phase = (& kubectl get pod $probeName -n $id.namespace -o jsonpath='{.status.phase}' 2>$null | Out-String).Trim()
        if ($phase -eq 'Running') { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) {
        # Surface the reason rather than just "not Running". A probe that is
        # Pending because Pod Security rejected it looks identical to a probe
        # that is Pending because an image could not be pulled, and the two have
        # nothing in common.
        $reason = (& kubectl get pod $probeName -n $id.namespace -o jsonpath='{.status.containerStatuses[*].state.waiting.reason}' 2>$null | Out-String).Trim()
        if (-not $reason) { $reason = "phase=$phase" }
        Write-Result "probe $($id.name) reached Running" 'Running' "not ready: $reason" | Out-Null
        if (-not $KeepProbes) {
            & kubectl delete pod $probeName -n $id.namespace --ignore-not-found --wait=false 2>&1 | Out-Null
        }
        continue
    }
    # Give kube-router a moment to program rules for the new pod's IP.
    Start-Sleep -Seconds 5

    foreach ($case in $matrix[$id.name]) {
        $targetNs = switch ($case.target) {
            'build-runner' { 'zerotrust-build' }
            default        { 'zerotrust' }
        }
        $ip = Get-ServiceIp -Name $case.target -Ns $targetNs
        $observed = Test-TcpFromProbe -Pod $probeName -Ns $id.namespace -Ip $ip -Port $case.port
        Write-Result ("{0} -> {1}:{2}" -f $id.name, $case.target, $case.port) $case.expected $observed $case.why
    }

    if (-not $KeepProbes) {
        & kubectl delete pod $probeName -n $id.namespace --ignore-not-found --wait=false 2>&1 | Out-Null
    }
}

if ($KeepProbes) {
    Write-Host ''
    Write-Host 'probes left running (use -KeepProbes:$false next time to clean up)' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
Write-Head 'summary'
$total = $script:pass + $script:fail
Write-Host "  $script:pass passed, $script:fail failed, $total total" -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
[pscustomobject]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    passed      = $script:pass
    failed      = $script:fail
    total       = $total
    results     = $results
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "  results written to $OutputPath"

exit $(if ($script:fail -eq 0) { 0 } else { 1 })
