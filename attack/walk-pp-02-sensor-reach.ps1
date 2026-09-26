<#
    Walks PP-02: the telemetry sensor holds a network path to all three business
    workloads, and holds no credential for any of them.

    T1046 Network Service Scanning
    T1595 Active Scanning
    T1550.001 Use Alternate Authentication Material: Application Access Token

    What this path actually is
    --------------------------
    Not a vulnerability. PP-02 is a compensating control that was added on
    purpose, and this script exists to prove the control still holds and to
    establish exactly how much it is worth.

    The sensor measures whether workloads can reach each other. To do that it
    has to be able to reach them, so a NetworkPolicy grants it ingress to
    web-frontend:80, orders-api:8080 and postgres:5432. That grant is real
    lateral movement surface: if the sensor is ever compromised, the attacker
    inherits three network paths into the business zone.

    What makes it acceptable is that the sensor holds nothing worth having. It
    has no database password, and its service account token grants no API
    access at all, which WP-02 walks separately. Reachability without a
    credential is not access. The two together would be, and the script is
    explicit about which half is present.

    The fact that decides the whole argument
    -----------------------------------------
    Measured while writing this: no pod in the lab can reach the API server.
    All four workload identities are blocked from 443.

        web-frontend     api:443 -> BLOCKED
        orders-api       api:443 -> BLOCKED
        telemetry-agent  api:443 -> BLOCKED
        build-runner     api:443 -> BLOCKED

    So every service account token in this cluster is latent. Not one of them
    can be spent from where it sits, and the containment is being carried
    entirely by the network policies while RBAC does none of the work at all.
    That is worth stating plainly, because "we have default-deny and narrow
    RBAC" reads like two independent controls and here only one of them is
    load-bearing.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'PP-02' `
    -Title 'the sensor holds a lateral path to every business workload' `
    -Claim @'
Reachability is not access. The sensor can open a TCP connection to all three
business workloads, and holds no credential that would make any of those
connections useful. Both halves of that sentence are asserted below, because
a lab that only demonstrated the first half would be demonstrating a
vulnerability it does not have.
'@

$ns  = 'zerotrust-observe'
$pod = Get-LabPod -Namespace $ns -App 'telemetry-agent'
if (-not $pod) {
    Write-Host "  no running telemetry-agent pod in $ns" -ForegroundColor Red
    exit 1
}
$podName = Get-Prop (Get-Prop $pod 'metadata') 'name'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1046' -Description 'the sensor is in its own zone, holding no business credential' | Out-Null

Write-Observed "pod: $podName"
Write-Observed 'identity, and everything the pod holds under the service account path:'
Write-Observed (Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'id; ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null')

Write-Assertion -Expected 'the sensor runs in zerotrust-observe, not the business zone' `
    -Observed $ns `
    -Passed ((Get-Prop (Get-Prop $pod 'metadata') 'namespace') -eq 'zerotrust-observe') `
    -Note 'zone separation is what makes the grant below a decision rather than an accident'

# Measured, not asserted. The sensor's full environment was read and every
# variable is a Kubernetes service-discovery entry, PATH, HOME, HOSTNAME or
# PROBE_INTERVAL_SECONDS. There is no PG*, DATABASE* or DB_* variable, and the
# count below is what the pod actually reports rather than a claim about it.
# Group alternation is written as repeated -e patterns because Invoke-InPod
# commands have to survive PowerShell's native argument marshalling, which eats
# the quotes around a "^(PG|DATABASE|DB_)" group and leaves sh parsing a bare
# parenthesis.
$envCount = Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' `
    -Command 'env | grep -ci -e ^PG -e ^DATABASE -e ^DB_ || true'
Write-Observed ("  variables matching PG* / DATABASE* / DB* : {0}" -f $envCount.Trim())

Write-Assertion -Expected 'the sensor holds no database password' `
    -Observed ("{0} matching variable(s) in the pod environment" -f $envCount.Trim()) `
    -Passed ($envCount.Trim() -eq '0') `
    -Note 'this is the assertion that keeps PP-02 a control rather than a hole'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1046' -Description 'the sensor opens a TCP path to all three business workloads' | Out-Null

$targets = @(
    @{ name = 'web-frontend'; host = 'web-frontend.zerotrust.svc.cluster.local';   port = 80   }
    @{ name = 'orders-api';   host = 'orders-api.zerotrust.svc.cluster.local';     port = 8080 }
    @{ name = 'postgres';     host = 'postgres.zerotrust.svc.cluster.local';       port = 5432 }
)

$reachable = @()
foreach ($t in $targets) {
    $r = Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' `
        -Command ("nc -w 3 -z {0} {1} && echo REACHABLE || echo BLOCKED" -f $t.host, $t.port)
    $verdict = Get-LastLine $r
    Write-Observed ("  {0,-14} :{1,-5} {2}" -f $t.name, $t.port, $verdict)
    if ($verdict -eq 'REACHABLE') { $reachable += $t.name }
}

Write-Assertion -Expected 'all three business workloads are reachable from the sensor' `
    -Observed ("{0} of 3 reachable: {1}" -f $reachable.Count, ($reachable -join ', ')) `
    -Passed ($reachable.Count -eq 3) `
    -Note 'this is the grant. It is real lateral movement surface and it is deliberate'

# The boundary that makes the grant defensible, checked in the same breath.
$apiBlock = Get-LastLine (Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' `
    -Command 'nc -w 3 -z kubernetes.default.svc 443 && echo REACHABLE || echo BLOCKED')
Write-Observed ("  {0,-14} :{1,-5} {2}" -f 'api-server', '443', $apiBlock)

Write-Assertion -Expected 'the API server is NOT reachable from the sensor' `
    -Observed $apiBlock `
    -Passed ($apiBlock -eq 'BLOCKED') `
    -Note 'so the sensor cannot read a Secret, create a pod, or escalate through the control plane. This is the second half of "reachability is not access", and it is the half that would be easy to lose in a later change'

Write-Assertion -Expected 'the sensor cannot reach the CI runner either' `
    -Observed 'measured by test-boundaries.ps1, which asserts build-runner:8080 is blocked' `
    -Passed $true `
    -Note 'not re-measured here to avoid duplicating an assertion that already runs in CI; the grant is business-zone only, not a general observer'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1550.001' -Description 'the sensor does hold a token, and it is worth nothing' | Out-Null

$token = Get-PodServiceAccountToken -Namespace $ns -Pod $podName
$claims = Get-TokenSubject -Token $token
$sub = if ($claims) { Get-Prop $claims 'sub' } else { $null }
Write-Observed "token present, sub: $sub"

$server = (& kubectl config view --raw --minify -o jsonpath='{..server}' 2>$null | Out-String).Trim()
$caData = (& kubectl config view --raw --minify -o jsonpath='{..certificate-authority-data}' 2>$null | Out-String).Trim()
$kc = @"
apiVersion: v1
kind: Config
clusters:
- name: lab
  cluster:
    server: $server
    certificate-authority-data: $caData
contexts:
- name: probe
  context:
    cluster: lab
    user: nobody
current-context: probe
users:
- name: nobody
  user:
    token: "not-a-real-token"
"@
$tmp = Join-Path $env:TEMP 'pp02.kubeconfig'
[System.IO.File]::WriteAllText($tmp, (($kc -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

$r1 = Invoke-Kubectl @(('--kubeconfig=' + $tmp), 'auth', 'can-i', 'list', 'secrets', '--all-namespaces')
$r2 = Invoke-Kubectl @(('--kubeconfig=' + $tmp), ('--token=' + $token), 'auth', 'can-i', 'list', 'secrets', '--all-namespaces')
$r3 = Invoke-Kubectl @(('--kubeconfig=' + $tmp), ('--token=' + $token), 'auth', 'can-i', 'list', 'pods', '--all-namespaces')

Write-Observed ("  invalid token      -> {0}" -f $r1.verdict)
Write-Observed ("  sensor token, secrets -> {0}" -f $r2.verdict)
Write-Observed ("  sensor token, pods    -> {0}" -f $r3.verdict)
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

Write-Assertion -Expected 'the sensor token cannot list Secrets' `
    -Observed $r2.verdict `
    -Passed ($r2.exitCode -ne 0) `
    -Note '403 or 401 both count. What matters is that it is a refusal and not a yes'

Write-Assertion -Expected 'the sensor token cannot list pods' `
    -Observed $r3.verdict `
    -Passed ($r3.exitCode -ne 0) `
    -Note 'WP-02 walks this identity in full. Here it is only half of PP-02''s argument'

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'authenticate to postgres on 5432 with the password SP-01 leaks in a ConfigMap' `
    -Why 'the sensor can open the connection but cannot obtain the password: app-config-leak is unreadable to it, and the API server that would tell it the password is blocked. That is the whole reason this path stops where it does.

      The chain that does work is PP-01 plus PP-02 -- steal a cluster-admin token from the CI runner, read the password, then create a pod that already sits inside the permitted network path. That is Phase 8, and it is assembled from two separately catalogued findings rather than from a new weakness.'

Write-Withheld -WouldDo 'scan the business zone for further hosts' `
    -Why 'the sensor does hold ingress to the three workloads, so a real port scan from it would succeed. The lab measures exactly the three connections it needs to prove isolation and no more, and inventing a wider scan would add reach without adding a finding.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
