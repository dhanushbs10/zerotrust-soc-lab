<#
    Walks WP-02: sa-telemetry-agent holds a mounted service account token that
    grants it nothing.

    T1550.001 Use Alternate Authentication Material: Application Access Token

    What this is
    ------------
    The exact inverse of PP-01, and the pair is the reason both are catalogued.

    PP-01: an identity bound to cluster-admin, on a workload that is sealed off
           from the network and hardened in every container-level respect.
    WP-02: a token mounted into a workload, on an identity bound to nothing at
           all.

    Both pods have automountServiceAccountToken: true. The setting is identical
    and the outcome is opposite, and the only thing that differs is the RBAC
    binding. So the finding is not really about this workload at all. It is
    that a mounted token is a credential whose value is decided somewhere else
    entirely, and a reviewer looking at the pod spec alone cannot tell which
    kind they are holding.

    WP-02 is therefore the *control* half of the pair, and it is walked to prove
    the control still holds. If the sensor were ever granted anything, this
    script fails and the drift scanner fails with it.

    A latent token is still a credential
    ------------------------------------
    The honest caveat, and the reason this is a finding rather than a
    non-finding: a token with no grants today is a token that becomes
    credential-bearing the moment a RoleBinding is added, with no change to the
    pod, no restart, and nothing in the pod spec to review. The safe version of
    this posture is automountServiceAccountToken: false, which is the fix
    WP-02 argues for and which the telemetry sensor cannot currently use
    without a redesign, because a reachability sensor that cannot call the API
    server is not a sensor.

    That tension is real and it is the point: the correct long-term answer is
    not a narrower grant, it is not needing the token at all.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'WP-02' `
    -Title 'sa-telemetry-agent holds a token worth only what every identity gets' `
    -Claim @'
A mounted service account token is a credential whose value is decided by RBAC,
not by the pod. PP-01 and WP-02 have identical pod specs in this respect and
opposite outcomes, and the only difference between them is a binding elsewhere
in the cluster. Neither can be judged by reading a manifest.
'@

$ns  = 'zerotrust-observe'
$pod = Get-LabPod -Namespace $ns -App 'telemetry-agent'
if (-not $pod) {
    Write-Host "  no running telemetry-agent pod in $ns" -ForegroundColor Red
    exit 1
}
$podName = Get-Prop (Get-Prop $pod 'metadata') 'name'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1550.001' -Description 'the token really is mounted into the pod' | Out-Null

Write-Observed "pod: $podName"
$automount = Get-Prop $pod.spec 'automountServiceAccountToken'
Write-Observed "pod spec automountServiceAccountToken: $automount"
Write-Observed (Invoke-InPod -Namespace $ns -Pod $podName -Shell 'sh' -Command 'ls -l /var/run/secrets/kubernetes.io/serviceaccount/')

$token = Get-PodServiceAccountToken -Namespace $ns -Pod $podName
$claims = Get-TokenSubject -Token $token
$sub = if ($claims) { Get-Prop $claims 'sub' } else { $null }

Write-Assertion -Expected 'a JWT is present in the pod, readable by the container process' `
    -Observed ("{0} characters, sub={1}" -f $token.Length, $sub) `
    -Passed ($token.Length -gt 100 -and $sub -like 'system:serviceaccount:*') `
    -Note 'the same primitive as PP-01 step 2. The read requires no privilege at all, so the pod spec alone decides whether this is a finding'

Write-Assertion -Expected 'the token names the sensor identity, not a shared one' `
    -Observed $sub `
    -Passed ($sub -eq 'system:serviceaccount:zerotrust-observe:sa-telemetry-agent') `
    -Note 'a dedicated identity is what makes the empty grant set enforceable. A shared identity would drag in whatever anyone else binds to it'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1550.001' -Description 'present it to the API server and find out what it is worth' | Out-Null

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
$tmp = Join-Path $env:TEMP 'wp02.kubeconfig'
[System.IO.File]::WriteAllText($tmp, (($kc -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# What the API server says this identity may do, asked of the API server rather
# than read out of a manifest, because a manifest can be out of step with what
# is actually bound.
#
# The answer is NOT empty, and claiming it was would be the easy mistake. Every
# authenticated identity in every Kubernetes cluster inherits two ClusterRoles
# through the system:authenticated group, and they show up here:
#
#   - selfsubjectreviews / selfsubjectaccessreviews / selfsubjectrulesreviews
#     with [create]. These are system:basic-user, and they let an identity ask
#     the API server whether it can do things. That is a read of its own
#     permissions, not access to anything.
#   - the discovery URLs: /healthz, /livez, /readyz, /version, /api, /apis,
#     /openapi, /openid/v1/jwks. These are system:discovery and
#     system:public-info-viewer, and they are public.
#
# So the honest description is not "grants nothing". It is "grants only what
# every authenticated identity gets, and nothing on any cluster resource". That
# is still the correct posture, and it is worth stating precisely, because a
# finding that overstates itself is one a reviewer learns to discount.
$selfReview = Invoke-Kubectl @(('--kubeconfig=' + $tmp), ('--token=' + $token), 'auth', 'can-i', '--list')
$reviewLines = @($selfReview.raw -split "`n" | Where-Object { $_.Trim() })
$selfReviewOnly = @($reviewLines | Where-Object { $_ -match 'selfsubject' })
# Everything else on this identity is a non-resource URL, and all of them are the
# public discovery surface. The pattern has to include /.well-known/* as well as
# the obvious ones: leaving it out reported two perfectly ordinary discovery
# entries as "anything else" and failed a walk that had found nothing.
$discoveryOnly  = @($reviewLines | Where-Object { $_ -match '\[/(healthz|livez|readyz|version|api|apis|openapi|openid|\.well-known)' })
$otherResourceLines = @($reviewLines | Where-Object {
    $_ -notmatch 'Resources\s+Non-Resource' -and
    $_ -notmatch 'selfsubject' -and
    $_ -notmatch '\[/(healthz|livez|readyz|version|api|apis|openapi|openid|\.well-known)' -and
    $_.Trim()
})

Write-Observed ("SelfSubjectRulesReview: {0} entries." -f $reviewLines.Count)
Write-Observed ("  resource-scoped, self-review only : {0}  (system:basic-user)" -f $selfReviewOnly.Count)
Write-Observed ("  non-resource, public discovery    : {0}" -f $discoveryOnly.Count)
Write-Observed ("  anything else                     : {0}" -f $otherResourceLines.Count)
foreach ($l in $otherResourceLines) { Write-Observed "    UNEXPECTED: $($l.Trim())" }

Write-Assertion -Expected 'the token holds no permission on any cluster resource' `
    -Observed ("{0} self-review creates, {1} public discovery URLs, {2} other entries" -f $selfReviewOnly.Count, $discoveryOnly.Count, $otherResourceLines.Count) `
    -Passed ($otherResourceLines.Count -eq 0) `
    -Note 'the "grants nothing" claim in the catalogue is imprecise: system:basic-user and the discovery roles are inherited by every authenticated identity in the cluster. The posture is still correct. This measures the real grant surface instead of asserting an empty one, because the assertion that would fail is the one that matters'

# Four explicit denials, collected as a list. The earlier version of this block
# read $check after the loop ended, so an assertion labelled "every one of the
# four checks is refused" was in fact testing only the fourth. Verifying one
# thing and reporting four is the worst kind of bug in a walk script, because
# the summary is exactly the thing a reader trusts.
$checks = @(
    @{ label = 'list secrets --all-namespaces'; args = @('list',   'secrets',    '--all-namespaces') }
    @{ label = 'list pods --all-namespaces';    args = @('list',   'pods',       '--all-namespaces') }
    @{ label = 'create pods -n zerotrust';      args = @('create', 'pods',       '-n', 'zerotrust') }
    @{ label = 'get configmaps -n zerotrust';   args = @('get',    'configmaps', '-n', 'zerotrust') }
)
$verdicts = @()
foreach ($c in $checks) {
    $r = Invoke-Kubectl (@(('--kubeconfig=' + $tmp), ('--token=' + $token), 'auth', 'can-i') + $c.args)
    Write-Observed ("  can {0,-32} -> {1}" -f $c.label, $r.verdict)
    $verdicts += $r.verdict
}

Remove-Item $tmp -Force -ErrorAction SilentlyContinue

$granted = @($verdicts | Where-Object { $_ -eq 'yes' })
Write-Assertion -Expected ('all {0} checks are refused' -f $checks.Count) `
    -Observed ("{0} of {1} refused; granted: {2}" -f ($verdicts.Count - $granted.Count), $verdicts.Count, $(if ($granted.Count) { $granted -join ', ' } else { 'none' })) `
    -Passed ($verdicts.Count -eq $checks.Count -and $granted.Count -eq 0) `
    -Note 'the token exists, is validly signed, and is refused by the API server. Validity of a credential and authority of a credential are different properties'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1550.001' -Description 'the same pod setting, side by side with PP-01' | Out-Null

$brPod = Get-LabPod -Namespace 'zerotrust-build' -App 'build-runner'
$brName = Get-Prop (Get-Prop $brPod 'metadata') 'name'
$brAuto = Get-Prop $brPod.spec 'automountServiceAccountToken'

Write-Observed '  pod spec          automount   identity                        grants on cluster resources'
Write-Observed ("  telemetry-agent  {0,-11} sa-telemetry-agent (observe)   none beyond the authenticated baseline" -f $automount)
Write-Observed ("  build-runner     {0,-11} sa-build-runner (build)        cluster-admin, everything" -f $brAuto)

Write-Assertion -Expected 'both pods have the identical automount setting' `
    -Observed ("sensor={0}, runner={1}" -f $automount, $brAuto) `
    -Passed ($automount -eq $brAuto) `
    -Note 'this is the whole finding. Identical pod spec, opposite blast radius, and the difference lives in a ClusterRoleBinding that no pod manifest mentions'

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'grant the sensor a single read-only permission, to see whether the posture drifts' `
    -Why 'that would be a cluster change, and tools/scan-drift.ps1 already covers the drift case in both directions: it fails on a permission appearing and it fails on a permission disappearing. Re-proving it here would duplicate a harness that runs on every commit.

      The change this finding actually argues for is automountServiceAccountToken: false on the sensor, which is a redesign rather than a tweak -- a reachability sensor that cannot reach the API server cannot report what it finds.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
