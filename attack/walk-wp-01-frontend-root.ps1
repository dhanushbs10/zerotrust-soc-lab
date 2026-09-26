<#
    Walks WP-01: web-frontend runs as root with no securityContext at all.

    T1610 Deploy Container
    T1611 Escape to Host

    The demonstration, and why it is shaped this way
    -----------------------------------------------
    "It runs as root" is a claim every container scanner makes and almost
    nobody can quantify. The interesting question is not whether the UID is 0,
    it is what the UID is actually worth in this specific pod.

    The lab can answer that precisely, because orders-api runs the *same image*
    on the same filesystem and differs only by its securityContext:

        web-frontend   nginx@sha256:65645c7b   runAsUser <none>   readOnlyRootFilesystem <none>
        orders-api     nginx@sha256:65645c7b   runAsUser 101      readOnlyRootFilesystem true

    One flag apart, on an identical image. That makes a controlled comparison
    possible without inventing anything, and it turns an abstract hardening
    claim into a measured capability difference: the served document root is
    writable in one pod and not in the other, and the only reason is the
    securityContext.

    The comparison is done with `test -w`, which asks the kernel a question and
    changes nothing. Nothing is written, and the served content is untouched.

    Why root matters here, concretely
    ---------------------------------
    web-frontend serves content to users. A process running as uid 0 in that
    container can rewrite what is served, so a compromise of this pod is a
    compromise of whatever the user is looking at at that moment. The hardening
    on orders-api does not prevent that by itself; it removes the capability
    that would make it trivial.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'WP-01' `
    -Title 'web-frontend explicitly opts out of non-root and has no container hardening' `
    -Claim @'
A workload can be correctly hardened and still be fully owned, and a workload
can be unhardened and still be contained. The two findings that prove it are
compared here on the same image, one flag apart, so the difference is measured
rather than asserted.
'@

$ns = 'zerotrust'
$front = Get-LabPod -Namespace $ns -App 'web-frontend'
$api   = Get-LabPod -Namespace $ns -App 'orders-api'
if (-not $front -or -not $api) {
    Write-Host '  both web-frontend and orders-api must be running' -ForegroundColor Red
    exit 1
}
$frontName = Get-Prop (Get-Prop $front 'metadata') 'name'
$apiName   = Get-Prop (Get-Prop $api   'metadata') 'name'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1610' -Description 'establish the precondition: something must be able to reach this pod' | Out-Null

Write-Observed "web-frontend pod: $frontName"
Write-Observed ("  NetworkPolicies selecting it: {0}" -f ((& kubectl get networkpolicy -n $ns -o json 2>$null | Out-String | ConvertFrom-Json).items |
    Where-Object { $_.spec.podSelector -and $_.metadata.name } | Measure-Object).Count)

$sensorReach = Get-LastLine (Invoke-InPod -Namespace 'zerotrust-observe' `
    -Pod (Get-Prop (Get-Prop (Get-LabPod -Namespace 'zerotrust-observe' -App 'telemetry-agent') 'metadata') 'name') `
    -Shell 'sh' -Command 'nc -w 3 -z web-frontend.zerotrust.svc.cluster.local 80 && echo REACHABLE || echo BLOCKED')

Write-Observed ("  telemetry-agent -> web-frontend:80 : {0}" -f $sensorReach)

Write-Assertion -Expected 'at least one identity can open a path to web-frontend' `
    -Observed $sensorReach `
    -Passed ($sensorReach -eq 'REACHABLE') `
    -Note 'this is PP-02. WP-01 is only exploitable by someone who can already get here, so the precondition is stated rather than assumed'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1610' -Description 'the process runs as uid 0' | Out-Null

$uid = Invoke-InPod -Namespace $ns -Pod $frontName -Shell 'sh' -Command 'id -u'
Write-Observed "id -u inside web-frontend: $uid"
Write-Observed (Invoke-InPod -Namespace $ns -Pod $frontName -Shell 'sh' -Command 'ps -o pid,user,comm 2>/dev/null | head -5')

Write-Assertion -Expected 'the container process runs as root' `
    -Observed "uid $uid" `
    -Passed ($uid.Trim() -eq '0')

# Worth being precise here, because the obvious phrasing is wrong. It is not
# that web-frontend omits its securityContext. It sets one, and the setting is
# an opt-out:
#
#     pod-level:        {"runAsNonRoot": false}
#     container-level:  {} -- absent entirely
#
# So the finding is stronger than "hardening was forgotten". runAsNonRoot was
# considered and set to false, and on top of that the container gets no
# allowPrivilegeEscalation, no readOnlyRootFilesystem, no dropped capabilities
# and no seccomp profile. Compare orders-api on the same image, which sets all
# five.
$podSc  = Get-Prop $front.spec 'securityContext'
$contSc = Get-Prop $front.spec.containers[0] 'securityContext'
$runAsNonRoot = if ($podSc) { Get-Prop $podSc 'runAsNonRoot' } else { '<absent>' }
$hasContainerSc = ($null -ne $contSc)

Write-Observed ("  pod-level securityContext       : runAsNonRoot={0}, runAsUser={1}" -f `
    $runAsNonRoot, $(if ($podSc -and (Get-Prop $podSc 'runAsUser')) { Get-Prop $podSc 'runAsUser' } else { '<absent>' }))
Write-Observed ("  container-level securityContext : {0}" -f $(if ($hasContainerSc) { 'present' } else { 'absent entirely' }))

Write-Assertion -Expected 'the pod explicitly opts out of non-root with runAsNonRoot: false' `
    -Observed ("runAsNonRoot is {0}" -f $runAsNonRoot) `
    -Passed ($runAsNonRoot -eq $false) `
    -Note 'declared rather than omitted. The difference matters: an omission is an oversight, an opt-out is a decision, and a decision is harder to argue with'

Write-Assertion -Expected 'the container declares no securityContext of its own' `
    -Observed $(if ($hasContainerSc) { 'present' } else { 'absent entirely' }) `
    -Passed (-not $hasContainerSc) `
    -Note 'which means no allowPrivilegeEscalation: false, no readOnlyRootFilesystem, no capabilities.drop, and no seccompProfile. orders-api sets all five on the same image'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1611' -Description 'measure what uid 0 is worth here, against the same image hardened' | Out-Null

$frontImage = Get-Prop $front.spec.containers[0] 'image'
$apiImage   = Get-Prop $api.spec.containers[0]   'image'
Write-Observed "web-frontend image: $frontImage"
Write-Observed "orders-api   image: $apiImage"
Write-Assertion -Expected 'both pods run the identical image digest' `
    -Observed $(if ($frontImage -eq $apiImage) { 'identical' } else { "DIFFERENT: $frontImage vs $apiImage" }) `
    -Passed ($frontImage -eq $apiImage) `
    -Note 'this is what makes the comparison controlled. Same bytes on disk, different securityContext, so any difference in capability is attributable to the securityContext alone'

Write-Observed ''
Write-Observed '  the same question, asked of both pods, answered by the kernel:'
$q = 'test -w /usr/share/nginx/html && echo document-root-WRITABLE || echo document-root-readonly'
$frontCap = Get-LastLine (Invoke-InPod -Namespace $ns -Pod $frontName -Shell 'sh' -Command $q)
$apiCap   = Get-LastLine (Invoke-InPod -Namespace $ns -Pod $apiName   -Shell 'sh' -Command $q)
Write-Observed ("    web-frontend (uid 0,  no securityContext) : {0}" -f $frontCap)
Write-Observed ("    orders-api   (uid 101, readOnly rootfs)   : {0}" -f $apiCap)

Write-Assertion -Expected 'the document root is writable in the unhardened pod' `
    -Observed $frontCap `
    -Passed ($frontCap -eq 'document-root-WRITABLE') `
    -Note 'test -w asks the kernel and changes nothing. Nothing was written to the served content'

Write-Assertion -Expected 'the document root is not writable in the hardened pod' `
    -Observed $apiCap `
    -Passed ($apiCap -eq 'document-root-readonly') `
    -Note 'identical image, opposite capability. The difference is the securityContext and nothing else'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1611' -Description 'uid 0 also defeats the boundaries an unprivileged process would respect' | Out-Null

# All of these are capability probes. None of them writes to the container, and
# none of them attempts an escape -- they establish what the UID is worth, and
# the escape attempt is withheld below.
#
# Results are captured into a hashtable rather than asserted inline, because
# each probe is a separate exec and re-running one to get its text for the
# report would be measuring the pod twice and reporting whichever run happened
# to be quoted. One run, one result, used for both the display and the verdict.
$probes = @(
    @{ label = 'can rewrite its own /etc/passwd';      q = 'test -w /etc/passwd && echo yes || echo no' }
    @{ label = 'can write a kernel-exposed file';     q = 'test -w /proc/sys/kernel/hostname && echo yes || echo no' }
    @{ label = 'can address pid 1 root';              q = 'ls /proc/1/root >/dev/null 2>&1 && echo yes || echo no' }
)
$probeResults = @{}
foreach ($p in $probes) {
    $r = Get-LastLine (Invoke-InPod -Namespace $ns -Pod $frontName -Shell 'sh' -Command $p.q)
    $probeResults[$p.label] = $r
    Write-Observed ("  {0,-36} {1}" -f $p.label, $(if ($r -eq 'yes') { 'yes' } else { 'no' }))
}

Write-Assertion -Expected 'the container can rewrite /etc/passwd, so it can alter its own identity' `
    -Observed $(if ($probeResults['can rewrite its own /etc/passwd'] -eq 'yes') { 'yes' } else { 'no' }) `
    -Passed ($probeResults['can rewrite its own /etc/passwd'] -eq 'yes') `
    -Note 'a process that can rewrite its own passwd entry can add a uid 0 account, which is a persistence primitive inside the container'

Write-Assertion -Expected 'the process can address pid 1 root, so it is not confined by a uid boundary' `
    -Observed $(if ($probeResults['can address pid 1 root'] -eq 'yes') { 'yes' } else { 'no' }) `
    -Passed ($probeResults['can address pid 1 root'] -eq 'yes') `
    -Note 'addressing pid 1 is not escaping. It is the precondition for an escape attempt, and it is the thing a non-root process is denied'

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'write a file into the served document root and fetch it back over HTTP' `
    -Why 'this is the step that converts a weakness into visible compromise, and it would change what users of this workload are served. It is trivially reversible but it is not invisible, and a demo that quietly serves a defaced page is a demo that edited production.

      To run it deliberately:
        kubectl exec -n zerotrust <web-frontend-pod> -- sh -c ''echo pwned > /usr/share/nginx/html/pwned.html''
        kubectl exec -n zerotrust <web-frontend-pod> -- wget -qO- http://127.0.0.1/pwned.html'

Write-Withheld -WouldDo 'attempt a container escape to the node' `
    -Why 'a real attempt is not a read-only observation and its outcome depends on the node kernel, which is not what this finding is about. WP-01 is the *precondition* for T1611: uid 0 in a privileged-adjacent workload. The escape itself is a different exercise.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
