<#
.SYNOPSIS
    Scans the cluster for permissions and hardening that exceed what each
    workload needs, and fails when the result differs from the committed
    baseline.

.DESCRIPTION
    Phase 2's requirement is "no workload holds an unneeded permission; drift
    fails a test". This is that test.

    It compares what each workload's service account is actually granted
    against what that workload is documented to need. Anything extra is an
    over-permission finding.

    Two things make the result trustworthy rather than decorative:

    Expectations are written out longhand, not derived from the manifests. A
    scanner that reads the RBAC files and reports that the RBAC files match
    itself cannot fail. The expected grants below are the specification.

    Drift is judged in both directions. A finding that is new is drift. A
    finding that has disappeared is also a failure, because every finding in
    the baseline is a planted weakness, and the attack chain in Phase 8 walks
    those weaknesses by script. Fixing PP-01 by accident would silently
    un-test four detections.

.NOTES
    Finding keys are derived from stable identifiers -- namespace, workload
    label, resource name -- never from a pod name. A pod name contains a
    ReplicaSet hash and a random suffix, so keying on one turns every rollout
    into phantom drift in both directions.

.EXAMPLE
    .\tools\scan-drift.ps1
    .\tools\scan-drift.ps1 -WriteBaseline
#>
[CmdletBinding()]
param(
    [switch] $WriteBaseline,
    [switch] $SkipHardening,
    [string] $OutputPath,
    [string] $BaselinePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $OutputPath)   { $OutputPath   = Join-Path $repoRoot '.telemetry\drift-scan.json' }
if (-not $BaselinePath) { $BaselinePath = Join-Path $repoRoot 'drift\baseline.json' }

$labNamespaces = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

# ===========================================================================
# The specification: what each service account is supposed to be able to do.
#
# Empty means the workload needs no API access at all. That is the expected
# state for a web server, a database, a build runner and a network sensor in
# this lab, and it is worth writing down explicitly -- "no permissions" is a
# decision, and an unstated one is indistinguishable from an unimplemented one.
#
# resourceNames matters as much as resource. A grant to `secrets` narrowed to
# one name is a different thing from a grant to `secrets`, and the scanner
# treats them as different.
#
# Note that sa-build-runner appears here with no grants at all. That is the
# honest answer: a CI runner that compiles and pushes a container image needs
# no Kubernetes API permissions whatsoever. Its cluster-admin binding is not
# a need, it is a planted weakness, and it is listed in $acceptedRisk below so
# that it is reported as a finding rather than quietly blessed as correct.
# ===========================================================================
$expectedGrants = @{
    'zerotrust/sa-web-frontend'          = @()
    'zerotrust/sa-orders-api'            = @(
        @{ apiGroup = ''; resource = 'configmaps'; resourceNames = @('orders-api-config'); verbs = @('get') }
        @{ apiGroup = ''; resource = 'secrets';    resourceNames = @('postgres-credentials');  verbs = @('get') }
    )
    'zerotrust/sa-postgres'              = @()
    'zerotrust-build/sa-build-runner'    = @()
    'zerotrust-observe/sa-telemetry-agent' = @()
}

# Over-permissions and weaknesses we have decided to keep. Each one is a real
# finding that the scanner emits; the baseline is what stops it from also being
# drift. The reason is required -- an accepted risk without a written reason is
# just a finding that got tired of being reported.
#
# Keys are matched as a PREFIX of the finding key, because a finding key names
# the exact rule or container while the accepted risk is about the workload.
$acceptedRisk = [ordered]@{
    'rbac/zerotrust-build/sa-build-runner' = @(
        'PP-01. sa-build-runner is bound to cluster-admin. Planted on purpose: it is the lab headline weakness, it is walked by script in Phase 4, and DET-0001 is written against it. The build zone is genuinely network-isolated and that does not mitigate it, because control-plane access is not pod-to-pod traffic. A CI runner needs no Kubernetes API permissions at all, so the correct grant set for this workload is the empty one.'
    )
    'identity/token-no-grants/zerotrust-observe/telemetry-agent' = @(
        'WP-02. The sensor mounts a token that grants nothing. This is deliberate and is the residue of a removed ClusterRole: kube-router DNATs the API server ClusterIP before the policy chain runs, so no NetworkPolicy written against 10.96.0.1:443 can ever match and the permissions could not have been exercised. The RBAC was removed; the token stays, because it is the sensor identity in the audit log and an unattributable sensor is one nobody can trust afterwards.'
    )
    'identity/token-no-grants/zerotrust/web-frontend' = @(
        'The web frontend mounts a token it does not need. It does not talk to the API server at all. Kept so that any API activity originating from the pod is attributable to sa-web-frontend rather than to an anonymous identity -- the cheapest possible tripwire, given that this is also the workload with the weakest pod security (WP-01).'
    )
    'hardening/statefulsets/postgres/postgres/rootfs' = @(
        'A database genuinely needs a writable filesystem, and the stock postgres image writes outside its data directory. The image is kept stock so that the seeded rows and the docker-entrypoint-initdb.d path stay reproducible, which is the property the rest of the lab depends on. Every other postgres control is enforced, and the data directory is a PVC rather than the container root.'
    )
}

function Get-AcceptedReason {
    param([string] $FindingKey)
    foreach ($prefix in $acceptedRisk.Keys) {
        if ($FindingKey.StartsWith($prefix)) { return , @($acceptedRisk[$prefix]) }
    }
    # ,@() rather than $null: the caller wraps the result in @(), and @($null)
    # is a one-element array, which prints an empty "accepted:" line for every
    # finding that is not an accepted risk. That is most of them.
    return , @()
}

# Which pods use which service account.
$knownWorkloads = @(
    @{ name = 'web-frontend';    namespace = 'zerotrust';         sa = 'sa-web-frontend' }
    @{ name = 'orders-api';      namespace = 'zerotrust';         sa = 'sa-orders-api' }
    @{ name = 'postgres';        namespace = 'zerotrust';         sa = 'sa-postgres' }
    @{ name = 'build-runner';    namespace = 'zerotrust-build';   sa = 'sa-build-runner' }
    @{ name = 'telemetry-agent'; namespace = 'zerotrust-observe'; sa = 'sa-telemetry-agent' }
)

# ===========================================================================
# helpers
#
# Get-Prop exists because Set-StrictMode turns a missing property into a
# terminating error, and Kubernetes objects are full of properties that are
# legitimately absent depending on scope: a ClusterRoleBinding has no
# metadata.namespace, and most RBAC rules have no resourceNames. Reading those
# directly aborts the scan on the first platform object it meets.
# ===========================================================================
$script:findings = [System.Collections.Generic.List[object]]::new()

function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

# The leading comma is load-bearing. Returning @() from a function emits
# nothing at all, so the caller receives $null rather than an empty array, and
# under StrictMode the first `.Count` on it throws. `,@()` wraps the array so
# that exactly one level of unrolling is undone on the way out and the caller
# gets a real, empty, countable array. Every call site depends on this.
function Get-Array {
    param($Object, [string] $Name)
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return , @() }
    return , @($v)
}

function Add-Finding {
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Resource,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $AttackId = '',
        [string] $CWE = ''
    )
    $script:findings.Add([pscustomobject]@{
        key      = $Key
        category = $Category
        severity = $Severity
        resource = $Resource
        detail   = $Detail
        attackId = $AttackId
        cwe      = $CWE
    })
}

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

# Set-Content -Encoding utf8 under Windows PowerShell 5.1 writes CRLF and a BOM.
# The pre-commit mixed-line-ending hook then rewrites the file and fails the
# commit, so every regenerated baseline produced a spurious hook failure and a
# dirty diff. Normalise to LF without a BOM here instead, so the file is stable
# across runs and matches the rest of the repository.
function Write-JsonFile {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string] $Path)
    $json = $Object | ConvertTo-Json -Depth 10
    $lf   = ($json -replace "`r`n", "`n").TrimEnd() + "`n"
    $dir  = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-Json {
    param([string[]] $Arguments)
    $out = & kubectl @Arguments 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $out.Trim()) { return $null }
    try { return ($out | ConvertFrom-Json) } catch { return $null }
}

# Normalises a rule into a comparable string. A missing dimension becomes the
# empty string, which is meaningful: a rule with no resourceNames applies to
# every resource of that type, and `secrets|get|` is not `secrets|get|one-name`.
function Format-Rule {
    param($Rule)
    $groups = (Get-Array $Rule 'apiGroups')      -join ','
    $res    = (Get-Array $Rule 'resources')      -join ','
    $verbs  = (Get-Array $Rule 'verbs')          -join ','
    $names  = (Get-Array $Rule 'resourceNames')  -join ','
    return "$groups|$res|$verbs|$names"
}

# Does an actual grant fall inside an expected grant?
#
# Narrowing is fine. An expected grant of `secrets` is satisfied by an actual
# grant of `secrets/postgres-credentials` for verb get, but not the reverse:
# granting every secret when one was needed is not the same permission, and a
# scanner that cannot tell the difference is a scanner that approves PP-01.
function Test-GrantCovered {
    param($Actual, $Expected)

    $aGroups = Get-Array $Actual 'apiGroups'
    $aRes    = Get-Array $Actual 'resources'
    $aVerbs  = Get-Array $Actual 'verbs'
    $aNames  = Get-Array $Actual 'resourceNames'

    foreach ($exp in $Expected) {
        $eGroups = @($exp.apiGroup)
        $eRes    = @($exp.resource)
        $eVerbs  = @($exp.verbs)
        $eNames  = @($exp.resourceNames)

        $ok = $true
        foreach ($pair in @(
            @{ actual = $aGroups; expected = $eGroups },
            @{ actual = $aRes;    expected = $eRes    },
            @{ actual = $aVerbs;  expected = $eVerbs  },
            @{ actual = $aNames;  expected = $eNames  }
        )) {
            if ($pair.expected -contains '*') { continue }
            if ($pair.actual -contains '*')   { $ok = $false; break }
            foreach ($v in $pair.actual) {
                if ($pair.expected -notcontains $v) { $ok = $false; break }
            }
            if (-not $ok) { break }
        }
        if ($ok) { return $true }
    }
    return $false
}

# ===========================================================================
# preflight
# ===========================================================================
Write-Head 'preflight'
$nodes = (& kubectl get nodes --no-headers 2>$null | Measure-Object).Count
if ($nodes -lt 1) {
    Write-Host '  no reachable cluster. Start it with cluster\bootstrap\bootstrap.ps1' -ForegroundColor Red
    exit 1
}
Write-Host "  $nodes node(s) reachable"

# ===========================================================================
# collect RBAC
# ===========================================================================
Write-Head 'collecting RBAC'

$clusterRoles = @{}
$crJson = Get-Json @('get','clusterroles','-o','json')
foreach ($cr in (Get-Array $crJson 'items')) {
    $clusterRoles["cluster/$((Get-Prop (Get-Prop $cr 'metadata') 'name'))"] = $cr
}
$namespacedRoles = @{}
foreach ($r in (Get-Array (Get-Json @('get','roles','-A','-o','json')) 'items')) {
    $md = Get-Prop $r 'metadata'
    $namespacedRoles["$(Get-Prop $md 'namespace')/$(Get-Prop $md 'name')"] = $r
}
Write-Host "  $($clusterRoles.Count) ClusterRole(s), $($namespacedRoles.Count) Role(s)"

# grants[ "ns/sa" ] = list of @{ rule; via; scope }
$grants = @{}

$bindings = [System.Collections.Generic.List[object]]::new()
foreach ($crb in (Get-Array (Get-Json @('get','clusterrolebindings','-o','json')) 'items')) { $bindings.Add($crb) }
foreach ($rb  in (Get-Array (Get-Json @('get','rolebindings','-A','-o','json'))   'items')) { $bindings.Add($rb) }
Write-Host "  $($bindings.Count) binding(s)"

foreach ($b in $bindings) {
    $md       = Get-Prop $b 'metadata'
    $ns       = Get-Prop $md 'namespace'
    $roleRef  = Get-Prop $b 'roleRef'
    $refKind  = Get-Prop $roleRef 'kind'
    $refName  = Get-Prop $roleRef 'name'

    if ($refKind -eq 'ClusterRole') { $roleKey = "cluster/$refName" }
    else                           { $roleKey = "$ns/$refName" }

    $role = $null
    if ($clusterRoles.ContainsKey($roleKey))      { $role = $clusterRoles[$roleKey] }
    elseif ($namespacedRoles.ContainsKey($roleKey)) { $role = $namespacedRoles[$roleKey] }
    if (-not $role) { continue }

    # A cluster-scoped binding has no namespace, so it renders with a leading
    # slash. That is accurate rather than ugly, and it is how the binding is
    # addressed back to the user.
    $bindingName = if ($ns) { "$ns/$(Get-Prop $md 'name')" } else { "/$(Get-Prop $md 'name')" }

    foreach ($subj in (Get-Array $b 'subjects')) {
        if ((Get-Prop $subj 'kind') -ne 'ServiceAccount') { continue }
        $sa = "$(Get-Prop $subj 'namespace')/$(Get-Prop $subj 'name')"
        if (-not $grants.ContainsKey($sa)) { $grants[$sa] = [System.Collections.Generic.List[object]]::new() }
        foreach ($rule in (Get-Array $role 'rules')) {
            $grants[$sa].Add([pscustomobject]@{ rule = $rule; via = $bindingName; scope = $roleKey })
        }
    }
}

# ===========================================================================
# check 1: over-permission
# ===========================================================================
Write-Head 'authorization: grants versus documented need'

foreach ($saKey in ($expectedGrants.Keys | Sort-Object)) {
    $expected = $expectedGrants[$saKey]
    $actual   = @()
    if ($grants.ContainsKey($saKey)) { $actual = @($grants[$saKey]) }

    if ($actual.Count -eq 0 -and $expected.Count -eq 0) {
        Write-Host "  [ok]  $saKey has no API grants" -ForegroundColor Green
        continue
    }

    foreach ($g in $actual) {
        $rule = $g.rule
        if (Test-GrantCovered -Actual $rule -Expected $expected) {
            Write-Host "  [ok]  $saKey <- $(Format-Rule $rule)  (via $($g.via))" -ForegroundColor Green
            continue
        }

        $aGroups = Get-Array $rule 'apiGroups'
        $aRes    = Get-Array $rule 'resources'
        $aVerbs  = Get-Array $rule 'verbs'
        $aNames  = Get-Array $rule 'resourceNames'

        $isWildcard  = ($aGroups -contains '*') -or ($aRes -contains '*') -or ($aVerbs -contains '*') -or ($aNames -contains '*')
        $isUnscoped  = ($aNames.Count -eq 0)
        $hitsSecrets = ($aRes -contains 'secrets') -or ($aRes -contains '*')
        $isWrite     = @($aVerbs | Where-Object { $_ -in @('create','update','patch','delete','deletecollection') }).Count -gt 0

        $severity = 'medium'
        $attack   = ''
        if ($isWildcard) {
            $severity = 'high'; $attack = 'T1078.001'
        } elseif ($hitsSecrets) {
            $severity = 'high'; $attack = 'T1552.001'
        } elseif ($isWrite) {
            $severity = 'high'; $attack = 'T1098.003'
        }

        $extra = ''
        if ($hitsSecrets -and $isUnscoped) { $extra = ' The grant is not narrowed by resourceNames, so it covers every Secret in the scope, not one.' }

        Add-Finding -Key "rbac/$saKey/$(Format-Rule $rule)" -Category 'rbac' -Severity $severity `
            -Resource "ServiceAccount/$saKey" `
            -Detail "granted $(Format-Rule $rule) via $($g.via), which is not in the documented need for this workload.$extra" `
            -AttackId $attack
    }
}

# Service accounts in a lab namespace that hold grants but are not in the
# inventory. Deliberately scoped to the lab namespaces: kube-system holds
# fifty-odd service accounts granted by the platform, and flagging those would
# bury the findings that matter under noise nobody can act on.
$knownSAs = @($knownWorkloads | ForEach-Object { "$($_.namespace)/$($_.sa)" })
foreach ($saKey in ($grants.Keys | Sort-Object)) {
    $saNs = ($saKey -split '/')[0]
    if ($labNamespaces -notcontains $saNs) { continue }
    if ($knownSAs -contains $saKey) { continue }
    Add-Finding -Key "rbac/unknown-sa/$saKey" -Category 'rbac' -Severity 'medium' `
        -Resource "ServiceAccount/$saKey" `
        -Detail 'holds RBAC grants but is not in the workload inventory; an untracked credential in a lab namespace is an unmonitored one' `
        -AttackId 'T1078.001'
}

# ===========================================================================
# check 2: named identities and tokens without grants (WP-02)
# ===========================================================================
Write-Head 'workloads: named identities and mounted tokens'

$podsJson = Get-Json @('get','pods','-A','-o','json')
$allPods  = Get-Array $podsJson 'items'

# Probe pods from tools/test-boundaries.ps1 are transient harness scaffolding,
# not part of the system under test. Excluding them keeps the drift scan
# independent of whether the boundary scan happens to have finished cleaning up.
$labPods = @($allPods | Where-Object {
    $ns = Get-Prop (Get-Prop $_ 'metadata') 'namespace'
    if ($labNamespaces -notcontains $ns) { return $false }
    $ann = Get-Prop (Get-Prop $_ 'metadata') 'annotations'
    if ((Get-Prop $ann 'zerotrust.lab/purpose') -eq 'boundary-test-probe') { return $false }
    return $true
})
Write-Host "  $($labPods.Count) lab pod(s) inspected"

foreach ($pod in $labPods) {
    $md      = Get-Prop $pod 'metadata'
    $ns      = Get-Prop $md 'namespace'
    $podName = Get-Prop $md 'name'
    $labels  = Get-Prop $md 'labels'
    $app     = Get-Prop $labels 'app'
    $spec    = Get-Prop $pod 'spec'
    $sa      = Get-Prop $spec 'serviceAccountName'

    # The key uses the app label, not the pod name. Pod names embed a
    # ReplicaSet hash and a random suffix, so keying on one would make every
    # rollout look like drift in both directions.
    $subject = if ($app) { "$ns/$app" } else { "$ns/$podName" }

    if (-not $sa -or $sa -eq 'default') {
        Add-Finding -Key "identity/default-sa/$subject" -Category 'identity' -Severity 'high' `
            -Resource "Pod/$ns/$app" `
            -Detail 'uses the default ServiceAccount, so the audit log cannot attribute its API activity to an application' `
            -AttackId 'T1078.001'
    }

    $mountsToken = ((Get-Prop $spec 'automountServiceAccountToken') -ne $false)
    $saKey = "$ns/$sa"
    $hasGrants = $grants.ContainsKey($saKey) -and $grants[$saKey].Count -gt 0

    if ($mountsToken -and -not $hasGrants) {
        # WP-02. Not automatically wrong -- the sensor is deliberately in this
        # state, and so is the web frontend -- but it must be a decision rather
        # than an accident, so it is reported and baselined.
        Add-Finding -Key "identity/token-no-grants/$subject" -Category 'identity' -Severity 'low' `
            -Resource "Pod/$ns/$app" `
            -Detail "ServiceAccount $saKey mounts a token that grants nothing. The token is the pod's identity in the audit log, so removing it would make the pod's API activity unattributable, but a credential that authorises nothing is still a credential" `
            -AttackId 'T1550.001'
    }
}

# ===========================================================================
# check 3: pod hardening (WP-01)
# ===========================================================================
if (-not $SkipHardening) {
    Write-Head 'workloads: pod hardening'

    $controllers = [System.Collections.Generic.List[object]]::new()
    foreach ($ns in $labNamespaces) {
        foreach ($kind in @('deployments','statefulsets')) {
            foreach ($item in (Get-Array (Get-Json @('get',$kind,'-n',$ns,'-o','json')) 'items')) {
                $md   = Get-Prop $item 'metadata'
                $spec = Get-Prop (Get-Prop $item 'spec') 'template'
                $spec = Get-Prop $spec 'spec'
                $controllers.Add([pscustomobject]@{
                    kind = $kind; name = Get-Prop $md 'name'; spec = $spec
                })
            }
        }
    }
    Write-Host "  $($controllers.Count) controller(s)"

    foreach ($c in $controllers) {
        $target = "$($c.kind)/$($c.name)"
        $sc  = Get-Prop $c.spec 'securityContext'
        $podKey = "hardening/$target"

        if ($null -eq $sc -or (Get-Prop $sc 'runAsNonRoot') -ne $true) {
            Add-Finding -Key $podKey -Category 'hardening' -Severity 'high' `
                -Resource $target -Detail 'no securityContext.runAsNonRoot, so the container starts as uid 0' `
                -AttackId 'T1610' -CWE 'CWE-250'
        }
        if ($null -eq $sc -or $null -eq (Get-Prop $sc 'seccompProfile')) {
            Add-Finding -Key "$podKey/seccomp" -Category 'hardening' -Severity 'medium' `
                -Resource $target -Detail 'no seccomp profile, so the default Unconfined applies' `
                -AttackId 'T1611' -CWE 'CWE-693'
        }

        foreach ($container in (Get-Array $c.spec 'containers')) {
            $cname = Get-Prop $container 'name'
            $csc   = Get-Prop $container 'securityContext'
            $ck    = "hardening/$target/$cname"

            if ($null -eq $csc -or (Get-Prop $csc 'allowPrivilegeEscalation') -ne $false) {
                Add-Finding -Key "$ck/priv-esc" -Category 'hardening' -Severity 'medium' `
                    -Resource "$target container $cname" -Detail 'allowPrivilegeEscalation is not false' `
                    -AttackId 'T1611' -CWE 'CWE-269'
            }
            $drop = Get-Array (Get-Prop $csc 'capabilities') 'drop'
            if ($drop -notcontains 'ALL') {
                Add-Finding -Key "$ck/caps" -Category 'hardening' -Severity 'medium' `
                    -Resource "$target container $cname" -Detail 'capabilities are not dropped to ALL' `
                    -AttackId 'T1611' -CWE 'CWE-250'
            }
            if ($null -eq $csc -or (Get-Prop $csc 'readOnlyRootFilesystem') -ne $true) {
                Add-Finding -Key "$ck/rootfs" -Category 'hardening' -Severity 'low' `
                    -Resource "$target container $cname" -Detail 'readOnlyRootFilesystem is not true' `
                    -AttackId 'T1611' -CWE 'CWE-284'
            }
        }
    }
}

# ===========================================================================
# report
# ===========================================================================
Write-Head 'findings'
$script:findings | Sort-Object key | ForEach-Object {
    Write-Host ("  [{0,-6}] {1}" -f $_.severity.ToUpper(), $_.key) -ForegroundColor DarkGray
    Write-Host ("           {0}" -f $_.detail) -ForegroundColor DarkGray
    if ($_.attackId) { Write-Host ("           {0}" -f $_.attackId) -ForegroundColor DarkGray }
    foreach ($reason in @(Get-AcceptedReason -FindingKey $_.key)) {
        Write-Host ("           accepted: {0}" -f $reason) -ForegroundColor DarkYellow
    }
}

# ===========================================================================
# compare against baseline
# ===========================================================================
$current = @{}
foreach ($f in $script:findings) { $current[$f.key] = $f }

if ($WriteBaseline) {
    $doc = [ordered]@{
        generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        note        = @'
Expected findings. Every entry is a deliberate weakness or an accepted trade-off.
A finding not in this list is drift and fails the scan. A finding here that has
disappeared also fails, because the attack chain in Phase 8 walks these by
script and four detections are written against them.
'@
        expectedGrants = $expectedGrants
        acceptedRisk   = $acceptedRisk
        findings       = @($script:findings | Sort-Object key)
    }
    Write-JsonFile -Object $doc -Path $BaselinePath
    Write-Host ''
    Write-Host "  baseline written to $BaselinePath ($($script:findings.Count) expected finding(s))" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    Write-Host ''
    Write-Host "  no baseline at $BaselinePath" -ForegroundColor Red
    Write-Host '  run once with -WriteBaseline, read the result, and commit it' -ForegroundColor Red
    exit 1
}

$baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
$expectedKeys = @((Get-Array $baseline 'findings') | ForEach-Object { Get-Prop $_ 'key' })
$baselineByKey = @{}
foreach ($f in (Get-Array $baseline 'findings')) { $baselineByKey[(Get-Prop $f 'key')] = $f }

$newFindings  = @($script:findings | Where-Object { $expectedKeys -notcontains $_.key })
$goneFindings = @($expectedKeys | Where-Object { -not $current.ContainsKey($_) })

Write-Head 'drift'
Write-Host "  expected $($expectedKeys.Count), observed $($script:findings.Count), new $($newFindings.Count), disappeared $($goneFindings.Count)"

if ($newFindings) {
    Write-Host ''
    Write-Host '  NEW findings (drift):' -ForegroundColor Red
    foreach ($f in $newFindings) {
        Write-Host ("    + [{0}] {1}" -f $f.severity.ToUpper(), $f.key) -ForegroundColor Red
        Write-Host ("      {0}" -f $f.detail) -ForegroundColor Red
    }
}
if ($goneFindings) {
    Write-Host ''
    Write-Host '  DISAPPEARED findings:' -ForegroundColor Yellow
    foreach ($k in $goneFindings) {
        Write-Host ("    - {0}" -f $k) -ForegroundColor Yellow
        if ($baselineByKey.ContainsKey($k)) { Write-Host ("      {0}" -f (Get-Prop $baselineByKey[$k] 'detail')) -ForegroundColor Yellow }
    }
    Write-Host ''
    Write-Host '  a planted weakness is gone. Phases 4 and 8 walk these paths by' -ForegroundColor Yellow
    Write-Host '  script, and four detections are written against them.' -ForegroundColor Yellow
}

$report = [pscustomobject]@{
    generatedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    total        = $script:findings.Count
    newCount     = $newFindings.Count
    goneCount    = $goneFindings.Count
    drift        = ($newFindings.Count -gt 0 -or $goneFindings.Count -gt 0)
    newFindings  = $newFindings
    goneFindings = $goneFindings
    allFindings  = @($script:findings | Sort-Object key)
}
Write-JsonFile -Object $report -Path $OutputPath
Write-Host ''
Write-Host "  report written to $OutputPath"

exit $(if ($newFindings.Count -gt 0 -or $goneFindings.Count -gt 0) { 1 } else { 0 })
