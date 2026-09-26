#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the ZeroTrust-SOC-Lab cluster from nothing.

.DESCRIPTION
    One command to get from a clean machine to a working lab:

      1. verify the toolchain is present
      2. create the three-node kind cluster from kind-config.yaml
      3. wait for every node to report Ready
      4. confirm audit logging is actually recording
      5. create the zerotrust namespace

    The script is safe to run repeatedly. It distinguishes three states, because
    they need different handling:

      - no cluster      create it
      - healthy cluster report and exit, change nothing
      - broken cluster  refuse to guess, tell the operator how to inspect it

    That last case is the one worth being careful about. A cluster where one
    node is Ready and two are NotReady is a genuinely different situation from
    no cluster at all, and quietly recreating it would destroy the evidence of
    whatever caused the breakage. Since this lab exists to investigate
    failures, the script must never paper over one.

.PARAMETER ClusterName
    kind cluster name. Defaults to soc-lab.

.PARAMetric ForceRecreate
    Delete and rebuild the cluster even if one exists. Destructive.

.PARAMETER SkipAuditCheck
    Do not verify audit logging. Only useful when debugging bootstrap itself.

.EXAMPLE
    .\bootstrap.ps1

.EXAMPLE
    .\bootstrap.ps1 -ForceRecreate
#>

[CmdletBinding()]
param(
    [string]$ClusterName = 'soc-lab',
    [switch]$ForceRecreate,
    [switch]$SkipAuditCheck
)

# Native tools (docker, kind, kubectl) write normal progress messages to
# stderr. With ErrorActionPreference = 'Stop' PowerShell turns those into
# terminating errors, which aborts the script on success. Every failure in this
# script is handled explicitly by checking $LASTEXITCODE and throwing a
# specific message, so Continue is the correct setting here.
$ErrorActionPreference = 'Continue'

$scriptRoot = $PSScriptRoot
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)
$configPath = Join-Path $scriptRoot 'kind-config.yaml'
$LabNamespace = 'zerotrust'
$NodeAuditLog = '/var/log/kubernetes/audit/audit.log'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

function Assert-Command {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Hint
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "'$Name' was not found on PATH. $Hint"
    }
}

function Test-DockerReady {
    $server = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
    return $server -match '^\d'
}

function Get-ClusterState {
    <#
        Returns one of: Absent, Healthy, Degraded
    #>
    $clusters = & kind get clusters 2>$null | Out-String
    if ($clusters -notmatch [regex]::Escape($ClusterName)) { return 'Absent' }

    $nodes = & kubectl get nodes --no-headers 2>$null | Out-String
    if (-not $nodes.Trim()) { return 'Degraded' }

    $rows = $nodes -split "`n" | Where-Object { $_.Trim() }
    if ($rows.Count -eq 0) { return 'Degraded' }

    $notReady = $rows | Where-Object { $_ -notmatch '\sReady\s' }
    if ($notReady.Count -gt 0) { return 'Degraded' }
    return 'Healthy'
}

function Get-NodeSummary {
    & kubectl get nodes 2>$null | Out-String
}

# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'ZeroTrust-SOC-Lab bootstrap' -ForegroundColor White
Write-Host '=========================' -ForegroundColor White
Write-Host ''

if (-not (Test-Path -LiteralPath $configPath)) {
    throw "Cluster config not found at $configPath"
}

# 1. Toolchain -------------------------------------------------------------
Write-Step 'Checking toolchain'

Assert-Command -Name 'docker' -Hint 'Install Docker Desktop and make sure it is running.'
Assert-Command -Name 'kind'  -Hint 'Install with: winget install Kubernetes.kind'
Assert-Command -Name 'kubectl' -Hint 'Install with: winget install Kubernetes.kubectl'
Write-Ok 'docker, kind and kubectl are on PATH'

if (-not (Test-DockerReady)) {
    throw 'Docker is installed but the engine is not responding. Start Docker Desktop and wait for the whale icon to stop animating, then re-run.'
}
Write-Ok "Docker engine is responding (server $(& docker version --format '{{.Server.Version}}'))"

# 2. Cluster state ---------------------------------------------------------
Write-Step 'Determining cluster state'

$state = Get-ClusterState

switch ($state) {
    'Degraded' {
        Write-Host ''
        Write-Host 'A cluster named ' -NoNewline -ForegroundColor Red
        Write-Host $ClusterName -NoNewline -ForegroundColor White
        Write-Host ' exists but is not fully healthy:' -ForegroundColor Red
        Write-Host ''
        Write-Host (Get-NodeSummary) -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Refusing to continue. Recreating now would destroy the evidence' -ForegroundColor Red
        Write-Host 'of whatever caused this, and this lab exists to investigate exactly' -ForegroundColor Red
        Write-Host 'that kind of failure.' -ForegroundColor Red
        Write-Host ''
        Write-Host 'Inspect it first:' -ForegroundColor Cyan
        Write-Host "  kubectl get nodes -o wide" -ForegroundColor Gray
        Write-Host "  kubectl describe node <name>" -ForegroundColor Gray
        Write-Host "  docker logs $ClusterName-control-plane --tail 50" -ForegroundColor Gray
        Write-Host ''
        Write-Host 'When you have decided, rebuild deliberately with:' -ForegroundColor Cyan
        Write-Host "  .\bootstrap.ps1 -ForceRecreate" -ForegroundColor Gray
        exit 1
    }
    'Healthy' {
        if ($ForceRecreate) {
            Write-Step 'Deleting existing cluster (-ForceRecreate)'
            & kind delete cluster --name $ClusterName 2>&1 | Out-Null
            $state = 'Absent'
        } else {
            Write-Ok "cluster '$ClusterName' already exists and all nodes are Ready"
            Write-Ok 'nothing to do. Use -ForceRecreate to rebuild from scratch.'
            Write-Host ''
            Write-Host (Get-NodeSummary) -ForegroundColor Gray
            exit 0
        }
    }
    'Absent' { Write-Ok "no cluster named '$ClusterName' found" }
}

# 3. Create ----------------------------------------------------------------
Write-Step "Creating cluster '$ClusterName'"
Write-Info 'this downloads a ~1.45 GB image on first run and takes a few minutes'

$createOutput = & kind create cluster --config $configPath --wait 120s 2>&1 | Out-String
$createExit = $LASTEXITCODE

if ($createExit -ne 0) {
    $detail = ($createOutput -split "`n" |
        Where-Object { $_ -match 'ERROR|error:|failed' -and $_ -notmatch 'CategoryInfo|FullyQualifiedErrorId' } |
        Select-Object -First 6)
    throw "kind create cluster failed:`n$($detail -join "`n")"
}
Write-Ok 'cluster created'

# 4. Wait for nodes --------------------------------------------------------
Write-Step 'Waiting for all nodes to report Ready'

& kubectl wait --for=condition=Ready nodes --all --timeout=180s 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Nodes did not become Ready in time. Current state:`n$(Get-NodeSummary)"
}
Write-Ok 'all nodes Ready'
Write-Host ''
Write-Host (Get-NodeSummary) -ForegroundColor Gray
Write-Host ''

# 5. Verify audit logging --------------------------------------------------
if (-not $SkipAuditCheck) {
    Write-Step 'Verifying audit logging is recording'

    $hasLog = & docker exec "$ClusterName-control-plane" sh -c "test -f $NodeAuditLog && echo yes || echo no" 2>$null | Out-String

    if ($hasLog.Trim() -ne 'yes') {
        throw @"
Audit logging is NOT active. No log at $NodeAuditLog.

This means the cluster was created without the audit configuration, so there
would be no record of API activity. That is the one control this lab cannot
work without. Rebuild with the current config:

    .\bootstrap.ps1 -ForceRecreate
"@
    }

    $bytes = (& docker exec "$ClusterName-control-plane" sh -c "wc -c < $NodeAuditLog" 2>$null | Out-String).Trim()
    Write-Ok "audit log is being written ($bytes bytes)"

    $flagged = (& docker exec "$ClusterName-control-plane" sh -c "grep -c 'audit-policy-file' /etc/kubernetes/manifests/kube-apiserver.yaml" 2>$null | Out-String).Trim()
    if ($flagged -ne '1') {
        Write-Warning 'audit log exists but --audit-policy-file is not set. Logging may be incomplete.'
    }
}

# 6. Namespace -------------------------------------------------------------
Write-Step "Ensuring namespace '$LabNamespace' exists"

$existing = & kubectl get namespace $LabNamespace --no-headers 2>$null | Out-String
if ($existing -match $LabNamespace) {
    Write-Ok "namespace '$LabNamespace' already exists"
} else {
    & kubectl create namespace $LabNamespace 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create namespace '$LabNamespace'" }
    Write-Ok "namespace '$LabNamespace' created"
}

# Done ---------------------------------------------------------------------
Write-Host ''
Write-Host 'Bootstrap complete.' -ForegroundColor Green
Write-Host ''
Write-Host 'Next:' -ForegroundColor White
Write-Host "  kubectl get pods -A" -ForegroundColor Gray
Write-Host "  .\telemetry\audit\export-audit-log.ps1 -SinceMinutes 5" -ForegroundColor Gray
Write-Host ''
Write-Host 'Tear down with:' -ForegroundColor White
Write-Host "  kind delete cluster --name $ClusterName" -ForegroundColor Gray
Write-Host ''
