#Requires -Version 5.1
<#
.SYNOPSIS
    Exports Kubernetes API server audit records from the kind cluster as
    normalized JSON Lines, ready for detection rules to consume.

.DESCRIPTION
    The API server audit log is the primary evidence source for this lab. It
    records every request made to the cluster: who asked, what they asked for,
    when, from where, and whether RBAC allowed it.

    This script copies the raw log out of the control plane node, then flattens
    each record into a stable shape so that detection rules do not have to know
    about the nesting of the original audit event.

    One field deserves special attention: effectiveIdentity.

    Kubernetes records two distinct identities per request:

      user.username          who actually authenticated
      impersonatedUser       who that caller claimed to be, via impersonation

    A caller running "kubectl --as=system:serviceaccount:zerotrust:default"
    authenticates as kubernetes-admin and impersonates the service account. The
    RBAC decision is made against the IMPERSONATED identity, but a naive rule
    that reads only user.username would attribute the action to the admin and
    miss the escalation entirely.

    effectiveIdentity resolves this to the identity RBAC actually decided on.
    Rules should match on that field, not on user.username.

.PARAMETER ClusterName
    kind cluster name. Defaults to soc-lab.

.PARAMETER SinceMinutes
    Only export records from the last N minutes. Useful for demo runs so that
    output stays small. Omit to export everything.

.PARAMETER OutputPath
    Destination file. Defaults to .telemetry\audit-events.jsonl

.EXAMPLE
    .\export-audit-log.ps1 -SinceMinutes 10
#>

[CmdletBinding()]
param(
    [string]$ClusterName = 'soc-lab',
    [int]$SinceMinutes = 0,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$ControlPlane = "$ClusterName-control-plane"
$NodeAuditLog = '/var/log/kubernetes/audit/audit.log'

if (-not $OutputPath) {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $OutputPath = Join-Path $projectRoot '.telemetry\audit-events.jsonl'
}

function Assert-Prerequisites {
    $server = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
    if ($server -notmatch '^\d') {
        throw 'Docker engine is not responding. Start Docker Desktop and retry.'
    }
    $clusters = & kind get clusters 2>$null | Out-String
    if ($clusters -notmatch [regex]::Escape($ClusterName)) {
        throw "kind cluster '$ClusterName' not found. Run bootstrap.ps1 first."
    }
}

Assert-Prerequisites

$exists = & docker exec $ControlPlane sh -c "test -f $NodeAuditLog && echo yes || echo no" 2>$null | Out-String
if ($exists.Trim() -ne 'yes') {
    throw "No audit log at $NodeAuditLog inside $ControlPlane. Was the cluster created with the audit config in kind-config.yaml?"
}

Write-Host 'Reading audit log from control plane...' -ForegroundColor Cyan
$raw = & docker exec $ControlPlane cat $NodeAuditLog 2>$null | Out-String

$cutoff = if ($SinceMinutes -gt 0) { (Get-Date).ToUniversalTime().AddMinutes(-$SinceMinutes) } else { [datetime]::MinValue }

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
$total = 0
$exported = 0

try {
    foreach ($line in ($raw -split "`n")) {
        if (-not $line.Trim()) { continue }
        $total++

        $record = $null
        try { $record = $line | ConvertFrom-Json } catch { continue }
        if ($null -eq $record) { continue }

        $ts = [datetime]::MinValue
        if ($record.stageTimestamp) {
            [void][datetime]::TryParse(
                $record.stageTimestamp,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$ts
            )
        }
        if ($ts -lt $cutoff) { continue }

        $authenticated = if ($record.user.username) { $record.user.username } else { 'unknown' }
        $impersonated = if ($record.impersonatedUser.username) { $record.impersonatedUser.username } else { $null }

        $event = [ordered]@{
            timestamp           = if ($ts -gt [datetime]::MinValue) { $ts.ToString('o') } else { $null }
            verb                = $record.verb
            authenticatedUser   = $authenticated
            impersonatedUser    = $impersonated
            effectiveIdentity   = if ($impersonated) { $impersonated } else { $authenticated }
            impersonated        = [bool]$impersonated
            groups              = @($record.user.groups)
            namespace           = $record.objectRef.namespace
            resource            = $record.objectRef.resource
            subresource         = $record.objectRef.subresource
            name                = $record.objectRef.name
            apiVersion          = $record.objectRef.apiVersion
            decision            = $record.annotations.'authorization.k8s.io/decision'
            decisionReason      = $record.annotations.'authorization.k8s.io/reason'
            sourceIP            = @($record.sourceIPs) -join ','
            userAgent           = $record.userAgent
            stage               = $record.stage
        }

        $writer.WriteLine(($event | ConvertTo-Json -Compress -Depth 5))
        $exported++
    }
}
finally {
    $writer.Dispose()
}

Write-Host ''
Write-Host "Records read   : $total" -ForegroundColor Gray
Write-Host "Records exported: $exported" -ForegroundColor Green
Write-Host "Output          : $OutputPath" -ForegroundColor Cyan

if ($SinceMinutes -gt 0 -and $exported -eq 0) {
    Write-Host ''
    Write-Warning "No records in the last $SinceMinutes minute(s). Generate some activity first, or omit -SinceMinutes."
}
