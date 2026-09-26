#Requires -Version 5.1
<#
.SYNOPSIS
    Collects runtime telemetry: who ran a command in a container, who minted a
    service account token, and what identity each workload actually runs as.

.DESCRIPTION
    The lab has no eBPF and no runtime security agent. Kubernetes' own audit log
    is the runtime record, and it turns out to carry more than the usual
    "someone called the API" -- at Metadata level the full requestURI is logged,
    which for a pod exec includes the command:

        /api/v1/namespaces/zerotrust-observe/pods/telemetry-agent-.../exec
          ?command=sh&command=-s&command=--&container=agent&stderr=true...

    So this is not "an exec happened", it is "these arguments were passed to a
    shell inside this pod, by this identity, from this address". That is the
    difference between a log line and a detection, and it is available without
    raising the policy above Metadata.

    What is NOT here, and is not claimed: what the command then did. The audit
    log records the request, not its consequences. A `cat` of a token file and a
    `cat` of /dev/null are the same event here.

    Three event schemas
    -------------------
      runtime/container-exec/v1    pods/exec, pods/attach, pods/portforward
      runtime/token-request/v1    serviceaccounts/token creates
      runtime/pod-log-read/v1     pods/log reads
      runtime/workload-identity/v1 the join table: pod -> image, SA, zone

    One audit event is two log lines
    --------------------------------
    Every exec session is logged TWICE, once at stage ResponseStarted and once
    at ResponseComplete, under one shared auditID. Measured on this cluster:
    1294 exec lines, 647 distinct auditIDs, every one of them with both stages.

    Counting lines would report exactly twice as many exec sessions as actually
    happened. This script keys on auditID and emits one event per session, which
    is the only number a threshold can be set against.

    Granted is distinguishable from refused
    ---------------------------------------
    A session that established the SPDY stream carries responseStatus 101; one
    that RBAC refused carries 403. The lab's entire premise is that most things
    are refused, so a collector that did not separate the two would spend most of
    its output describing attacks that never started.

    Node-attested token requests are the baseline, not the signal
    -------------------------------------------------------------
    Every kubelet mints a token for each pod it runs, so serviceaccounts/token is
    legitimately busy. 135 such requests here, the largest single group being
    coredns requested by system:node:soc-lab-control-plane. A token request is
    only interesting when the requester is not the node the pod runs on, so that
    distinction is computed here and carried on the event.

.PARAMETER AuditLogPath
    Path to the audit log on the control-plane node.
    Defaults to /var/log/kubernetes/audit/audit.log

.PARAMETER FromFile
    Read an already-exported audit JSONL instead of the live cluster. Used to
    re-derive telemetry from an export without needing the cluster up.

.PARAMETER SinceMinutes
    Only emit sessions newer than this many minutes. Unbounded by default,
    because a truncated window that is not labelled is indistinguishable from a
    quiet cluster.

.EXAMPLE
    .\collect-runtime.ps1

.EXAMPLE
    .\collect-runtime.ps1 -FromFile .telemetry\audit-events.jsonl
#>

[CmdletBinding()]
param(
    [string]$ClusterName = 'soc-lab',
    [string]$AuditLogPath = '/var/log/kubernetes/audit/audit.log',
    [string]$FromFile,
    [string]$OutputPath,
    [int]$SinceMinutes = 0
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot '.telemetry\runtime-events.jsonl' }

# A missing key is a fact about the object, not an error. At Metadata level the
# audit log omits impersonatedUser, user.impersonatedUser, requestObject and
# responseObject entirely, so a bare $e.user.impersonatedUser throws under
# StrictMode on every single line.
function Get-PropOrNull {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

# ------------------------------------------------------------------ #
# ATT&CK mappings used by this collector.
#
# These are candidate techniques attached to an event class, NOT detections.
# Nothing here fires, alerts, or decides anything. Deciding whether an event
# is an attack is Phase 7, and a rule that claims otherwise is a rule nobody
# has tested. Each entry states why the mapping was chosen so a reader can
# disagree with it.
# ------------------------------------------------------------------ #
$ExecTechniques = @(
    [pscustomobject]@{
        id = 'T1609.001'
        name = 'Container Administration Command'
        why = 'an API client established an interactive command session inside a running container'
        mappingBasis = 'direct: the audit log records the exec subresource request and the command arguments'
    }
    [pscustomobject]@{
        id = 'T1090.001'
        name = 'Proxy: Internal Proxy'
        why = 'recorded for portforward only, where the client asked the API server to relay traffic to a pod it cannot otherwise route to'
        mappingBasis = 'judgement: ATT&CK has no Kubernetes-specific portforward technique, and relaying through a trusted component is closest to an internal proxy'
    }
)

$TokenTechniques = @(
    [pscustomobject]@{
        id = 'T1528'
        name = 'Steal Application Access Token'
        why = 'a token was minted for a service account by a requester outside the measured baseline: either not the node that runs the pod, or acting under an impersonated identity that is not who the token will be judged by'
        mappingBasis = 'judgement: minting a token is not theft, but an acquisition of a credential the requester was not scheduled to hold. Flagged, not called an attack'
    }
)

$LogReadTechniques = @(
    [pscustomobject]@{
        id = 'T1552.001'
        name = 'Unsecured Credentials: Credentials In Files'
        why = 'container stdout was read through the API, and application logs are a common place for credentials to have been written'
        mappingBasis = 'weak: this records that logs were read, not that anything was found in them. Listed so the surface is visible, not because a log read is credential theft'
    }
)

# The three trust zones this lab is about. Anything outside them is cluster
# plumbing, and an event about kube-system is context rather than lab activity.
$LabZones = @('zerotrust', 'zerotrust-build', 'zerotrust-observe')

# ------------------------------------------------------------------ #
# Reading the audit log
# ------------------------------------------------------------------ #

function Get-AuditLines {
    if ($FromFile) {
        if (-not (Test-Path -LiteralPath $FromFile)) { throw "audit export not found: $FromFile" }
        Write-Host "  source: $FromFile" -ForegroundColor DarkGray
        return @(Get-Content -LiteralPath $FromFile)
    }

    $server = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
    if ($server -notmatch '^\d') { throw 'Docker engine is not responding. Start Docker Desktop and retry.' }
    $cp = "$ClusterName-control-plane"
    & docker inspect $cp *> $null
    if ($LASTEXITCODE -ne 0) { throw "control-plane container '$cp' not found. Run bootstrap.ps1 first." }

    # Prefilter on the node rather than pulling 50 MB across the boundary.
    # Quote-free: PowerShell strips embedded double quotes before a native
    # executable sees them, so the pattern is a bare word.
    Write-Host ("  source: docker exec {0} grep subresource {1}" -f $cp, $AuditLogPath) -ForegroundColor DarkGray
    $out = & docker exec $cp sh -c "grep subresource $AuditLogPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errTxt = ($out | Out-String).Trim()
        throw "could not read $AuditLogPath from $cp : $errTxt"
    }
    return @($out)
}

# ------------------------------------------------------------------ #
# requestURI -> structured exec request
#
# kubectl encodes each argv element as a repeated command= parameter, so
#   ?command=sh&command=-s&command=--&container=agent
# is argv = [sh, -s, --] against container "agent".
#
# Values are redacted before they are written. A command line can legitimately
# contain a password passed with -p, and a telemetry file that quietly accumulates
# credentials is a liability even in a gitignored directory.
# ------------------------------------------------------------------ #

$SecretishQueryKeys = '^(token|password|passwd|secret|apikey|api_key|authorization|bearer)$'

function Get-RedactedValue {
    param([string] $Value)
    if ($Value -match 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}') {
        return 'REDACTED-jwt'
    }
    if ($Value -match '^[A-Za-z0-9_\-]{40,}$') { return 'REDACTED-long-opaque-token' }
    return $Value
}

function ConvertFrom-RequestUri {
    param([string] $Uri)

    $result = [pscustomobject]@{
        path        = $null
        command     = @()
        container   = $null
        stdin       = $null
        stdout      = $null
        stderr      = $null
        tty         = $null
        ports       = @()
        redactedKeys = @()
    }
    if (-not $Uri) { return $result }

    $q = $Uri
    $qi = $q.IndexOf('?')
    if ($qi -ge 0) {
        $result.path = $q.Substring(0, $qi)
        $q = $q.Substring($qi + 1)
    }
    else { $result.path = $q }

    $fragment = $q.IndexOf('#')
    if ($fragment -ge 0) { $q = $q.Substring(0, $fragment) }

    foreach ($pair in ($q -split '&')) {
        if (-not $pair) { continue }
        $eq = $pair.IndexOf('=')
        if ($eq -lt 0) {
            $kRaw = $pair -replace '\+', ' '
            $k = [uri]::UnescapeDataString($kRaw)
            switch ($k) {
                'stdin' { $result.stdin = $true }
                'stdout' { $result.stdout = $true }
                'stderr' { $result.stderr = $true }
                'tty' { $result.tty = $true }
            }
            continue
        }
        $kRaw = $pair.Substring(0, $eq) -replace '\+', ' '
        $vRaw = $pair.Substring($eq + 1) -replace '\+', ' '
        $k = [uri]::UnescapeDataString($kRaw)
        # kubectl percent-encodes everything except space, which it writes as a
        # literal '+' (verified: 0x2B in the raw query). UnescapeDataString
        # leaves '+' alone, so it has to be turned into a space BEFORE decoding
        # or the command comes out as "cat+/var/run/secrets/..." -- unreadable,
        # and un-greppable for the exact string a detection would look for.
        $v = [uri]::UnescapeDataString($vRaw)
        switch ($k) {
            'command' { $result.command += (Get-RedactedValue $v) }
            'container' { $result.container = $v }
            'ports' { $result.ports += $v }
            default {
                if ($k -match $SecretishQueryKeys) {
                    $result.redactedKeys += $k
                    switch ($k) {
                        'stdin' { $result.stdin = $true }
                        'stdout' { $result.stdout = $true }
                        'stderr' { $result.stderr = $true }
                    }
                }
            }
        }
    }
    return $result
}

# ------------------------------------------------------------------ #
# Workload identity: the join table every other event resolves against.
#
# Built from the API rather than from the manifests, because a manifest says
# what was requested and the API says what is running. If a pod was started with
# a different image than the YAML claims, only one of those is evidence.
# ------------------------------------------------------------------ #

function Get-WorkloadIdentity {
    $raw = (& kubectl get pods -A -o json 2>$null | Out-String)
    if (-not $raw.Trim()) { throw 'kubectl returned no pods; refusing to emit telemetry with no identity table.' }
    $list = $raw | ConvertFrom-Json

    $out = @()
    foreach ($p in $list.items) {
        $meta = $p.metadata
        $podLabels = $meta.labels
        $nsLabels = (& kubectl get namespace $meta.namespace -o json 2>$null | Out-String) | ConvertFrom-Json
        $zone = Get-PropOrNull $nsLabels.metadata.labels 'zerotrust.lab/zone'
        if (-not $zone) { $zone = $meta.namespace }

        foreach ($c in @($p.spec.containers)) {
            if ($null -eq $c) { continue }
            # Most containers in this cluster set no securityContext at all, and
            # under StrictMode a bare $c.securityContext throws on the first one.
            $sc = Get-PropOrNull $c 'securityContext'
            $status = @($p.status.containerStatuses | Where-Object { $_.name -eq $c.name })
            $st = if ($status.Count -gt 0) { $status[0] } else { $null }
            $lastTerm = Get-PropOrNull (Get-PropOrNull $st 'lastState') 'terminated'

            # The spec asks for a digest-pinned image; the status reports the
            # digest actually running. Comparing the two is an integrity check
            # that costs nothing here and would catch a substituted image.
            #
            # A null "matches" is not the same as a false one, so the reason is
            # carried with it: a spec that names a tag instead of a digest has
            # nothing to compare against, and reporting that as inconclusive is
            # different from reporting it as a substitution.
            $wantDigest = $null
            if ($c.image -match '@(sha256:[0-9a-f]{64})$') { $wantDigest = $Matches[1] }
            $runDigest = $null
            $imageId = Get-PropOrNull $st 'imageID'
            if ($imageId -match '@(sha256:[0-9a-f]{64})$') { $runDigest = $Matches[1] }
            $digestMatch = $null
            $digestWhy = $null
            if ($wantDigest -and $runDigest) {
                $digestMatch = ($wantDigest -eq $runDigest)
                $digestWhy = if ($digestMatch) { 'spec digest equals the digest reported by the container runtime' }
                             else { 'SPEC DIGEST DIFFERS FROM THE RUNNING DIGEST' }
            }
            elseif (-not $wantDigest -and -not $runDigest) { $digestWhy = 'no digest in the spec and none reported by the runtime; nothing to compare' }
            elseif (-not $wantDigest) { $digestWhy = 'the spec names a tag rather than a digest, so the requested image is not pinned and cannot be compared' }
            else { $digestWhy = 'the runtime reported a digest but the spec did not pin one' }

            $out += [pscustomobject]@{
                schema        = 'runtime/workload-identity/v1'
                collectedAt   = $null
                namespace     = $meta.namespace
                zone          = $zone
                pod           = $meta.name
                podUid        = Get-PropOrNull $meta 'uid'
                app           = Get-PropOrNull $podLabels 'app'
                container     = $c.name
                serviceAccount = Get-PropOrNull $p.spec 'serviceAccountName' 'default'

                # The image the spec asked for, which in this lab is digest
                # pinned, and the image actually running. Divergence between
                # the two is worth a detection of its own.
                image         = $c.image
                imageId       = $imageId
                imageIntegrity = [pscustomobject]@{
                    requestedDigest = $wantDigest
                    runningDigest   = $runDigest
                    comparable      = ($null -ne $digestMatch)
                    matches         = $digestMatch
                    reason          = $digestWhy
                }
                phase         = Get-PropOrNull $p.status 'phase'
                node          = Get-PropOrNull $p.spec 'nodeName'
                podIp         = Get-PropOrNull $p.status 'podIP'
                restartCount  = Get-PropOrNull $st 'restartCount' 0
                lastExitCode  = Get-PropOrNull $lastTerm 'exitCode'
                lastReason    = Get-PropOrNull $lastTerm 'reason'

                securityContext = [pscustomobject]@{
                    runAsNonRoot             = Get-PropOrNull $sc 'runAsNonRoot'
                    privileged               = Get-PropOrNull $sc 'privileged'
                    allowPrivilegeEscalation = Get-PropOrNull $sc 'allowPrivilegeEscalation'
                    readOnlyRootFilesystem   = Get-PropOrNull $sc 'readOnlyRootFilesystem'
                    runAsUser                = Get-PropOrNull $sc 'runAsUser'
                }

                resolution    = 'read from the API, not from the manifests; describes what is running, not what was requested'
                note          = 'identity table, not a finding. It is the thing other events are resolved against.'
                candidateTechniques = @()
            }
        }
    }
    return $out
}

# ------------------------------------------------------------------ #

Write-Host 'Reading audit log...' -ForegroundColor Cyan
$auditLines = Get-AuditLines
Write-Host ("  {0} candidate lines" -f $auditLines.Count)

Write-Host 'Resolving workload identities from the API...' -ForegroundColor Cyan
$identities = Get-WorkloadIdentity
$byPod = @{}
foreach ($i in $identities) { $byPod["$($i.namespace)/$($i.pod)"] = $i }
Write-Host ("  {0} containers across {1} pods" -f $identities.Count, $byPod.Count)

$collectedAt = (Get-Date).ToUniversalTime().ToString('o')
foreach ($i in $identities) { $i.collectedAt = $collectedAt }

# ------------------------------------------------------------------ #
# Fold the audit log into events.
#
# Grouping by auditID is the load-bearing step, not a tidy-up: it is the
# difference between 647 sessions and 1294 lines.
# ------------------------------------------------------------------ #

$cutoff = $null
if ($SinceMinutes -gt 0) { $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$SinceMinutes) }

$events = @()
$execEvents = @()
$tokenEvents = @()
$logEvents = @()

$sessionGroups = @{}
$tokenRows = @()
$logRows = @()

# Two shapes of audit record reach this script, and they do not nest the same way.
#
#   raw log line  : user.username, objectRef.namespace, stageTimestamp,
#                   responseStatus.code, sourceIPs[]
#   exported line : authenticatedUser, namespace, timestamp, sourceIP
#                   (the flat record written by telemetry/audit/export-audit-log.ps1)
#
# Reading only the raw shape works right up until someone re-derives telemetry
# from an export with no cluster running, which is the documented -FromFile path.
# Then every line throws on objectRef under StrictMode and the run dies on the
# first record having produced nothing at all -- a failure that looks like an
# empty cluster rather than a schema mismatch.
#
# The export also drops responseStatus, so `granted` cannot be derived from it.
# That is reported as unknown rather than guessed, because "this session was
# refused" and "this source cannot tell me" must not collapse into the same null.
function ConvertTo-NormalizedAudit {
    param($E)
    if ($null -eq $E) { return $null }

    $isRaw = ($null -ne $E.PSObject.Properties['objectRef'])
    $ref = if ($isRaw) { $E.objectRef } else { $null }
    $user = if ($isRaw) { Get-PropOrNull $E 'user' } else { $null }

    $authUser = if ($isRaw) { Get-PropOrNull $user 'username' } else { Get-PropOrNull $E 'authenticatedUser' }
    $impUser = if ($isRaw) { Get-PropOrNull $user 'impersonatedUser' } else { Get-PropOrNull $E 'impersonatedUser' }
    $groups = if ($isRaw) { @(Get-PropOrNull $user 'groups' @()) } else { @(Get-PropOrNull $E 'groups' @()) }
    $impGroups = if ($isRaw) { @(Get-PropOrNull $user 'impersonatedGroups' @()) } else { @(Get-PropOrNull $E 'impersonatedGroups' @()) }

    $sourceIPs = @()
    if ($isRaw) { $sourceIPs = @(Get-PropOrNull $E 'sourceIPs' @()) }
    else {
        $single = Get-PropOrNull $E 'sourceIP'
        if ($single) { $sourceIPs = @($single) }
    }

    $ts = $null
    if ($isRaw) {
        $ts = Get-PropOrNull $E 'stageTimestamp'
        if (-not $ts) { $ts = Get-PropOrNull $E 'requestReceivedTimestamp' }
    }
    else { $ts = Get-PropOrNull $E 'timestamp' }

    $code = $null
    if ($isRaw) { $code = Get-PropOrNull (Get-PropOrNull $E 'responseStatus') 'code' }
    else { $code = Get-PropOrNull $E 'responseCode' }

    # Whether this source records an outcome at all, judged by whether the field
    # is present rather than by whether it happens to be populated. An export
    # written before responseCode was added has no such key, and reporting its
    # sessions as "granted: null" for that reason is correct -- the difference
    # between "refused" and "this source cannot say" has to survive.
    $codeAvailable = if ($isRaw) { $true } else { ($null -ne $E.PSObject.Properties['responseCode']) }

    return [pscustomobject]@{
        isRaw             = $isRaw
        namespace         = if ($isRaw) { Get-PropOrNull $ref 'namespace' } else { Get-PropOrNull $E 'namespace' }
        name              = if ($isRaw) { Get-PropOrNull $ref 'name' } else { Get-PropOrNull $E 'name' }
        resource          = if ($isRaw) { Get-PropOrNull $ref 'resource' } else { Get-PropOrNull $E 'resource' }
        subresource       = if ($isRaw) { Get-PropOrNull $ref 'subresource' } else { Get-PropOrNull $E 'subresource' }
        authenticatedUser = $authUser
        impersonatedUser  = $impUser
        # Identity is the impersonated user when there is one. A rule that
        # matches authenticatedUser alone misses every escalation performed by
        # impersonating someone with more privilege.
        effectiveIdentity = if ($impUser) { $impUser } else { $authUser }
        impersonated      = [bool]$impUser
        groups            = $groups
        impersonatedGroups = $impGroups
        sourceIPs         = $sourceIPs
        userAgent         = Get-PropOrNull $E 'userAgent'
        stage             = Get-PropOrNull $E 'stage'
        code              = $code
        # False means the source did not record an outcome, not that the
        # request failed.
        codeAvailable     = $codeAvailable
        timestamp         = $ts
        auditId           = Get-PropOrNull $E 'auditID'
        requestURI        = Get-PropOrNull $E 'requestURI'
    }
}

foreach ($line in $auditLines) {
    $e = $null
    try { $e = $line | ConvertFrom-Json } catch { continue }
    $n = ConvertTo-NormalizedAudit $e
    if ($null -eq $n) { continue }

    $ref = [pscustomobject]@{
        namespace   = $n.namespace
        name        = $n.name
        resource    = $n.resource
        subresource = $n.subresource
    }
    $sub = $n.subresource
    $ts = $n.timestamp
    $tsDt = [datetime]::MinValue
    if ($ts) { [void][datetime]::TryParse($ts, [ref]$tsDt) }
    if ($cutoff -and $tsDt -lt $cutoff) { continue }

    $authUser = $n.authenticatedUser
    $impUser = $n.impersonatedUser
    $groups = $n.groups
    $impGroups = $n.impersonatedGroups
    $effective = $n.effectiveIdentity
    $impersonated = $n.impersonated

    $stage = $n.stage
    $code = $n.code
    $uri = $n.requestURI
    $auditId = $n.auditId

    if ($sub -eq 'exec' -or $sub -eq 'attach' -or $sub -eq 'portforward') {
        $gkey = $auditId
        if (-not $gkey) { $gkey = "$ts|$uri" }
        if (-not $sessionGroups.ContainsKey($gkey)) {
            $sessionGroups[$gkey] = @{
                auditId = $auditId; uri = $uri; subresource = $sub
                objectRef = $ref
                effectiveIdentity = $effective; impersonated = $impersonated
                groups = $groups; impersonatedGroups = $impGroups
                authenticatedUser = $authUser; impersonatedUser = $impUser
                sourceIPs = $n.sourceIPs
                userAgent = $n.userAgent
                firstSeen = $ts; stages = @(); codes = @(); codeAvailable = $n.codeAvailable
            }
        }
        $g = $sessionGroups[$gkey]
        $g.stages += $stage
        $g.codes += $code
    }
    elseif ($sub -eq 'token' -and $ref.resource -eq 'serviceaccounts') {
        $tokenRows += [pscustomobject]@{
            auditId = $auditId; timestamp = $ts; stage = $stage
            namespace = $ref.namespace
            serviceAccount = $ref.name
            effectiveIdentity = $effective; impersonated = $impersonated
            authenticatedUser = $authUser; impersonatedUser = $impUser
            groups = $groups
            sourceIPs = $n.sourceIPs
            userAgent = $n.userAgent
            code = $code
        }
    }
    elseif ($sub -eq 'log' -and $ref.resource -eq 'pods') {
        # The container is a query parameter, not part of objectRef, so it has to
        # come out of the URI the same way an exec command does.
        $lq = ConvertFrom-RequestUri $uri
        $logRows += [pscustomobject]@{
            auditId = $auditId; timestamp = $ts; stage = $stage
            namespace = $ref.namespace
            pod = $ref.name
            container = $lq.container
            effectiveIdentity = $effective; impersonated = $impersonated
            authenticatedUser = $authUser; impersonatedUser = $impUser
            groups = $groups
            sourceIPs = $n.sourceIPs
            userAgent = $n.userAgent
            code = $code
        }
    }
}

# ------------------------------------------------------------------ #
# container exec sessions
# ------------------------------------------------------------------ #

foreach ($g in $sessionGroups.Values) {
    $rq = ConvertFrom-RequestUri $g.uri
    $podKey = "$($g.objectRef.namespace)/$($g.objectRef.name)"
    $ident = $null
    if ($byPod.ContainsKey($podKey)) { $ident = $byPod[$podKey] }

    # 101 Switching Protocols means the stream was established. 403 means RBAC
    # refused it and no command ever ran. Collapsing the two would describe
    # every blocked attempt as a successful intrusion.
    #
    # A normalized export carries no responseStatus at all, so $granted stays
    # null there. Null means "this source does not say", which is not the same
    # claim as $false, and a Phase 7 rule that treats them alike would report
    # every session derived from an export as refused.
    $granted = $null
    $outcome = $null
    $codes = @($g.codes | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    if ($g.codeAvailable) {
        $granted = $false
        foreach ($c in $g.codes) { if ($c -eq 101 -or $c -eq 200) { $granted = $true } }
        $outcome = if ($granted) { 'session established; the command ran' }
                   elseif ($codes -contains 403) { 'refused by RBAC; no command ran' }
                   else { 'no 101 and no 403; outcome not determined from this log' }
    }
    else {
        $outcome = 'outcome unknown: this source does not record responseStatus. Re-run against the live audit log to learn whether the session was granted.'
    }

    $techs = @($ExecTechniques | Where-Object {
        if ($_.id -eq 'T1609.001') { $g.subresource -ne 'portforward' } else { $g.subresource -eq 'portforward' }
    })

    $execEvents += [pscustomobject]@{
        schema        = 'runtime/container-exec/v1'
        collectedAt   = $collectedAt
        auditId       = $g.auditId
        firstSeen     = $g.firstSeen
        auditStages   = @($g.stages)
        auditLines    = $g.stages.Count

        subresource   = $g.subresource
        target        = [pscustomobject]@{
            namespace = Get-PropOrNull $g.objectRef 'namespace'
            pod       = Get-PropOrNull $g.objectRef 'name'
            container = $rq.container
            resolved  = $ident
        }

        # The reason this collector is worth having. At Metadata level the
        # requestURI still carries every argv element.
        command       = @($rq.command)
        commandLine   = ($rq.command -join ' ')
        interactive   = [bool]($rq.stdin -and $rq.stdout)
        tty           = $rq.tty
        redactedQueryKeys = @($rq.redactedKeys)

        identity      = [pscustomobject]@{
            effectiveIdentity = $g.effectiveIdentity
            authenticatedUser = $g.authenticatedUser
            impersonatedUser  = $g.impersonatedUser
            impersonated      = $g.impersonated
            groups            = @($g.groups)
            impersonatedGroups = @($g.impersonatedGroups)
        }
        sourceIPs     = @($g.sourceIPs)
        userAgent     = $g.userAgent

        granted       = $granted
        outcomeKnown  = $g.codeAvailable
        responseCodes = $codes
        outcome       = $outcome

        resolution    = 'the audit log records the exec request and its arguments, not what the command did. A read of a credential file and a read of /dev/null are the same event here.'
        candidateTechniques = $techs
        note          = 'candidate technique, not a detection. Firing is Phase 7.'
    }
}

# ------------------------------------------------------------------ #
# token requests
# ------------------------------------------------------------------ #

$podNode = @{}
foreach ($i in $identities) { if (-not $podNode.ContainsKey("$($i.namespace)/$($i.pod)")) { $podNode["$($i.namespace)/$($i.pod)"] = $i.node } }

# The baseline for token minting is not one prefix, it is three kinds of caller,
# and all three are busy in a healthy cluster. Measured on this lab: 135 token
# requests, every one of them from system:kube-controller-manager (57) or a
# system:node:* kubelet (78). A rule that called all 135 unusual would be wrong
# 135 times, and an analyst who learns that stops reading the field.
#
# So the event carries a class, and only 'other' is left for a human.
function Get-RequesterClass {
    param([string] $Identity, $Impersonated)
    if ($Impersonated) { return 'impersonated' }
    if ($Identity -match '^system:node:') { return 'kubelet' }
    if ($Identity -match '^system:serviceaccount:kube-system:') { return 'control-plane-component' }
    if ($Identity -match '^system:(kube-controller-manager|kube-scheduler|kube-proxy|apiserver|controller)$') { return 'control-plane-component' }
    return 'other'
}

foreach ($t in $tokenRows) {
    $requester = $t.effectiveIdentity
    $class = Get-RequesterClass -Identity $requester -Impersonated $t.impersonated
    # The two classes outside the measured baseline. Everything else is the
    # cluster doing its job, and is left untagged on purpose.
    $isOffBaseline = ($class -eq 'other' -or $class -eq 'impersonated')
    $attestedNode = $null
    if ($requester -match '^system:node:(.+)$') { $attestedNode = $Matches[1] }
    $podsOnNode = @()
    if ($attestedNode) {
        $podsOnNode = @($identities | Where-Object { $_.node -eq $attestedNode -and $_.serviceAccount -eq $t.serviceAccount -and $_.namespace -eq $t.namespace } | ForEach-Object { "$($_.namespace)/$($_.pod)" })
    }

    $interpretation = switch ($class) {
        'kubelet' { 'kubelet minting a token for a pod it runs; the expected baseline' }
        'control-plane-component' { 'a control plane component minting a token for one of its own service accounts; the expected baseline' }
        'impersonated' { 'requested under an impersonated identity, so the requester is not the identity the token will be judged by' }
        default { 'a token was requested for this service account by a caller that is neither a kubelet nor a control plane component. Worth a human look; not proof of anything on its own' }
    }

    # Computed here and forced to a typed array. See the matching comment in
    # telemetry\network\collect-network.ps1: PowerShell 5.1's ConvertTo-Json
    # unwraps a 0- or 1-element array arriving from an if-expression, so an
    # inline assignment here serialised all 151 untagged token requests as
    # "candidateTechniques":{} instead of []. @() normalises, [object[]] is what
    # survives the serialiser.
    $taggedTechs = if ($isOffBaseline) { $TokenTechniques } else { @() }
    $taggedTechs = [object[]]@($taggedTechs)

    $events += [pscustomobject]@{
        schema        = 'runtime/token-request/v1'
        collectedAt   = $collectedAt
        auditId       = $t.auditId
        timestamp     = $t.timestamp
        stage         = $t.stage

        namespace     = $t.namespace
        serviceAccount = $t.serviceAccount
        isLabServiceAccount = ($LabZones -contains $t.namespace)

        identity      = [pscustomobject]@{
            effectiveIdentity = $t.effectiveIdentity
            authenticatedUser = $t.authenticatedUser
            impersonatedUser  = $t.impersonatedUser
            impersonated      = $t.impersonated
        }
        sourceIPs     = @($t.sourceIPs)
        userAgent     = $t.userAgent
        responseCode  = $t.code

        # kubelet | control-plane-component | impersonated | other
        # Only 'other' is outside the measured baseline of a healthy cluster.
        requesterClass = $class
        attestedNode  = $attestedNode
        labPodsMatchingThisSaOnThatNode = $podsOnNode
        interpretation = $interpretation

        resolution    = 'the request is logged; the token value is never in the audit log, so a token minted here cannot be read back from this source'

        # Tagged only where the rationale above actually holds.
        #
        # Measured: 135 token requests, 78 kubelet and 57 control-plane-component,
        # 0 off-baseline. Tagging all 135 would put a T1528 candidate on every
        # event, including 78 whose own requesterClass is 'kubelet' -- the node
        # that *does* run the pod, which is the exact opposite of the stated
        # rationale. A tag whose condition its own data refutes is a false
        # positive waiting to be inherited by Phase 7, so the tag is emitted
        # only for 'other' and 'impersonated', and the untagged case says why.
        candidateTechniques = $taggedTechs
        note          = if ($isOffBaseline) {
                             'candidate technique, not a detection. Firing is Phase 7.'
                         }
                         else {
                             ('no candidate technique: requesterClass is {0}, which is on the measured baseline of a healthy cluster. Minting a token is not theft, and this is what the kubelet and the control plane are supposed to do' -f $class)
                         }
    }
}

# ------------------------------------------------------------------ #
# pod log reads
# ------------------------------------------------------------------ #

foreach ($l in $logRows) {
    $podKey = "$($l.namespace)/$($l.pod)"
    $ident = $null
    if ($byPod.ContainsKey($podKey)) { $ident = $byPod[$podKey] }
    $events += [pscustomobject]@{
        schema        = 'runtime/pod-log-read/v1'
        collectedAt   = $collectedAt
        auditId       = $l.auditId
        timestamp     = $l.timestamp
        stage         = $l.stage
        namespace     = $l.namespace
        pod           = $l.pod
        resolvedWorkload = $ident
        identity      = [pscustomobject]@{
            effectiveIdentity = $l.effectiveIdentity
            authenticatedUser = $l.authenticatedUser
            impersonatedUser  = $l.impersonatedUser
            impersonated      = $l.impersonated
        }
        sourceIPs     = @($l.sourceIPs)
        userAgent     = $l.userAgent
        responseCode  = $l.code
        resolution    = 'records that logs were read. The log contents are not in the audit log, so what was learned is not observable here.'
        candidateTechniques = $LogReadTechniques
        note          = 'candidate technique, not a detection.'
    }
}

$events += $execEvents
$events += $identities

# ------------------------------------------------------------------ #

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
try { foreach ($e in $events) { $writer.WriteLine(($e | ConvertTo-Json -Compress -Depth 7)) } }
finally { $writer.Dispose() }

$grantedS = @($execEvents | Where-Object { $_.granted -eq $true })
$refusedS = @($execEvents | Where-Object { $_.granted -eq $false })
$unknownS = @($execEvents | Where-Object { $null -eq $_.granted })
$bySub = @{}
foreach ($e in $execEvents) { $bySub[$e.subresource] = 1 + $(if ($bySub.ContainsKey($e.subresource)) { $bySub[$e.subresource] } else { 0 }) }
$nodeTok = @($events | Where-Object { $_.schema -eq 'runtime/token-request/v1' -and $_.requesterClass -eq 'kubelet' })
$tokEvents = @($events | Where-Object { $_.schema -eq 'runtime/token-request/v1' })
$byClass = @{}
foreach ($t in $tokEvents) { $byClass[$t.requesterClass] = 1 + $(if ($byClass.ContainsKey($t.requesterClass)) { $byClass[$t.requesterClass] } else { 0 }) }
$offBaseline = @($tokEvents | Where-Object { $_.requesterClass -eq 'other' -or $_.requesterClass -eq 'impersonated' })
$imp = @($execEvents | Where-Object { $_.identity.impersonated })
$auditLinesFolded = @($execEvents | ForEach-Object { $_.auditLines } | Measure-Object -Sum).Sum

Write-Host ''
Write-Host "Audit lines read     : $($auditLines.Count)"
Write-Host ("Exec sessions        : {0}  (folded from {1} audit lines by auditID)" -f $execEvents.Count, $auditLinesFolded)
foreach ($k in ($bySub.Keys | Sort-Object)) { Write-Host ("  {0,-14} {1}" -f $k, $bySub[$k]) }
Write-Host ("  granted {0}, refused {1}, outcome unknown {2}" -f $grantedS.Count, $refusedS.Count, $unknownS.Count)
if ($unknownS.Count -gt 0) {
    Write-Host ("    {0} session(s) have no recorded outcome. This source does not carry" -f $unknownS.Count) -ForegroundColor DarkYellow
    Write-Host '    responseStatus, so they are neither granted nor refused here.' -ForegroundColor DarkYellow
}
Write-Host ("  identities         : {0}" -f ((@($execEvents | ForEach-Object { $_.identity.effectiveIdentity } | Sort-Object -Unique)) -join ', '))
if ($imp.Count -gt 0) { Write-Host ("  impersonated        : {0}" -f $imp.Count) -ForegroundColor Yellow }
Write-Host ("Token requests       : {0}" -f $tokEvents.Count)
foreach ($k in ($byClass.Keys | Sort-Object)) { Write-Host ("  {0,-26} {1}" -f $k, $byClass[$k]) }
Write-Host ("Pod log reads        : $($logRows.Count)")
Write-Host ("Workload identities  : $($identities.Count)")
Write-Host "Output               : $OutputPath"
if ($SinceMinutes -gt 0) { Write-Host "Window               : last $SinceMinutes minute(s)" -ForegroundColor DarkGray }

if ($offBaseline.Count -gt 0) {
    Write-Host ''
    Write-Host 'Token requests outside the measured baseline:' -ForegroundColor Cyan
    foreach ($t in $offBaseline) {
        Write-Host ("  {0}/{1} by {2} ({3}) from {4}" -f $t.namespace, $t.serviceAccount, $t.identity.effectiveIdentity, $t.requesterClass, ($t.sourceIPs -join ','))
    }
}
else {
    Write-Host ''
    Write-Host 'Token requests outside the measured baseline: 0' -ForegroundColor DarkGray
}

# The commands are the reason this collector exists, so show what was actually
# run rather than only how many sessions there were. Grouped, because 647
# sessions of the same three commands is a different fact from 647 of them.
$cmds = @($execEvents | Group-Object commandLine | Sort-Object Count -Descending)
Write-Host ''
Write-Host ("Distinct command lines: {0} across {1} sessions" -f $cmds.Count, $execEvents.Count) -ForegroundColor Cyan
foreach ($c in ($cmds | Select-Object -First 10)) {
    $line = $c.Name
    if ($null -eq $line) { $line = '<no command recorded>' }
    if ($line.Length -gt 94) { $line = $line.Substring(0, 91) + '...' }
    Write-Host ("  {0,4}  {1}" -f $c.Count, $line)
}
if ($cmds.Count -gt 10) { Write-Host ("  ... and {0} more" -f ($cmds.Count - 10)) -ForegroundColor DarkGray }
Write-Host ''
