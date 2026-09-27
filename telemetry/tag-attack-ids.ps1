<#
.SYNOPSIS
    Single-source registry of ATT&CK technique mappings, and the checker that
    holds every collected event to it.

.DESCRIPTION
    Phase 5 requires an ATT&CK ID on every attack step, every detection and
    every telemetry rule. Steps and detections are covered by the catalogue and
    by Phase 7. This script covers the third of those: it is the one place that
    says which technique a given telemetry schema is allowed to carry, and it
    fails when a collected event does not match.

    Why a registry and not a tagging pass
    ------------------------------------
    The obvious implementation is a script that walks the events and writes a
    technique onto anything that looks interesting. That was rejected, for two
    reasons that both showed up during measurement.

    First, it has no fixed point. A tag applied by a script that then reads its
    own output proves only that the script ran. Putting the mapping in a
    declared table instead means the mapping can be reviewed, argued with, and
    diffed in a commit, and it means an unmapped event is a failure rather than
    something nobody notices.

    Second, and worse, a pass that tags by pattern tags the lab's own
    instrumentation. Measured: the only cross-zone connections in this cluster
    are the telemetry agent's health probes, and all four carried a T1021
    candidate before this registry existed. All 135 service-account token
    requests carried T1528, including 78 whose own requesterClass was
    'kubelet' -- the node that does run the pod, which is the exact opposite of
    the rationale printed beside the tag. A Phase 7 rule built on either of
    those would have fired on nothing but the lab checking itself, and would
    have looked like it was working.

    So: the mapping lives here, the collectors emit what this file permits, and
    the untagged cases are enumerated explicitly with a reason and a test.

    The exemptions are verified, not trusted
    ----------------------------------------
    An exemption that only checks "the tag is absent" is a hole with a comment
    over it. Every exemption below carries a test evaluated against the event's
    own fields, and an untagged event that fails its exemption test is a
    failure. Concretely: an untagged token request is only acceptable if its
    requesterClass really is on the measured baseline, so if the collector ever
    stops classifying requesters, this fails instead of quietly exempting all
    151 of them.

    Vacuous passes
    --------------
    A coverage check that passes because it examined nothing is worse than no
    check, and that failure has already happened four times in this project
    where a counter that did not move was read as a result. So the script
    refuses to report coverage unless it can show the work happened: both input
    files must exist and parse, every registered schema must have been
    observed at least once, and every schema that is required to carry a
    technique must have at least one event that actually carries one. Each of
    those refusals is a separate exit, not a warning.

    What this does not do
    ---------------------
    It does not decide whether a tag is correct. ATT&CK has no
    Kubernetes-specific exec technique, so T1609.001 is a judgement, and
    T1552.001 is explicitly weak: it records that logs were read, not that
    anything was found in them. Those judgements are recorded in the registry
    with their weakness stated, and reviewing them is a human decision this
    script cannot make.

    It also does not fire anything. A candidate technique is not a detection.
    Phase 7 is where firing is proven, and until then every event in these files
    is a candidate and nothing more.

.PARAMETER NetworkEvents
    Network telemetry JSON Lines. Defaults to .telemetry\network-events.jsonl

.PARAMETER RuntimeEvents
    Runtime telemetry JSON Lines. Defaults to .telemetry\runtime-events.jsonl

.PARAMETER ReportPath
    Coverage report destination, which Phase 7 reads for the exclusions each
    technique requires. Defaults to .telemetry\attack-tag-report.json

.EXAMPLE
    .\tag-attack-ids.ps1

.EXAMPLE
    .\tag-attack-ids.ps1 -ReportPath .telemetry\attack-tag-report.json
#>

[CmdletBinding()]
param(
    [string]$NetworkEvents,
    [string]$RuntimeEvents,
    [string]$ReportPath,
    # Emit just the registry -- schema -> allowed techniques -- as JSON, and stop.
    #
    # This exists because attack/chain-purple-team.ps1 used to keep its own
    # hardcoded copy of "which techniques have a telemetry schema behind them"
    # and check the chain's hops against that. The copy was one schema behind:
    # runtime/object-create/v1 was added, T1078.001 became detectable, and the
    # chain kept printing "NO SCHEMA, NOT DETECTABLE: T1078.001" and writing it
    # into .telemetry/chain-summary.json. Nothing was wrong with the schema and
    # nothing was wrong with the hop; a list of the truth had quietly become a
    # copy of an older truth.
    #
    # This is the same failure the registry itself was written to prevent, one
    # level up: a mapping duplicated in two files is a mapping that will disagree.
    # So the chain reads this file, and there is exactly one place where the set
    # of detectable techniques is written down.
    [string]$EmitRegistryPath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $NetworkEvents) { $NetworkEvents = Join-Path $projectRoot '.telemetry\network-events.jsonl' }
if (-not $RuntimeEvents) { $RuntimeEvents = Join-Path $projectRoot '.telemetry\runtime-events.jsonl' }
if (-not $ReportPath) { $ReportPath = Join-Path $projectRoot '.telemetry\attack-tag-report.json' }

function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('-' * $Text.Length) -ForegroundColor DarkGray
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Returns a real array, never $null, so that .Count is meaningful. Wrapping $null
# in @() yields a one-element array holding null, which is how a filter written
# as "@($x).Count -gt 0" ends up matching everything. The leading comma is also
# load-bearing: a function that "returns" an empty array emits nothing, so the
# caller gets $null instead, and .Count on that throws under Set-StrictMode.
function Get-ArrayOf {
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [string]) { return , @($Value) }
    if ($Value -is [array]) { return , @($Value) }
    return , @($Value)
}

# ---------------------------------------------------------------------------
# The registry. This is the single source of truth for the whole project.
# ---------------------------------------------------------------------------

# Every technique id the lab is allowed to emit, with the name ATT&CK gives it
# and how solid the mapping is. A technique that is not in this table cannot be
# emitted, which is what makes "every event carries a technique" a checkable
# statement rather than a hope.
$KnownTechniques = @(
    [pscustomobject]@{
        id = 'T1021'; name = 'Remote Services'
        basis = 'direct: a connection between two pods in different trust zones is remote service use by definition'
    }
    [pscustomobject]@{
        id = 'T1046'; name = 'Network Service Scanning'
        basis = 'direct: repeated connection attempts to ports the policy refuses is service scanning'
    }
    [pscustomobject]@{
        id = 'T1078.001'; name = 'Valid Accounts: Default Accounts'
        basis = 'direct: the catalogue already claims T1078.001 for PP-01, and PP-01''s escalation step is exactly this -- a valid account used to place a workload where the creator''s own policy does not apply'
    }
    [pscustomobject]@{
        id = 'T1090.001'; name = 'Proxy: Internal Proxy'
        basis = 'judgement: ATT&CK has no Kubernetes-specific portforward technique, and relaying through a trusted component is closest to an internal proxy'
    }
    [pscustomobject]@{
        id = 'T1528'; name = 'Steal Application Access Token'
        basis = 'judgement: minting a token is not theft, but an acquisition of a credential the requester was not scheduled to hold. Flagged, not called an attack'
    }
    [pscustomobject]@{
        id = 'T1552.001'; name = 'Unsecured Credentials: Credentials In Files'
        basis = 'weak: this records that logs were read, not that anything was found in them. Listed so the surface is visible, not because a log read is credential theft'
    }
    [pscustomobject]@{
        id = 'T1609.001'; name = 'Container Administration Command'
        basis = 'direct: the audit log records the exec subresource request and the command arguments'
    }
)

# Per-schema rules.
#
#   coverage     always       every event must carry a technique; the exemption
#                             list must be empty, because there is no condition
#                             under which this schema goes untagged.
#               conditional  tagging depends on a condition in the data. The
#                             ratio is reported rather than asserted, and a
#                             technique that no event currently carries is
#                             reported as unexercised instead of failed: a
#                             healthy cluster with no off-baseline token request
#                             is the correct state, and the technique is proven
#                             by Phase 7 inducing the condition, not by this
#                             script pretending it happened.
#               inventory    never tagged. This schema records the absence of
#                             adversary action, so a full exemption is the
#                             correct outcome and failing on it would be failing
#                             on the data being healthy.
#   allowed      the technique ids this schema may carry, and no others
#   exemptions   the conditions under which an untagged event is acceptable.
#                Each has a Test that is evaluated against the event, so the
#                exemption is verified rather than assumed.
$SchemaRegistry = @(
    [pscustomobject]@{
        schema = 'network/denial-counter/v1'
        coverage = 'always'
        allowed = @('T1046')
        exemptions = @()
    }
    [pscustomobject]@{
        schema = 'network/observed-flow/v1'
        coverage = 'conditional'
        allowed = @('T1021')
        exemptions = @(
            [pscustomobject]@{
                id = 'cluster-internal'
                basis = 'The flow is cluster plumbing: coredns, the local path provisioner, or a kubelet. Real traffic, but not a lab workload talking to a lab workload, and tagging it would produce a rule that fires on DNS.'
                test = { param($e) (Get-Prop $e 'scope') -eq 'cluster-internal' }
            }
            [pscustomobject]@{
                id = 'lab-instrumentation'
                basis = 'The source is the lab''s own telemetry agent. PP-02 grants it observation ingress to web-frontend, orders-api and postgres, so a cross-zone connection from it is the lab checking that its own policies still hold. Measured: all four lab-zone flows in this cluster are this case, so a Phase 7 rule on T1021 that does not exclude it will fire on nothing but the heartbeat.'
                test = {
                    param($e)
                    ((Get-Prop $e 'scope') -eq 'lab-zone') -and
                    ((Get-Prop (Get-Prop $e 'source') 'role') -eq 'instrumentation')
                }
            }
        )
    }
    [pscustomobject]@{
        schema = 'runtime/container-exec/v1'
        coverage = 'always'
        allowed = @('T1609.001', 'T1090.001')
        exemptions = @()
    }
    [pscustomobject]@{
        schema = 'runtime/object-create/v1'
        coverage = 'conditional'
        allowed = @('T1078.001')
        exemptions = @(
            [pscustomobject]@{
                id = 'machine-created'
                basis = 'The pod was created by a controller, the scheduler or a kubelet, which is how a healthy cluster creates pods. Measured: of 183 pod creates, 24 are the kubelet, 19 are a workload controller and 13 are another service account -- 56 in total, against 127 created directly by an operator identity. Tagging all 183 would put T1078.001 on every replica the cluster has ever rolled, and the tag''s own rationale would be refuted by its data.'
                test = {
                    param($e)
                    @('kubelet', 'workload-controller', 'service-account', 'control-plane-component') -contains (Get-Prop $e 'creatorClass')
                }
            }
        )
    }
    [pscustomobject]@{
        schema = 'runtime/pod-log-read/v1'
        coverage = 'always'
        allowed = @('T1552.001')
        exemptions = @()
    }
    [pscustomobject]@{
        schema = 'runtime/token-request/v1'
        coverage = 'conditional'
        allowed = @('T1528')
        exemptions = @(
            [pscustomobject]@{
                id = 'on-baseline-requester'
                basis = 'Minting a token is not theft. The kubelet mints a token for every pod it runs and the control plane components mint tokens for their own service accounts; measured 151 requests, all of them one of those two, and zero off-baseline. Tagging them would put a credential-theft candidate on 100% of the cluster''s normal credential traffic.'
                test = {
                    param($e)
                    @('kubelet', 'control-plane-component') -contains (Get-Prop $e 'requesterClass')
                }
            }
        )
    }
    [pscustomobject]@{
        schema = 'runtime/workload-identity/v1'
        coverage = 'inventory'
        allowed = @()
        exemptions = @(
            [pscustomobject]@{
                id = 'inventory'
                basis = 'This schema is an inventory of which identity each workload runs as, and whether its image is digest-pinned. It records the absence of adversary action rather than its presence, so there is nothing in it to map to a technique. The absence of drift here is the finding.'
                test = { param($e) $true }
            }
        )
    }
)

# ---------------------------------------------------------------------------

$failures = New-Object System.Collections.ArrayList
# Failures repeat once per offending event, and 300 identical lines is not a
# report. Deduplicated on insert, with the count kept.
$failureSeen = @{}
function Add-Failure {
    param([string]$Text)
    if ($script:failureSeen.ContainsKey($Text)) {
        $script:failureSeen[$Text] = $script:failureSeen[$Text] + 1
        return
    }
    $script:failureSeen[$Text] = 1
    [void]$script:failures.Add($Text)
    Write-Host ("  FAIL  " + $Text) -ForegroundColor Red
}

$script:rows = New-Object System.Collections.ArrayList
$script:unexercised = New-Object System.Collections.ArrayList

# --- emit registry and stop ---------------------------------------------------

if ($EmitRegistryPath) {
    $techniqueSet = New-Object 'System.Collections.Generic.HashSet[string]'
    $map = [ordered]@{}
    foreach ($s in $SchemaRegistry) {
        $map[$s.schema] = @($s.allowed)
        foreach ($t in @($s.allowed)) { [void]$techniqueSet.Add([string]$t) }
    }
    $payload = [pscustomobject]@{
        generatedFrom = 'telemetry/tag-attack-ids.ps1 $SchemaRegistry'
        schemas        = $map
        techniques     = @($techniqueSet | Sort-Object)
    }
    $json = (($payload | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n"
    $dir = Split-Path -Parent $EmitRegistryPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($EmitRegistryPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("registry written to {0} ({1} schema(s), {2} technique(s))" -f `
        $EmitRegistryPath, $SchemaRegistry.Count, $techniqueSet.Count)
    return
}

# --- load ------------------------------------------------------------------

Write-Head 'loading collected telemetry'

$events = New-Object System.Collections.ArrayList
$fileInfo = @()

foreach ($path in @($NetworkEvents, $RuntimeEvents)) {
    $name = Split-Path -Leaf $path
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host ("  {0}: MISSING" -f $name) -ForegroundColor Red
        Add-Failure ("{0} does not exist. Coverage cannot be assessed against telemetry that was never collected." -f $name)
        continue
    }
    $lines = @(Get-Content -LiteralPath $path | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0) {
        Write-Host ("  {0}: EMPTY" -f $name) -ForegroundColor Red
        Add-Failure ("{0} is empty. A coverage check over no events passes trivially and proves nothing." -f $name)
        continue
    }
    $parsed = 0
    $badLines = 0
    foreach ($line in $lines) {
        try {
            $obj = $line | ConvertFrom-Json
            [void]$script:events.Add($obj)
            $parsed++
        }
        catch {
            $badLines++
        }
    }
    $fileInfo += [pscustomobject]@{
        file = $name; lines = $lines.Count; parsed = $parsed; unparseable = $badLines
    }
    Write-Host ("  {0}: {1} line(s), {2} parsed, {3} unparseable" -f $name, $lines.Count, $parsed, $badLines) -ForegroundColor DarkGray
    if ($badLines -gt 0) {
        Add-Failure ("{0} has {1} line(s) that are not valid JSON. Unparseable telemetry is missing telemetry, and treating it as covered would be a silent pass." -f $name, $badLines)
    }
    if ($parsed -eq 0) {
        Add-Failure ("{0} produced no parseable events." -f $name)
    }
}

if ($events.Count -eq 0) {
    Write-Host ''
    Write-Host '  refusing to report coverage: no events were loaded, so every check below would pass without examining anything' -ForegroundColor Red
    exit 1
}

Write-Host ("  {0} event(s) loaded" -f $events.Count) -ForegroundColor DarkGray

# --- group by schema -------------------------------------------------------

Write-Head 'schema coverage'

$bySchema = @{}
foreach ($e in $script:events) {
    $s = [string](Get-Prop $e 'schema')
    if (-not $s) {
        Add-Failure 'an event has no schema field, so it cannot be held to any mapping'
        continue
    }
    if (-not $bySchema.ContainsKey($s)) { $bySchema[$s] = New-Object System.Collections.ArrayList }
    [void]$bySchema[$s].Add($e)
}

$knownIds = @($KnownTechniques | ForEach-Object { $_.id })
$rows = New-Object System.Collections.ArrayList

foreach ($r in $SchemaRegistry) {
    $observed = $false
    $group = @()
    if ($bySchema.ContainsKey($r.schema)) { $group = @($bySchema[$r.schema]); $observed = $true }

    # Anti-vacuity: a registered schema that never appeared is not "covered".
    if (-not $observed) {
        Add-Failure ("schema {0} is registered but produced no events. A mapping that was never exercised cannot be called covered." -f $r.schema)
        [void]$script:rows.Add([pscustomobject]@{
                schema = $r.schema; coverage = $r.coverage; observed = 0; tagged = 0; exempt = 0
                untaggedUnjustified = 0; techniques = @(); exemptionsUsed = @()
            })
        continue
    }

    $tagged = 0
    $exempt = 0
    $unjustified = 0
    $exemptionsUsed = @{}
    $idsSeen = @{}
    $unjustifiedSamples = @()

    foreach ($e in $group) {
        # Get-ArrayOf already emits the array as a single object, so it must be
        # used directly. Piping it into Where-Object hands the filter the array
        # itself, and the extra @() re-wraps it, so the loop below would iterate
        # once over a nested array and read .id off an array -- which has none.
        # Every event then looks untagged. See the note on Get-ArrayOf.
        $techs = Get-ArrayOf (Get-Prop $e 'candidateTechniques')
        $ids = @($techs | ForEach-Object { [string](Get-Prop $_ 'id') } | Where-Object { $_ })

        if ($ids.Count -gt 0) {
            $tagged++
            foreach ($id in $ids) { $idsSeen[$id] = 1 }
            continue
        }

        # Untagged. It is only acceptable if a registered exemption's test
        # passes against this event's own fields.
        $matched = $null
        foreach ($x in $r.exemptions) {
            $ok = $false
            try { $ok = [bool](& $x.test $e) } catch { $ok = $false }
            if ($ok) { $matched = $x; break }
        }
        if ($matched) {
            $exempt++
            $exemptionsUsed[$matched.id] = 1
        }
        else {
            $unjustified++
            if ($unjustifiedSamples.Count -lt 3) {
                $note = [string](Get-Prop $e 'note')
                if ($note.Length -gt 70) { $note = $note.Substring(0, 70) + '...' }
                $unjustifiedSamples += $note
            }
        }
    }

    if ($r.coverage -eq 'always') {
        if ($r.exemptions.Count -gt 0) {
            Add-Failure ("schema {0} is classified 'always' but declares {1} exemption(s). One of those two statements is wrong." -f $r.schema, $r.exemptions.Count)
        }
        if ($tagged -ne $group.Count) {
            Add-Failure ("schema {0} must carry a technique on every event, but {1} of {2} do not." -f $r.schema, ($group.Count - $tagged), $group.Count)
            foreach ($s in $unjustifiedSamples) { Write-Host ("          note: " + $s) -ForegroundColor DarkGray }
        }
    }
    elseif ($r.coverage -eq 'inventory') {
        # A full exemption here is the correct outcome, not a warning. What would
        # be wrong is this schema quietly carrying a technique, because an
        # inventory that starts flagging techniques has stopped being an
        # inventory and nobody would notice.
        if ($tagged -gt 0) {
            Add-Failure ("schema {0} is an inventory and must never carry a technique, but {1} of {2} events do. The registry and the collector disagree about what this schema is." -f $r.schema, $tagged, $group.Count)
        }
        $unjustified = 0
    }
    else {
        # conditional. Report the ratio; do not assert a minimum. A technique no
        # event currently carries is unexercised, not broken, and it becomes a
        # Phase 7 obligation instead of a failure here.
        if ($unjustified -gt 0) {
            Add-Failure ("schema {0} tags conditionally, but {1} of {2} untagged events match no exemption. These are unexplained, not merely benign." -f $r.schema, $unjustified, $group.Count)
            foreach ($s in $unjustifiedSamples) { Write-Host ("          note: " + $s) -ForegroundColor DarkGray }
        }
        foreach ($id in $r.allowed) {
            if (-not $idsSeen.ContainsKey($id)) {
                [void]$script:unexercised.Add([pscustomobject]@{
                        schema    = $r.schema
                        technique = $id
                        reason    = 'declared for this schema, but no collected event currently carries it'
                    })
            }
        }
    }

    [void]$script:rows.Add([pscustomobject]@{
            schema = $r.schema; coverage = $r.coverage; observed = $group.Count; tagged = $tagged; exempt = $exempt
            untaggedUnjustified = $unjustified
            techniques = @($idsSeen.Keys | Sort-Object)
            exemptionsUsed = @($exemptionsUsed.Keys | Sort-Object)
        })

    $taggedStr = if ($tagged -eq $group.Count) { 'all' } else { "$tagged/$($group.Count)" }
    Write-Host ("  {0,-34} {1,-11} {2,5} event(s)  tagged {3,-9} exempt {4,-5} {5}" -f `
            $r.schema, $r.coverage, $group.Count, $taggedStr, $exempt, ($(if ($idsSeen.Count) { (@($idsSeen.Keys | Sort-Object)) -join ',' } else { '' })))
}

# Any schema present in the data but absent from the registry is unmapped
# telemetry. It must not pass quietly.
foreach ($s in ($bySchema.Keys | Sort-Object)) {
    $registered = @($SchemaRegistry | Where-Object { $_.schema -eq $s })
    if ($registered.Count -eq 0) {
        Add-Failure ("schema {0} appears in the telemetry but is not in the registry. Unmapped telemetry is the exact gap this script exists to close." -f $s)
        [void]$script:rows.Add([pscustomobject]@{
                schema = $s; coverage = 'unregistered'; observed = @($bySchema[$s]).Count; tagged = 0; exempt = 0
                untaggedUnjustified = 0; techniques = @(); exemptionsUsed = @(); unregistered = $true
            })
    }
}

# --- technique ids ---------------------------------------------------------

Write-Head 'technique ids'

$emitted = @{}
foreach ($e in $script:events) {
    foreach ($t in (Get-ArrayOf (Get-Prop $e 'candidateTechniques'))) {
        $id = [string](Get-Prop $t 'id')
        if (-not $id) {
            # Array elements with no id are the shape bug this registry was built
            # to catch, so it is worth naming precisely rather than counting.
            $schemaOfEvent = [string](Get-Prop $e 'schema')
            Add-Failure ("schema {0} carries a candidateTechniques entry with no id. The field is declared as a list of mappings, so an entry without an id is a malformed event, not an untagged one." -f $schemaOfEvent)
            continue
        }
        $emitted[$id] = 1
    }
}

foreach ($id in ($emitted.Keys | Sort-Object)) {
    if ($knownIds -notcontains $id) {
        Add-Failure ("technique {0} was emitted but is not in the registry's known-technique table. Either the mapping is new and should be declared, or the collector invented it." -f $id)
    }
    else {
        $kn = @($KnownTechniques | Where-Object { $_.id -eq $id })[0]
        $weak = if ($kn.basis -match '^weak') { '  [WEAK MAPPING]' } else { '' }
        Write-Host ("  {0,-10} {1}{2}" -f $id, $kn.name, $weak) -ForegroundColor $(if ($kn.basis -match '^weak') { 'Yellow' } else { 'DarkGray' })
    }
}

$unused = @($knownIds | Where-Object { -not $emitted.ContainsKey($_) })
if ($unused.Count -gt 0) {
    Write-Host ''
    Write-Host ("  declared but not emitted by the current telemetry: {0}" -f ($unused -join ', ')) -ForegroundColor DarkGray
    Write-Host '  T1090.001 is expected here: nothing has used portforward in this lab yet.' -ForegroundColor DarkGray
}

# --- unexercised techniques: the Phase 7 work list -------------------------

Write-Head 'declared but not yet exercised'

# This is the section that keeps the lab honest about what it has actually
# proven. A technique the registry permits but no event carries has never fired,
# and no amount of coverage in the files above substitutes for inducing it. Each
# of these is a Phase 7 obligation: write the rule, cause the condition, prove
# it fires, and prove it stays quiet on the benign traffic around it.
if ($script:unexercised.Count -eq 0) {
    Write-Host '  none: every technique the registry permits is carried by at least one collected event' -ForegroundColor DarkGray
}
else {
    foreach ($u in $script:unexercised) {
        $kn = @($KnownTechniques | Where-Object { $_.id -eq $u.technique })[0]
        $knName = if ($kn) { $kn.name } else { '(not in known-technique table)' }
        Write-Host ("  {0,-10} {1,-24} via {2}" -f $u.technique, $knName, $u.schema) -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host ("  {0} technique(s) have a mapping but no firing evidence. Phase 7 owns these." -f $script:unexercised.Count) -ForegroundColor Yellow
}

# --- what Phase 7 must exclude ---------------------------------------------

Write-Head 'exclusions Phase 7 inherits'

# The instrumentation exclusion is the one that matters most, because getting it
# wrong produces a rule that appears to work. It is surfaced unconditionally
# rather than only on failure, with the count of events a naive rule would
# inherit.
$instrumentedFlows = @($script:events | Where-Object {
        (Get-Prop $_ 'schema') -eq 'network/observed-flow/v1' -and
        (Get-Prop $_ 'scope') -eq 'lab-zone' -and
        (Get-Prop (Get-Prop $_ 'source') 'role') -eq 'instrumentation'
    })
$workloadLabFlows = @($script:events | Where-Object {
        (Get-Prop $_ 'schema') -eq 'network/observed-flow/v1' -and
        (Get-Prop $_ 'scope') -eq 'lab-zone' -and
        (Get-Prop (Get-Prop $_ 'source') 'role') -ne 'instrumentation'
    })

Write-Host ("  T1021  lab-zone flows that are the lab''s own sensor : {0}" -f $instrumentedFlows.Count) -ForegroundColor Yellow
Write-Host ("  T1021  lab-zone flows from an actual workload        : {0}" -f $workloadLabFlows.Count) -ForegroundColor DarkGray
if ($instrumentedFlows.Count -gt 0 -and $workloadLabFlows.Count -eq 0) {
    Write-Host '  A T1021 rule must exclude source.role=instrumentation. Without that exclusion its only' -ForegroundColor Yellow
    Write-Host '  hits in this cluster are the telemetry agent''s own health probes.' -ForegroundColor Yellow
}

$offBaselineTokens = @($script:events | Where-Object {
        (Get-Prop $_ 'schema') -eq 'runtime/token-request/v1' -and
        @('other', 'impersonated') -contains (Get-Prop $_ 'requesterClass')
    })
Write-Host ("  T1528  token requests outside the measured baseline   : {0}" -f $offBaselineTokens.Count) -ForegroundColor DarkGray
Write-Host '  A T1528 rule must require requesterClass in (other, impersonated).' -ForegroundColor DarkGray

# --- report ----------------------------------------------------------------

$report = [ordered]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    note        = @'
Coverage of the ATT&CK mapping, and the exclusions a detection on each technique
must apply. Produced by telemetry\tag-attack-ids.ps1, which holds the mapping.

A candidate technique here is not a detection. Nothing in this file has been
shown to fire; Phase 7 is where that is proven, per technique, with a test.

The exclusions matter more than the coverage. Two techniques in this lab have
only benign hits available if a rule is written naively: every T1021 candidate
is the lab's own sensor, and every T1528 candidate would have been the kubelet
and the control plane doing their jobs. A rule that ignores the exclusions
fires on the lab checking itself and looks healthy.
'@
    files           = @($fileInfo)
    eventCount      = $events.Count
    knownTechniques = @($KnownTechniques)
    schemaRegistry  = @($SchemaRegistry)
    coverage        = @($script:rows)
    emittedIds      = @($emitted.Keys | Sort-Object)
    unexercised     = @($script:unexercised)
    phase7Exclusions = [ordered]@{
        'T1021' = 'exclude source.role=instrumentation (the lab''s own telemetry agent)'
        'T1528' = 'require requesterClass in (other, impersonated)'
    }
    instrumentationFlows = $instrumentedFlows.Count
    workloadLabFlows     = $workloadLabFlows.Count
    offBaselineTokens    = $offBaselineTokens.Count
    passed = ($script:failures.Count -eq 0)
    failures = @($script:failures)
}

$reportDir = Split-Path -Parent $ReportPath
if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}
# ASCII by design. The registry text is the part a reviewer will actually read,
# and it should not depend on the reader's code page.
$json = ($report | ConvertTo-Json -Depth 8) -replace '[^\x00-\x7F]', ''
Set-Content -LiteralPath $ReportPath -Value $json -Encoding ascii

Write-Host ''
Write-Host ("  report written to {0}" -f $ReportPath) -ForegroundColor DarkGray

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host ("  PASS  {0} event(s) across {1} schema(s); every technique is registered and every untagged event is justified by a verified exemption" -f $events.Count, $rows.Count) -ForegroundColor Green
    exit 0
}

Write-Host ("  FAIL  {0} problem(s)" -f $script:failures.Count) -ForegroundColor Red
exit 1
