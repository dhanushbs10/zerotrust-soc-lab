<#
.SYNOPSIS
    Proves the reachability self-test can actually fail.

.DESCRIPTION
    A test suite that has never failed is not evidence that anything works. It is
    entirely consistent with a suite whose assertions are empty, or whose subject
    was replaced by something that always agrees.

    This harness takes the opposite approach to the usual one. Instead of adding
    more assertions to build-reachability.ps1, it breaks the real script on
    purpose, in a throwaway copy, and requires the self-test to notice. Each
    mutation below reintroduces a bug this project has actually hit, and each one
    must make -SelfTest exit non-zero.

    Every bug in the list was found by the graph disagreeing with the datapath, or
    by reading it and finding nothing wrong. None of them announced itself. That
    is the whole reason this file exists: the class of defect that survives review
    is the class that looks like a plausible answer, and the only defence measured
    so far is a test that is known to be able to fail.

    The script under test is copied rather than edited in place, so a failure here
    damages nothing and the working tree is untouched.

.PARAMETER KeepCopies
    Leave the mutated copies on disk for inspection. They are deleted otherwise.

.EXAMPLE
    .\test-reachability-selftest.ps1

.EXAMPLE
    .\test-reachability-selftest.ps1 -KeepCopies
#>

[CmdletBinding()]
param(
    [switch]$KeepCopies
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'build-reachability.ps1'
if (-not (Test-Path -LiteralPath $scriptPath)) {
    Write-Host "  cannot find $scriptPath" -ForegroundColor Red
    exit 1
}
$original = [System.IO.File]::ReadAllText($scriptPath)

# Scratch space. The approved OpenCode temp directory is preferred over the
# generic one so nothing lands somewhere the user did not sanction.
$scratch = Join-Path $env:LOCALAPPDATA 'Temp\opencode\reachability-mutations'
if (-not (Test-Path -LiteralPath $scratch)) {
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
}

function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('-' * $Text.Length) -ForegroundColor DarkGray
}

# Runs -SelfTest on a copy and reports what happened, without ever throwing.
#
# $ErrorActionPreference is relaxed for the call. Several of the mutations below
# do not make an assertion fail -- they make the script die on a strict-mode
# error, which is exactly how the original bugs behaved. PowerShell surfaces a
# native command's stderr as a terminating error under 'Stop', so a mutated
# script that crashes would otherwise take this harness down with it and the run
# would stop at the first one, reporting a broken harness instead of a result.
#
# The distinction is kept rather than flattened: a mutation caught by an assertion
# and a mutation caught by a crash are both caught, but they are not the same
# evidence, and a suite that only ever dies would be a poor test.
function Invoke-SelfTest {
    param([string]$Path)

    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $Path -SelfTest 2>&1 | Out-String
    $code = $LASTEXITCODE

    $lines = @()
    if ($out) { $lines = @($out -split "`r?`n") }

    return [pscustomobject]@{
        exitCode = $code
        output = $out
        failures = @($lines | Where-Object { $_ -match '\[FAIL\]' })
    }
}

# Each mutation names a bug that really happened, quotes the line that causes it,
# and supplies the broken replacement.
#
# The find strings are single-quoted here-strings so that the $variables inside
# them are not interpolated by PowerShell while this file is being parsed. They
# are matched exactly once each; the harness verifies that before running
# anything, because a mutation that silently matched nothing would report a pass
# for a test that never happened.
$mutations = @(

    @{
        name = 'agreement rule inverted'
        bug = 'the one function whose whole job is to notice a disagreement'
        find = @'
    return ($Observed -eq 'open' -and $Modelled -eq 'open') -or
'@
        replace = @'
    return ($Observed -ne 'open' -and $Modelled -eq 'open') -or
'@
    }

    @{
        name = 'Get-ArrayOf returns $null for an empty list'
        bug = 'a PowerShell function that returns an empty array emits nothing, so the caller got $null and .Count threw'
        find = @'
    if ($null -eq $Value) { return , @() }
'@
        replace = @'
    if ($null -eq $Value) { return @() }
'@
    }

    @{
        name = 'endPort range silently evaluated as a single port'
        bug = 'a port range guessed at produces a confidently wrong edge'
        find = @'
            throw "policy port range (endPort) is not supported by this model; refusing to guess at a range"
'@
        replace = @'
            Write-Verbose 'range ignored'
'@
    }

    @{
        name = 'drop threshold moved outside the measured gap'
        bug = 'a threshold fitted to a machine instead of to a measurement classifies every refusal as a drop'
        find = @'
$script:DropThresholdMs = 600
'@
        replace = @'
$script:DropThresholdMs = 2000
'@
    }

    @{
        name = 'port protocol comparison removed'
        bug = 'TCP and UDP are different ports to a policy, so a UDP rule would be read as a TCP one'
        find = @'
        if ($proto -ne $Protocol) { continue }
'@
        replace = @'
        if ($false) { continue }
'@
    }

    @{
        name = 'namespaceSelector matched against the whole cluster instead of the peer'
        bug = 'type-compatible, so it ran, and silently denied every cross-zone rule until the three PP-02 observation edges disappeared from the graph'
        find = @'
        $peerNsLabels = $NamespaceLabels[$PeerPod.namespace]
'@
        replace = @'
        $peerNsLabels = $NamespaceLabels
'@
    }

    @{
        name = 'ingress direction resolved as egress'
        bug = 'the direction was ignored, so each policy governed the wrong half of the conversation'
        find = @'
        $policyType = 'Ingress'
'@
        replace = @'
        $policyType = 'Egress'
'@
    }

    @{
        name = 'rule list looked up under the capitalised field name'
        bug = 'PowerShell resolves $obj.Ingress and $obj.ingress to the same property, so this is a no-op and the class of bug cannot exist here. Worth keeping: the original policyTypes confusion was real, but it was the direction that was conflated, not the field name, and mutation 7 covers that.'
        expectUncatchable = $true
        find = @'
        $specField = 'ingress'
'@
        replace = @'
        $specField = 'Ingress'
'@
    }

    @{
        name = 'bare podSelector not scoped to its own namespace'
        bug = 'a zone boundary drawn with a podSelector alone stops being a boundary'
        find = @'
        if ($PeerPod.namespace -ne $PolicyNamespace) { return $false }
'@
        replace = @'
        if ($false) { return $false }
'@
    }
)

Write-Head 'baseline: the unmutated script must pass'
$baseline = Invoke-SelfTest -Path $scriptPath
if ($baseline.exitCode -eq 0) {
    Write-Host '  [ok  ] -SelfTest passes on the real script' -ForegroundColor DarkGreen
}
else {
    Write-Host '  [FAIL] -SelfTest does not pass on the unmutated script, so nothing below means anything' -ForegroundColor Red
    Write-Host $baseline.output -ForegroundColor DarkGray
    exit 1
}

Write-Head 'each mutation must break the self-test'

$pass = 0
$fail = 0
$index = 0

foreach ($m in $mutations) {
    $index++
    $label = '{0,2}. {1}' -f $index, $m.name

    $occurrences = ([regex]::Matches($original, [regex]::Escape($m.find))).Count
    if ($occurrences -ne 1) {
        Write-Host ("  [FAIL] {0}" -f $label) -ForegroundColor Red
        Write-Host ("         the text to mutate matched {1} time(s), expected exactly 1." -f $occurrences) -ForegroundColor Red
        Write-Host '         The mutation never happened, so a pass here would prove nothing.' -ForegroundColor Red
        $fail++
        continue
    }

    $mutated = $original.Replace($m.find, $m.replace)

    # -ceq, not -eq. PowerShell's -eq on strings is case-insensitive, so a
    # mutation that changes only the case of an identifier -- exactly what the
    # policyTypes mutation below does -- compares equal to the original and gets
    # reported as "no change" when the change did happen. That is the same
    # casing confusion that made the graph model report 25/25 open, and it is
    # worth being explicit about rather than lucky.
    if ($mutated -ceq $original) {
        Write-Host ("  [FAIL] {0}" -f $label) -ForegroundColor Red
        Write-Host '         the replacement produced an identical file.' -ForegroundColor Red
        $fail++
        continue
    }

    $copy = Join-Path $scratch ('mutated-{0:d2}.ps1' -f $index)
    [System.IO.File]::WriteAllText($copy, $mutated, (New-Object System.Text.UTF8Encoding($false)))

    $out = Invoke-SelfTest -Path $copy
    $caughtBy = @($out.failures).Count

    # Read defensively. Set-StrictMode throws on a hashtable key that is absent
    # rather than yielding $null, so a mutation without this flag would abort the
    # run -- which is how a missing key becomes a mystery instead of a default.
    $uncatchable = $m.ContainsKey('expectUncatchable') -and [bool]$m['expectUncatchable']

    if ($uncatchable) {
        # Kept deliberately. A mutation the suite provably cannot catch is a
        # result, not an oversight: it says the bug cannot occur in this code.
        # Dropping it would lose that, and the next person to try it would
        # conclude the suite was broken.
        if ($out.exitCode -eq 0) {
            Write-Host ("  [ok  ] {0}" -f $label) -ForegroundColor DarkGreen
            Write-Host '         confirmed uncatchable, as expected' -ForegroundColor DarkGray
            Write-Host ("         {0}" -f $m.bug) -ForegroundColor DarkGray
            $pass++
        }
        else {
            Write-Host ("  [FAIL] {0}" -f $label) -ForegroundColor Red
            Write-Host '         this was believed to be uncatchable, but the suite caught it.' -ForegroundColor Red
            Write-Host '         That is better news than expected, and the note on it is now wrong.' -ForegroundColor Red
            $fail++
        }
    }
    elseif ($out.exitCode -ne 0) {
        Write-Host ("  [ok  ] {0}" -f $label) -ForegroundColor DarkGreen
        if ($caughtBy -gt 0) {
            Write-Host ("         {0} assertion(s) caught it" -f $caughtBy) -ForegroundColor DarkGray
            foreach ($d in $out.failures) { Write-Host ("         {0}" -f $d.Trim()) -ForegroundColor DarkGray }
        }
        else {
            # Caught, but by dying rather than by disagreeing. Worth saying out
            # loud, because a suite that only crashes is testing less than it
            # appears to.
            Write-Host '         caught by aborting, not by an assertion failing' -ForegroundColor DarkYellow
        }
        $pass++
    }
    else {
        Write-Host ("  [FAIL] {0}" -f $label) -ForegroundColor Red
        Write-Host ("         the self-test still passed with this bug present. It is not testing: {0}" -f $m.bug) -ForegroundColor Red
        $fail++
    }

    if (-not $KeepCopies) {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ("  {0} mutation(s): {1} caught, {2} missed" -f $mutations.Count, $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })

if (-not $KeepCopies) {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
else {
    Write-Host "  mutated copies kept in $scratch" -ForegroundColor Yellow
}

if ($fail -gt 0) {
    Write-Host ''
    Write-Host '  FAIL  the self-test cannot be relied on to catch these bugs.' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '  PASS  every known bug is caught, so a passing self-test means something.' -ForegroundColor Green
exit 0
