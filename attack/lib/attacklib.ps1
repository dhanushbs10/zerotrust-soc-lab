<#
    Shared helpers for the attack scripts in attack/.

    Dot-source, do not run:

        . "$PSScriptRoot\lib\attacklib.ps1"

    Why a library rather than five self-contained scripts: the reporting format
    is the point of this directory. A path that is walked but not recorded
    produces nothing a detection can later be tested against, and the five
    scripts share a lot of structure that must not drift apart. The helpers here
    are the only place that structure lives.

    The reporting contract
    ---------------------
    Every script in this directory reports, in order:

      1. What it is exercising, with the ATT&CK IDs attached to the step rather
         than to the file. A step with no technique ID cannot be handed to a
         detection engineer, so the reporter will not accept one.
      2. Real observed output. Not a restatement of intent: if a step says a
         token was read, the token's length and its decoded subject claim are
         printed, because "the token was read" is a claim and "1229 bytes,
         sub=system:serviceaccount:zerotrust-build:sa-build-runner" is evidence.
      3. An assertion per step, with the expectation written down before the
         observation. Expectations are never derived from what happened; that
         would make every assertion agree with reality by construction.
      4. What the script deliberately did not do, and why. The read-only
         guarantee is only meaningful if it is stated per step.

    And it exits non-zero if any assertion fails, so a path that stops being
    walkable fails loudly instead of quietly becoming untestable.

    The read-only guarantee
    ----------------------
    Every script here reads. None of them creates, patches or deletes a
    Kubernetes object, and none of them writes to a database. Steps that would
    cross that line are printed under "withheld" with the exact command that
    would have run, so the reader can decide to run it themselves with full
    knowledge of what it does.

    That is a deliberate trade. A path that mutates the cluster is not
    re-runnable without a teardown step, and a demo you can only run once cannot
    be used to test a detection twice. The steps that were withheld are the
    steps that Phase 7's detections will be exercised against, so nothing is
    lost by not running them here.
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

$script:Assertions = [System.Collections.Generic.List[object]]::new()
$script:PathId      = $null
$script:StepNumber  = 0

function Write-Banner {
    param(
        [string] $PathId,
        [string] $Title,
        [string] $Claim
    )
    $script:PathId     = $PathId
    $script:StepNumber = 0
    $script:Assertions.Clear()

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host ("  {0}  {1}" -f $PathId, $Title) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    if ($Claim) {
        Write-Host ''
        Write-Host '  Claim:' -ForegroundColor White
        Write-Host "    $Claim" -ForegroundColor White
    }
}

function Write-Step {
    param(
        [Parameter(Mandatory)] [string] $AttackId,
        [Parameter(Mandatory)] [string] $Description
    )
    $script:StepNumber++
    Write-Host ''
    Write-Host ("  step {0}  [{1}]  {2}" -f $script:StepNumber, $AttackId, $Description) -ForegroundColor Yellow
    return $script:StepNumber
}

function Write-Observed {
    param([string] $Text, [switch] $Quiet)
    if ($Quiet) { return }
    if (-not $Text) { return }
    foreach ($line in ($Text -split "`n")) {
        if ($line.Trim()) { Write-Host ("      {0}" -f $line.TrimEnd()) -ForegroundColor DarkGray }
    }
}

# Expectations are passed in by the caller as literal strings, written from the
# catalogue rather than observed from the run. There is no code path that
# derives the expected value from the actual value, which is the only way to
# stop an assertion from agreeing with reality by construction.
function Write-Assertion {
    param(
        [Parameter(Mandatory)] [string] $Expected,
        [Parameter(Mandatory)] [string] $Observed,
        [Parameter(Mandatory)] [bool]   $Passed,
        [string] $Note = ''
    )
    $script:Assertions.Add([pscustomobject]@{
        path     = $script:PathId
        step     = $script:StepNumber
        expected = $Expected
        observed = $Observed
        passed   = $Passed
        note     = $Note
    })
    $mark = if ($Passed) { 'PASS' } else { 'FAIL' }
    $col  = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host ("      [{0}] expected {1}" -f $mark, $Expected) -ForegroundColor $col
    Write-Host ("           observed {0}" -f $Observed) -ForegroundColor $col
    if ($Note) { Write-Host ("           {0}" -f $Note) -ForegroundColor DarkGray }
}

function Write-Withheld {
    param(
        [Parameter(Mandatory)] [string] $WouldDo,
        [Parameter(Mandatory)] [string] $Why
    )
    Write-Host ''
    Write-Host '      withheld:' -ForegroundColor DarkYellow
    Write-Host ("        would {0}" -f $WouldDo) -ForegroundColor DarkYellow
    Write-Host ("        because {0}" -f $Why) -ForegroundColor DarkYellow
}

function Complete-Attack {
    $failed = @($script:Assertions | Where-Object { -not $_.passed })
    Write-Host ''
    Write-Host ('-' * 78) -ForegroundColor DarkGray
    if ($failed.Count -eq 0) {
        Write-Host ("  {0}: path is walkable. {1} assertion(s) held." -f $script:PathId, $script:Assertions.Count) -ForegroundColor Green
    } else {
        Write-Host ("  {0}: {1} of {2} assertion(s) FAILED. The path changed shape." -f $script:PathId, $failed.Count, $script:Assertions.Count) -ForegroundColor Red
        foreach ($f in $failed) {
            Write-Host ("    step {0}: expected {1}, observed {2}" -f $f.step, $f.expected, $f.observed) -ForegroundColor Red
        }
    }
    return $failed.Count
}

# ---------------------------------------------------------------------------
# cluster access
#
# The traps below are not hypothetical. Each of them cost a real debugging cycle
# in this repository and is therefore encoded here once.
# ---------------------------------------------------------------------------

function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# `kubectl -o json` emits one line per line. Piping that straight into
# ConvertFrom-Json hands it a single line at a time, so it throws and the caller
# silently ends up holding $null. Out-String first, always.
function Get-KubeJson {
    param([string[]] $Arguments)
    $out = & kubectl @Arguments 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $out.Trim()) { return $null }
    try { return ($out | ConvertFrom-Json) } catch { return $null }
}

# Plain unrolled stream, with @() at every call site. The `, @()` idiom is
# correct for direct assignment but not when piped and actively wrong when
# wrapped in @(), and getting it wrong produced a scanner that reported zero
# credentials while two Secrets sat in the cluster.
function Get-Items {
    param($Object)
    if ($null -eq $Object) { return }
    if (-not $Object.PSObject.Properties['items']) { return }
    $Object.items | Where-Object { $null -ne $_ }
}

function Get-LabPod {
    param(
        [Parameter(Mandatory)] [string] $Namespace,
        [Parameter(Mandatory)] [string] $App
    )
    $pod = @(Get-Items (Get-KubeJson @('get','pods','-n',$Namespace,'-l',("app={0}" -f $App),'-o','json'))) |
        Where-Object { (Get-Prop (Get-Prop $_ 'status') 'phase') -eq 'Running' } |
        Select-Object -First 1
    if (-not $pod) { return $null }
    return $pod
}

function Assert-ClusterReady {
    $nodes = @(& kubectl get nodes --no-headers 2>$null | Where-Object { $_ -and $_.Trim() }).Count
    if ($nodes -lt 3) {
        Write-Host ''
        Write-Host "  the lab is not up: $nodes node(s) reachable, expected 3." -ForegroundColor Red
        Write-Host '  run cluster\bootstrap\bootstrap.ps1 first.' -ForegroundColor Red
        return $false
    }
    return $true
}

<#
    Returns the last non-empty line of a native command's combined output.

    Windows PowerShell wraps native stderr in a NativeCommandError record, so
    capturing a failing kubectl call verbatim yields several lines of PowerShell
    error decoration wrapped around the one line that carries the verdict. Since
    $ErrorActionPreference has to stay at 'Continue' for native tools that write
    progress to stderr, that decoration cannot be suppressed, only trimmed off.
    Matching on the last non-empty line is what makes an assertion readable.
#>
function Get-LastLine {
    param([string] $Output)
    if (-not $Output) { return '' }

    $candidates = @()
    foreach ($raw in ($Output -split "`n")) {
        $line = $raw.Trim()
        if (-not $line) { continue }

        # PowerShell's native-stderr decoration. It is appended AFTER the real
        # message, so a naive "last non-empty line" returns "+ FullyQualifiedErrorId
        # : NativeCommandError" instead of what kubectl actually said. A verdict
        # of that shape means the check was asserting on PowerShell's plumbing.
        #
        # The position line has two different spellings and the filter has to
        # survive both, because which one appears depends on where the failing
        # call sits. At the top level of a script it renders as
        #     At line:281 char:12
        # and inside a function in a dot-sourced library it renders as
        #     At D:\path\attacklib.ps1:281 char:12
        # Filtering only the first form let the second one through, and the
        # verdict came back as a file path.
        if ($line -match '^\+\s') { continue }
        if ($line -match '^At\b.*\bchar:\d+') { continue }
        if ($line -match 'CategoryInfo|FullyQualifiedErrorId') { continue }

        # "... At line:12 char:3" and the echoed source can land on the same line
        # as the message, so trim from that marker onwards.
        $line = ($line -replace '\s+At\s+.*\bchar:\d+.*$', '')

        # "<exe> : " prefix that PowerShell puts in front of native stderr.
        $line = ($line -replace '^[A-Za-z0-9_.\-]+\.exe\s*:\s*', '')

        if ($line) { $candidates += $line }
    }
    if ($candidates.Count -eq 0) { return '' }
    return $candidates[-1]
}

<#
    Runs kubectl and returns the last meaningful line plus the exit code.

    The guard is not defensive padding. PowerShell binds the comma operator
    tighter than +, so:

        @('--kubeconfig=' + $k, '--token=' + $t, 'get', 'secrets')

    does not build an eight-element array. It builds an array of one, whose
    single element is the whole thing space-joined, because the expression
    parses as '--kubeconfig=' + ($k, ('--token=' + $t, 'get', 'secrets')) and
    concatenating a string with an array yields a space-separated string.

    Nothing errors. kubectl is handed one enormous argument, prints its usage
    text, and exits 1 -- so the symptom is a wall of help output and a verdict
    of "Use kubectl options for a list of global command-line options", which
    points nowhere near the cause. Every element needs its own parentheses:

        @(('--kubeconfig=' + $k), ('--token=' + $t), 'get', 'secrets')

    A single argument containing whitespace is that mistake, and it is caught
    here so it cannot masquerade as a kubectl problem again.
#>
function Invoke-Kubectl {
    param([string[]] $Arguments)

    if ($Arguments.Count -eq 1 -and $Arguments[0] -match '\s') {
        throw ("Invoke-Kubectl received one argument containing whitespace. That is the signature of PowerShell binding ',' tighter than '+', which collapses a multi-element argument list into one space-joined string. Parenthesise each element: @(('a=' + `$x), ('b=' + `$y)). Received: " + $Arguments[0])
    }

    # The same mistake takes a second shape, and this one does not collapse the
    # list -- it splits it. Written unparenthesised:
    #
    #     @('auth', 'can-i', 'get', 'x', '--as=' + $id)
    #
    # arrives as two separate arguments, '--as=' and the identity. kubectl reads
    # the option as having an empty value and reports "you must specify two
    # arguments: verb resource or verb resource/resourceName", which says nothing
    # whatsoever about the real problem.
    #
    # An option with an empty value is never intentional, so it is a reliable
    # signature for the bug no matter which way the precedence went.
    $emptyOption = @($Arguments | Where-Object { $_ -match '^--[a-zA-Z][a-zA-Z0-9-]*=$' })
    if ($emptyOption.Count -gt 0) {
        throw ("Invoke-Kubectl received an option with an empty value: {0}`n  This is unparenthesised concatenation, e.g. '--as=' + `$id, which PowerShell split into two arguments. Write ('--as=' + `$id) with parentheses.`n  Full list: {1}" -f ($emptyOption -join ', '), ($Arguments -join ' | '))
    }

    $out = & kubectl @Arguments 2>&1 | Out-String
    return [pscustomobject]@{
        exitCode = $LASTEXITCODE
        verdict  = Get-LastLine $out
        raw      = $out
    }
}

<#
    Runs a command inside a lab pod and returns its combined output.

    kubectl exec is itself an audit event, and an audited one: it is recorded as
    a pods/exec subresource request by the operator's identity, attributed to
    system:serviceaccount:zerotrust-build:sa-build-runner as the target. That is
    the mechanism DET-0002-era runtime detections key on, so these calls are not
    incidental -- they are part of what Phase 5 and Phase 7 consume.
#>
<#
    A stable, non-reversible label for a credential.

    Two copies of the same password produce the same fingerprint, which is what
    lets a report say "these are one credential" without ever printing the
    value. This is the same algorithm tools/scan-secrets.ps1 uses, deliberately,
    so a walk script and the scanner agree on the label for the same secret. If
    the two ever disagree, one of them is wrong about which copy is which.
#>
function Get-Fingerprint {
    param([string] $Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))) -replace '-', ''
    $sha.Dispose()
    return $hex.Substring(0, 16)
}

<#
    Runs a single command inside a lab pod and returns its combined output.

    THE COMMAND MUST BE QUOTE-FREE
    ------------------------------
    Only characters that survive PowerShell's native argument marshalling may
    appear here: no " ' ( ) { } $ * ? [ ] or backtick.

    PowerShell hands the argument to kubectl.exe having stripped any embedded
    double quotes, so the pod's shell receives a command whose quoting has
    silently evaporated:

        Invoke-InPod -Command 'env | grep -ciE "^(PG|DATABASE|DB_)"'
        -> sh: syntax error: unexpected "("

    That one is at least loud. The dangerous case is a command that merely
    misbehaves once its quoting is gone -- an unquoted glob that expands, a
    bracket that turns into a redirect -- and returns a plausible wrong answer
    that a later assertion happily records as a finding.

    Write group alternation as repeated patterns instead:

        env | grep -ci -e ^PG -e ^DATABASE -e ^DB_ || true

    Piping a script in on stdin is NOT an escape from this. It was tried and
    measured: Windows PowerShell 5.1 has no input redirection at all ('<' is
    "reserved for future use"), and Get-Content piped to a native command
    re-emits every line with CRLF, which busybox sh rejects --

        for x in a b c; do
          echo "loop-$x"
        done

    fails with `sh: syntax error: unexpected word (expecting "do")` whether the
    source file was written with LF or CRLF, because the corruption happens in
    the PowerShell pipeline rather than in the file. So the rule stands: keep
    in-pod commands simple enough to pass as one argument.

    The guard below enforces it, because a loud failure here is worth far more
    than a quiet wrong answer.
#>
function Invoke-InPod {
    param(
        [Parameter(Mandatory)] [string] $Namespace,
        [Parameter(Mandatory)] [string] $Pod,
        [Parameter(Mandatory)] [string] $Shell,
        [Parameter(Mandatory)] [string] $Command,
        [int] $TimeoutSeconds = 30
    )
    if ($Command -match '["''(){}\[\]*?$`]') {
        throw ("In-pod command contains a character that PowerShell's native marshalling will mangle: {0}`n  Write group alternation as repeated -e patterns, and precompute anything else in PowerShell." -f $Command)
    }
    $out = & kubectl exec -n $Namespace $Pod -- $Shell '-c' $Command 2>&1 | Out-String
    return $out.TrimEnd()
}

# Reads the projected service account token out of a running pod. This is the
# single most important primitive in this directory: five of the paths reduce to
# what this returns.
function Get-PodServiceAccountToken {
    param(
        [Parameter(Mandatory)] [string] $Namespace,
        [Parameter(Mandatory)] [string] $Pod
    )
    return Invoke-InPod -Namespace $Namespace -Pod $Pod -Shell 'sh' -Command 'cat /var/run/secrets/kubernetes.io/serviceaccount/token'
}

<#
    Decodes the claims of a service account JWT.

    This does NOT verify the signature, and cannot: the signing key is the API
    server's. The purpose here is attribution -- showing which identity a token
    asserts -- not trust. The trust question is settled separately and for real,
    by presenting the token to the API server and being answered.
#>
function Get-TokenSubject {
    param([string] $Token)
    if (-not $Token) { return $null }
    $parts = $Token.Trim() -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    try {
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    } catch { return $null }
}
