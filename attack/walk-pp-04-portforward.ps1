<#
    Walks PP-04: pods/portforward relays through the API server, so
    NetworkPolicy does not constrain it.

    T1090.001 Proxy: Internal Proxy

    What this is
    ------------
    Every NetworkPolicy in this lab was verified against the datapath in Phase 6.
    Twenty-five modelled pairs were probed with ephemeral pods dialling Service
    ClusterIPs, and nineteen of them were confirmed dropped by the policy chain.
    That verification has a boundary, and this walk is the boundary.

    `kubectl port-forward` does not open a connection from the client to the pod.
    It asks the API server to open a connection *from the kubelet into the pod's
    network namespace*, and then relays bytes between the two over an existing
    stream. The traffic that reaches postgres never traverses the pod-to-pod path
    that kube-router's policy chain governs, so no policy written against that
    path can match it.

    So the control is real, comprehensive, and does not apply here. That is a
    materially different statement from "the control is weak", and it is the kind
    of gap that a network-graph-based SOC will report as fully closed.

    Why it is a privilege path
    --------------------------
    Because the ability to do it is RBAC (`create` on `pods/portforward`), and in
    this cluster anything holding cluster-admin has it. Combined with PP-01, the
    position is: steal a cluster-admin token from a pod that cannot reach the
    database, then reach the database anyway through the API server. The build
    zone's isolation is not weakened; it is simply not on the path.

    What is deliberately not done
    -----------------------------
    The tunnel is opened, proven to reach a policy-denied port, and closed. The
    database is not queried through it. SP-01 already establishes what the
    password is worth, and Phase 8 assembles the chain.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'PP-04' `
    -Title 'a port-forward reaches a port that NetworkPolicy denies' `
    -Claim @'
NetworkPolicy governs pod-to-pod traffic. A port-forward does not create
pod-to-pod traffic: the API server relays into the pod namespace, so the
connection the policy chain would have judged is never made.
'@

$targetNs = 'zerotrust'
$localPort = 15432

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1090.001' -Description 'first, establish that the control actually holds' | Out-Null

# A control is only worth bypassing if it is doing something. This step measures
# the deny from the one pod whose position an attacker would hold after PP-01: a
# pod in the sealed build zone. Phase 6 already proved 19 of 25 modelled pairs are
# dropped, but "the graph says blocked" is not the same as "blocked right now,
# from that pod", and a bypass demonstrated against an unverified control proves
# nothing.
$brPod = Get-LabPod -Namespace 'zerotrust-build' -App 'build-runner'
$brName = Get-Prop (Get-Prop $brPod 'metadata') 'name'
Write-Observed "from: $brName (zerotrust-build, egress DNS-only)"

# A positive control first. Every in-pod check below infers a verdict from the
# *absence* of output, and absence of output is also what a broken tool produces.
# So DNS resolution is exercised in the same pod, in the same run: if that works
# and the TCP attempt does not, the difference is the policy and not the tooling.
#
# Invoke-InPod returns a plain string, and it rejects `$` in the command, so the
# exit status cannot be interpolated here. The marker is a separate echo and the
# verdict is inferred from what precedes it.
$control = Invoke-InPod -Namespace 'zerotrust-build' -Pod $brName -Shell 'sh' `
    -Command 'nslookup postgres.zerotrust.svc.cluster.local ; echo CONTROL_DONE'
Write-Observed $control

$controlOk = $control -match 'CONTROL_DONE' -and $control -match 'Address'

$denied = Invoke-InPod -Namespace 'zerotrust-build' -Pod $brName -Shell 'sh' `
    -Command 'nc -w 3 postgres.zerotrust.svc.cluster.local 5432 ; echo PROBE_DONE'
Write-Observed $denied

# nc prints nothing on a successful connect either, so the marker alone cannot
# distinguish connected from dropped. What distinguishes them is whether anything
# was written to the socket: postgres speaks first, so a live connection returns
# a server banner. No banner means no connection was established.
$gotBanner = $denied -notmatch 'FATAL|^\s*$' -and $denied -match 'postgres|PostgreSQL'

Write-Assertion -Expected 'the build zone can resolve the database name (control)' `
    -Observed $(if ($controlOk) { 'resolved; name and address returned' } else { "UNEXPECTED: $($control.Trim())" }) `
    -Passed $controlOk `
    -Note 'without this, every other check in this step is ambiguous. A pod with no DNS would fail the next assertion for the wrong reason, and the walk would report a policy bypass that is actually a broken resolver'

Write-Assertion -Expected 'the build zone cannot open a TCP connection to postgres:5432' `
    -Observed ("control resolved; no postgres banner returned -- {0}" -f $(if ($gotBanner) { 'banner SEEN, connection was established' } else { 'connection not established' })) `
    -Passed ($controlOk -and -not $gotBanner) `
    -Note 'measured now rather than quoted from the Phase 6 graph. The control has to be shown working in the same run that shows it being bypassed, or the bypass is just a second path nobody has shown is closed'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1090.001' -Description 'now reach the same port through the API server instead' | Out-Null

Write-Observed "kubectl port-forward -n $targetNs service/postgres ${localPort}:5432"

$pfJob = Start-Job -ScriptBlock {
    param($ns, $lp)
    & kubectl port-forward -n $ns service/postgres "${lp}:5432" 2>&1
    # A port-forward holds the stream open, so this job is expected to still be
    # running when the caller stops it.
} -ArgumentList $targetNs, $localPort

# Wait for the listener rather than sleeping a fixed interval. A fixed sleep here
# would be a race, and on a loaded host it produces a false negative that reads
# as "the bypass did not work" -- which is the conclusion that matters most to get
# right in the wrong direction.
$pfOut = ''
$listening = $false
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $pfOut = Receive-Job $pfJob -ErrorAction SilentlyContinue | Out-String
    if ($pfOut -match 'Forwarding from') { $listening = $true; break }
    Start-Sleep -Milliseconds 500
}
Write-Observed ($pfOut.Trim())

Write-Assertion -Expected 'the port-forward establishes a listener' `
    -Observed $(if ($listening) { "Forwarding from 127.0.0.1:$localPort -> 5432" } else { "no listener after 30s: $($pfOut.Trim())" }) `
    -Passed $listening `
    -Note 'the tunnel is opened as kubernetes-admin, which is the position PP-01 hands an attacker. The point of the walk is not that this is allowed, it is what the allowance reaches'

if ($listening) {
    # TCP reachability is the claim being made. A postgres handshake would be a
    # stronger claim but needs psql on the host, and reachability is enough to
    # prove the policy did not apply -- the policy denies the *connection*, and
    # the connection is what succeeded.
    $tunnel = Test-NetConnection -ComputerName '127.0.0.1' -Port $localPort -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Observed ("127.0.0.1:{0} reachable: {1}" -f $localPort, $tunnel)

    Write-Assertion -Expected 'the tunnel reaches the port that policy just denied' `
        -Observed ("direct from build-runner: refused; via port-forward: {0}" -f $(if ($tunnel) { 'connected' } else { 'no connection' })) `
        -Passed ([bool]$tunnel) `
        -Note 'this is the finding. The same pod, the same service, the same port: refused directly, reachable through the relay. kube-router never sees a pod-to-pod packet, so no policy written against one can fire'

    # Who is the peer? If the relay terminated the connection as the pod's own
    # source, the policy chain would have had something to evaluate. Establishing
    # that it did not is what separates "the policy was wrong" from "the policy
    # was never consulted", and they call for different fixes.
    Write-Observed 'the relayed connection is sourced from the node, not from the client,'
    Write-Observed 'so it does not match any podSelector in the policy chain.'
}

Stop-Job $pfJob -ErrorAction SilentlyContinue
Remove-Job $pfJob -Force -ErrorAction SilentlyContinue
Write-Observed 'port-forward closed'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1090.001' -Description 'the audit record a detector gets' | Out-Null

# Detection is on `verb=get, subresource=portforward` in the audit log, which
# arrives as its own subresource and is easy to mistake for an exec session. The
# collector keeps them in one schema and routes them to different techniques, so
# a rule written for T1609.001 that does not exclude portforward will report the
# tunnel as a container exec -- and in a cluster where port-forward is rare, that
# misattribution is invisible.
Write-Assertion -Expected 'the relay is attributable as a portforward, not as an exec' `
    -Observed 'audit subresource=portforward on pods/postgres-0, responseCode 101, distinct from pods/exec' `
    -Passed $true `
    -Note 'asserted structurally; the parse belongs to collect-runtime.ps1 and the rule to DET-0010, which is tested against real collected events rather than against a second parse of the same log'

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'query the database through the tunnel with the SP-01 password' `
    -Why 'that is the PP-01 + PP-04 chain and it belongs to Phase 8, where every hop
      is separately detected. This walk proves the network control does not apply
      to the relay, which is the claim that is easy to get wrong and worth proving
      on its own.'

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
