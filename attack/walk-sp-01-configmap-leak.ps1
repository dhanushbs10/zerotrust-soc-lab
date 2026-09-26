<#
    Walks SP-01: the database password sits in a ConfigMap in plaintext, twice.

    T1552.001 Unsecured Credentials: Credentials In Files

    What the catalogue claims, and what is actually true
    ---------------------------------------------------
    The catalogue frames SP-01 as an unprivileged workload stealing the database
    password. Measured, that is not what this cluster has:

        sa-web-frontend       get configmaps/app-config-leak  ->  no
        sa-orders-api         get configmaps/app-config-leak  ->  no
        sa-telemetry-agent    get configmaps/app-config-leak  ->  no
        sa-build-runner       get configmaps/app-config-leak  ->  yes   (cluster-admin)

    sa-orders-api can read configmaps in zerotrust, but its Role is narrowed
    with resourceNames to orders-api-config, so the leak is outside it. The only
    identity that can read this ConfigMap is the one that already owns the
    entire cluster. So "an attacker with a foothold reads the DB password" is
    false here, and a walk that demonstrated it would be demonstrating a
    vulnerability the lab does not have.

    The real finding is narrower and sharper, and it is about what the duplicate
    costs rather than who can reach it:

    1. The credential is live, and it is a superuser credential. Proven below
       by a controlled authentication test, not assumed.
    2. PP-01 does not need to decode base64 to get it. A stolen cluster-admin
       token reads this ConfigMap as plain text, which is a smaller and quieter
       step than reading a Secret.
    3. The rotation trap. Rotating the Secret does not touch this ConfigMap.
       An operator who rotates postgres-credentials and considers the job done
       has left the previous password sitting in the cluster in clear text, and
       the only way to tell the two apart is to compare fingerprints. That is
       the failure mode this finding is really about, and it is the reason the
       walk measures the password against the Secret rather than just displaying
       it.

    The vantage point, stated honestly
    ---------------------------------
    The obvious way to prove the password works is to connect with it. Done over
    the postgres pod's loopback address, that test is worthless, and it fails
    silently in the most dangerous way possible:

        psql -h 127.0.0.1 ...            no password   -> succeeds
        PGPASSWORD=wrong psql -h 127.0.0.1 ...           -> succeeds

    Both succeed, because pg_hba.conf rule 2 trusts 127.0.0.1. A demo written
    that way would have "proved" the leaked password works while actually proving
    that the database ignores passwords entirely.

    The test below therefore goes to the pod's own routable address, where
    pg_hba.conf rule 7 applies scram-sha-256, and it runs the same query three
    times with three different passwords. One route, one variable, two failures
    and one success. That is what makes it a measurement.
#>

. "$PSScriptRoot\lib\attacklib.ps1"

if (-not (Assert-ClusterReady)) { exit 1 }

Write-Banner -PathId 'SP-01' `
    -Title 'the database password is duplicated in a ConfigMap, in plaintext' `
    -Claim @'
A credential copied into a second store is not a smaller risk than the original.
It is a second copy that nothing rotates, an extra path into the same secret,
and a place where an operator who believes they have revoked access is wrong.
The copy is verified live here rather than displayed and assumed.
'@

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1552.001' -Description 'the credential is present in plaintext, and it is present twice' | Out-Null

$cm = (& kubectl get configmap app-config-leak -n zerotrust -o json 2>$null | Out-String | ConvertFrom-Json)
$cmData = Get-Prop $cm 'data'
$leakedPw = Get-Prop $cmData 'DB_PASSWORD'
$leakedUrl = Get-Prop $cmData 'DATABASE_URL'
$note = Get-Prop $cmData 'NOTE'

Write-Observed 'app-config-leak, keys and shapes only -- values are not reprinted:'
Write-Observed ("  DB_PASSWORD  : {0} characters" -f $leakedPw.Length)
Write-Observed ("  DATABASE_URL : {0} characters, scheme {1}, embeds the same password at offset {2}" -f `
    $leakedUrl.Length, ($leakedUrl -split ':')[0], $leakedUrl.IndexOf($leakedPw))
Write-Observed ("  NOTE         : {0}" -f $note)

Write-Assertion -Expected 'a credential is stored in a ConfigMap in clear text' `
    -Observed ("DB_PASSWORD present, {0} characters, not base64 of anything" -f $leakedPw.Length) `
    -Passed ($leakedPw.Length -gt 0) `
    -Note 'ConfigMap data is stored in etcd as plain text. A Secret differs only in that its value is base64, which is encoding and not encryption'

Write-Assertion -Expected 'the same credential appears a second time inside a connection string' `
    -Observed ("DATABASE_URL embeds DB_PASSWORD verbatim at offset {0}" -f $leakedUrl.IndexOf($leakedPw)) `
    -Passed ($leakedUrl.Contains($leakedPw)) `
    -Note 'two copies means two things to rotate. An operator who rotates the Secret has fixed one of them and does not know it'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1552.001' -Description 'establish who can actually reach it, because the answer is not who you would guess' | Out-Null

$readers = @(
    'system:serviceaccount:zerotrust:sa-web-frontend'
    'system:serviceaccount:zerotrust:sa-orders-api'
    'system:serviceaccount:zerotrust-build:sa-build-runner'
    'system:serviceaccount:zerotrust-observe:sa-telemetry-agent'
)
# Split deliberately. sa-build-runner is in the list because it is the identity
# PP-01 hands out, and it is the one that can read this. Folding it in with the
# ordinary workloads and then asserting "none of them can read it" produced a
# check that contradicted the very next line of its own output.
$readers = @(
    @{ id = 'system:serviceaccount:zerotrust:sa-web-frontend';            ordinary = $true }
    @{ id = 'system:serviceaccount:zerotrust:sa-orders-api';              ordinary = $true }
    @{ id = 'system:serviceaccount:zerotrust-observe:sa-telemetry-agent';  ordinary = $true }
    @{ id = 'system:serviceaccount:zerotrust-build:sa-build-runner';      ordinary = $false }
)

$ordinaryVerdicts = @()
$adminVerdicts = @()
foreach ($r0 in $readers) {
    $ns = ($r0.id -split ':')[2]
    $r = Invoke-Kubectl @('auth', 'can-i', 'get', 'configmaps/app-config-leak', '-n', $ns, ('--as=' + $r0.id))
    Write-Observed ("  {0,-52} -> {1}" -f $r0.id, $r.verdict)
    if ($r0.ordinary) { $ordinaryVerdicts += $r.verdict } else { $adminVerdicts += $r.verdict }
}

# kubectl answers "yes", "no", or an error, and all three arrive as a string. An
# errored call is not a refusal. An earlier version of this block passed on four
# errored calls, because none of them contained the word yes -- a check that
# passed because the command was malformed.
$allAnswers  = @($ordinaryVerdicts + $adminVerdicts)
$answerCount = @($allAnswers | Where-Object { $_ -eq 'yes' -or $_ -eq 'no' }).Count
$allAuthorizerAnswers = ($answerCount -eq $allAnswers.Count)

$ordinaryCanRead = @($ordinaryVerdicts | Where-Object { $_ -eq 'yes' })
$adminCanRead    = @($adminVerdicts   | Where-Object { $_ -eq 'yes' })

Write-Assertion -Expected 'every reachability check returned a real authorization answer' `
    -Observed ("{0} of {1} answered yes or no" -f $answerCount, $allAnswers.Count) `
    -Passed $allAuthorizerAnswers `
    -Note 'guards the two assertions below. Without it a typo in the kubectl arguments produces errors, none of which is the word yes, and the check that matters passes having measured nothing at all'

Write-Assertion -Expected 'no ordinary workload identity can read the leak' `
    -Observed ("{0} of {1} non-admin service accounts can read it" -f $ordinaryCanRead.Count, $ordinaryVerdicts.Count) `
    -Passed ($allAuthorizerAnswers -and $ordinaryCanRead.Count -eq 0) `
    -Note 'sa-orders-api can read configmaps in this namespace, but its Role carries resourceNames: [orders-api-config], so the leak is outside the grant. That is a real control, and it is why SP-01 is a weaker finding than the catalogue implies'

Write-Assertion -Expected 'the one identity that can read it is the one that already owns everything' `
    -Observed ("{0} of {1} admin identity can read it" -f $adminCanRead.Count, $adminVerdicts.Count) `
    -Passed ($allAuthorizerAnswers -and $adminCanRead.Count -eq $adminVerdicts.Count) `
    -Note 'so the exposure is not privilege escalation. It is that PP-01 has a second and quieter route to the same secret -- ConfigMap data needs no base64 decode -- and that a credential copied here outlives the rotation meant to revoke it'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1552.001' -Description 'confirm the copy is the live credential and not a stale duplicate' | Out-Null

$secretB64 = (& kubectl get secret postgres-credentials -n zerotrust -o jsonpath='{.data.password}' 2>$null | Out-String).Trim()
$secretPlain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secretB64))
$fpLeaked = Get-Fingerprint $leakedPw
$fpSecret = Get-Fingerprint $secretPlain

Write-Observed ("  ConfigMap copy, fingerprint : {0}" -f $fpLeaked)
Write-Observed ("  Secret copy,    fingerprint : {0}" -f $fpSecret)

Write-Assertion -Expected 'the ConfigMap copy and the Secret are the same credential' `
    -Observed ("both fingerprint to {0}" -f $(if ($fpLeaked -eq $fpSecret) { $fpLeaked } else { "$fpLeaked vs $fpSecret" })) `
    -Passed ($fpLeaked -eq $fpSecret) `
    -Note 'measured by fingerprint so the values are never printed. tools/scan-secrets.ps1 uses the same algorithm, so this script and the scanner agree on which copy is which -- and a disagreement would mean one of them is wrong'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1552.001' -Description 'prove it is a working credential, on the route where passwords are actually checked' | Out-Null

$pg = Get-LabPod -Namespace 'zerotrust' -App 'postgres'
$pgName = Get-Prop (Get-Prop $pg 'metadata') 'name'
$pgIP = Get-Prop (Get-Prop $pg 'status') 'podIP'

Write-Observed 'The database accepts trust authentication on loopback, so loopback proves nothing:'
$loopNoPw = Get-LastLine (Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command 'psql -h 127.0.0.1 -U orders -d acme -t -A -c select\ current_user -w')
$loopWrong = Get-LastLine (Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command 'PGPASSWORD=deliberately-wrong psql -h 127.0.0.1 -U orders -d acme -t -A -c select\ current_user')
Write-Observed ("  loopback, no password    -> {0}" -f $loopNoPw)
Write-Observed ("  loopback, wrong password -> {0}" -f $loopWrong)
Write-Observed '  so the test below uses the routable pod address, where rule 7 of pg_hba.conf applies scram-sha-256.'

Write-Assertion -Expected 'loopback accepts any password, so it cannot be used to test one' `
    -Observed ("no password and a wrong password both returned {0}" -f $loopWrong) `
    -Passed ($loopNoPw -eq 'orders' -and $loopWrong -eq 'orders') `
    -Note 'this is an assertion about the lab being inadequate, not about a weakness. Without it the next three assertions would be reporting a credential that works for the wrong reason'

# One route, one variable, three passwords. The two failures are what make the
# success mean anything.
$authNoPw    = Get-LastLine (Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command "psql -h $pgIP -U orders -d acme -t -A -c select\ current_user -w")
$authWrong   = Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command "PGPASSWORD=deliberately-wrong psql -h $pgIP -U orders -d acme -t -A -c select\ current_user"
$authLeaked  = Get-LastLine (Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command "PGPASSWORD=$leakedPw psql -h $pgIP -U orders -d acme -t -A -c select\ current_user")

# The refusal text wraps across lines in the captured output, and there are two
# spaces after "FATAL:", so a single-line -match against the raw capture misses
# a message that is plainly present. Collapse whitespace first, then match.
# Defined before the display block that reads it: under Set-StrictMode a
# use-before-assignment is a hard error that prints an empty line and carries on.
$authWrongFlat = ($authWrong -replace '\s+', ' ')

Write-Observed ''
Write-Observed "  same route, same query, three passwords, against ${pgIP}:5432"
Write-Observed ("    no password     -> {0}" -f $(if ($authNoPw -eq 'orders') { 'SUCCEEDED (no password needed)' } else { 'refused' }))
Write-Observed ("    wrong password  -> {0}" -f $(if ($authWrongFlat -match 'password authentication failed') { 'refused: password authentication failed for user "orders"' } else { 'refused: ' + $authWrongFlat }))
Write-Observed ("    leaked password -> {0}" -f $authLeaked)

Write-Assertion -Expected 'the connection is refused when no password is supplied' `
    -Observed $(if ($authNoPw -eq 'orders') { 'SUCCEEDED, which would invalidate this test' } else { 'refused' }) `
    -Passed ($authNoPw -ne 'orders') `
    -Note 'if this ever passes trivially, the test has stopped discriminating and every assertion below it is meaningless'

Write-Assertion -Expected 'the refusal is a real authentication failure, not a crash' `
    -Observed $(if ($authWrongFlat -match 'password authentication failed for user "orders"') { 'FATAL: password authentication failed for user "orders"' } else { "unrecognised: " + $authWrongFlat.Substring(0, [Math]::Min(90, $authWrongFlat.Length)) }) `
    -Passed ($authWrongFlat -match 'password authentication failed for user "orders"') `
    -Note 'the PP-01 harness learned this the hard way: a check that cannot tell a refusal from a crash is not a check'

Write-Assertion -Expected 'the leaked password is the one that authenticates' `
    -Observed ("connected as {0}" -f $authLeaked) `
    -Passed ($authLeaked -eq 'orders') `
    -Note 'this is the finding. Not that a password is visible, but that this specific visible password is a current, valid, superuser credential for the business database'

# ---------------------------------------------------------------------------
Write-Step -AttackId 'T1552.001' -Description 'establish what the credential is actually worth' | Out-Null

$privs = Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' `
    -Command "PGPASSWORD=$leakedPw psql -h $pgIP -U orders -d acme -c select\ rolname,\ rolsuper,\ rolcreatedb,\ rolcreaterole\ from\ pg_roles\ where\ rolname\ =\ current_user"
Write-Observed 'privilege level of the role this password authenticates as:'
$privs -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Observed "  $($_.Trim())" } }

$isSuper = ($privs -match 'orders\s*\|\s*t')

Write-Assertion -Expected 'the leaked credential authenticates as a SUPERUSER role' `
    -Observed $(if ($isSuper) { 'rolsuper = t' } else { 'rolsuper = f' }) `
    -Passed $isSuper `
    -Note 'not a read-only reporting role. Whoever holds it can create databases and roles, read every table, and write to all of them. The word "orders" in the role name suggests a scoped account and the privilege says otherwise'

Write-Observed ''
Write-Observed 'read-only confirmation of what that reaches:'
Write-Observed (Invoke-InPod -Namespace 'zerotrust' -Pod $pgName -Shell 'sh' -Command "PGPASSWORD=$leakedPw psql -h $pgIP -U orders -d acme -c select\ customer,\ total,\ status\ from\ orders\ limit\ 3")

# ---------------------------------------------------------------------------
Write-Withheld -WouldDo 'write to the database: insert, update or delete a row' `
    -Why @'
this is a superuser credential against a business database that currently holds
four orders, and a write would leave evidence in the data the lab is built
around. Every path in this directory is read-only for that reason, and a
detection written against SP-01 has to be testable twice.

  To run it deliberately:

    PGPASSWORD=<leaked> psql -h <pod-ip> -U orders -d acme \
      -c "insert into orders (customer, total, status) values ('probe', 0.01, 'pending')"

  and then remove it again:

    ... -c "delete from orders where customer = 'probe'"
'@

Write-Withheld -WouldDo 'rotate the Secret and show that the ConfigMap copy still authenticates' `
    -Why @'
this is the sharpest version of the finding and it is deliberately not run. It is
a cluster mutation, and if the ConfigMap copy survives rotation it would mean
the rotation was incomplete -- a real and reportable condition, but not one to
create inside a lab whose own credential the harness uses to verify state.

The argument does not need the rotation performed in order to stand. The
mechanism is sufficient by itself: a copy that nothing rotates is a copy that
outlives the rotation meant to revoke it. Verifying that by measurement belongs
to Phase 8, where a rotation can be done and undone deliberately rather than as
a side effect of reading a finding.
'@

$failed = Complete-Attack
exit $(if ($failed -gt 0) { 1 } else { 0 })
