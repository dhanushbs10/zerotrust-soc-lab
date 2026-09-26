# attack/ — walking the privilege paths

Every weakness this lab claims is walked here by script, against the running
cluster, and asserted. Not described. Not illustrated. Walked.

```
attack\
  run-all.ps1                        run every path, one verdict, machine-readable summary
  lib\attacklib.ps1                  shared harness: output formatting, assertions, kubectl plumbing
  catalog\privilege-paths.md         the claims, the ATT&CK ids, and what measurement changed
  walk-pp-01-cluster-admin.ps1       10 assertions
  walk-pp-02-sensor-reach.ps1        7 assertions
  walk-wp-01-frontend-root.ps1        9 assertions
  walk-wp-02-sensor-token.ps1        5 assertions
  walk-sp-01-configmap-leak.ps1      11 assertions
```

## Running them

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\attack\run-all.ps1
```

Exit 0 means every path's assertions held. Exit 1 means at least one changed
shape — which is a finding about the lab, not a bug in the script. One path at a
time:

```
.\attack\run-all.ps1 -Only PP-01
```

`-ContinueOnFailure` keeps going past a failure so one broken path does not hide
the state of the other four. The exit code still reflects it.

The runner also writes `.telemetry/walk-summary.json` — verdicts, counts and
ATT&CK ids, and deliberately no credential, token or password. Later phases read
that file rather than re-deriving anything from console output, because parsing
human-readable text is how a lab ends up asserting things nobody measured.

## What the scripts do and do not do

**Everything is read-only.** The walks read tokens, present credentials and
connect to the database, and they change nothing: no cluster object is created,
patched or deleted, and no row is written. This is not caution for its own sake.
A detection has to be testable twice against the same state, and a demo that can
only be run once cannot be used to check a rule twice.

Where a path has an irreversible next step, the script stops and prints the exact
command under `withheld`, with the reason. Those commands are written to be
copied deliberately, not stumbled into.

**No fabricated results.** Every `-Observed` value is measured at runtime and
printed next to the verdict it justifies. Early versions of these scripts
hardcoded the observed text, which is how a report ends up describing a lab that
does not exist. If a number appears in this directory it came from the cluster
during that run.

**The assertions can fail, and that is tested.** A harness that always passes is
indistinguishable from no harness. `run-all.ps1` distinguishes three failure
modes and reports each differently:

| verdict | meaning |
|---------|---------|
| `walkable` | exit 0, every assertion held |
| `CHANGED` | a path's claim no longer matches reality — the interesting failure |
| `ERRORED` | non-zero exit with no failed assertion — a broken prerequisite, not a finding |
| `MISSING` | the walk script is not there |

The distinction between `CHANGED` and `ERRORED` is deliberate. A path that
crashes has told you nothing about the lab, and reporting it as a changed finding
would be worse than reporting nothing.

## The five paths, and what each one is really about

| ID | Claim | ATT&CK |
|----|-------|--------|
| PP-01 | A token copied out of a sealed zone still carries cluster-admin | T1078.001, T1190, T1550.001 |
| PP-02 | The sensor can see three open doors and holds no key to any of them | T1046, T1550.001 |
| WP-01 | Root in a user-facing pod, measured against the same image hardened | T1610, T1611 |
| WP-02 | The same pod setting as PP-01, with the opposite blast radius | T1550.001 |
| SP-01 | A duplicated credential that is live, superuser, and never rotated | T1552.001 |

Three of these were catalogued as something other than what measurement showed,
and the corrections are recorded in `catalog/privilege-paths.md` rather than
quietly applied. In summary:

- **PP-01** could not be walked from inside the build pod, because that zone
  cannot reach the API server. The lesson is sharper for it: a NetworkPolicy
  constrains a workload, and a copied credential is no longer a workload.
- **WP-01** does not omit its `securityContext`. It sets `runAsNonRoot: false`.
- **WP-02**'s token is not worth nothing — it inherits `system:basic-user` and
  the public discovery URLs, as every authenticated identity does.
- **SP-01** is readable by no ordinary workload identity. It is not privilege
  escalation; it is a rotation failure waiting to happen.

## Harness notes that will cost someone time otherwise

These are Windows PowerShell 5.1 behaviours, all of them discovered the hard way
and all of them capable of producing a *plausible wrong answer* rather than an
error. `lib/attacklib.ps1` guards against the ones it can detect.

**PowerShell binds `,` tighter than `+`.** This is the expensive one.

```powershell
@('--kubeconfig=' + $k, '--token=' + $t, 'get', 'secrets')
```

is not an eight-element array. It is **one** element containing all of it,
space-joined, because the expression parses as
`'--kubeconfig=' + ($k, ('--token=' + $t, 'get', 'secrets'))` and string-plus-array
yields a space-separated string. kubectl receives one enormous argument, prints
its usage text, and exits 1.

The same mistake written without a trailing comma takes the opposite shape —
`'--as=' + $id` arrives as **two** arguments, and kubectl reports
`you must specify two arguments: verb resource`, which points nowhere near the
cause. `Invoke-Kubectl` throws on both signatures.

Every concatenation in an argument array needs its own parentheses:
`@(('--kubeconfig=' + $k), ('--token=' + $t), 'get', 'secrets')`.

**In-pod commands must be quote-free.** PowerShell hands the argument to
`kubectl.exe` having stripped any embedded double quotes, so

```powershell
Invoke-InPod -Command 'env | grep -ciE "^(PG|DATABASE|DB_)"'
```

reaches the pod's shell as `env | grep -ciE ^(PG|DATABASE|DB_)` — quoting gone —
and answers `sh: syntax error: unexpected "("`. That one is at least loud. The
dangerous case is a command that merely *misbehaves* once its quoting is stripped
and returns a plausible wrong number. Write group alternation as repeated
patterns: `grep -ci -e ^PG -e ^DATABASE -e ^DB_`.

Piping a script in on stdin is **not** an escape. Windows PowerShell 5.1 has no
input redirection at all (`<` is "reserved for future use"), and `Get-Content`
piped to a native command re-emits every line with CRLF, which busybox `sh`
rejects — `for x in a b c; do` fails with `syntax error: unexpected word
(expecting "do")` whether the source file was LF or CRLF, because the corruption
happens in the PowerShell pipeline rather than in the file. So the rule stands:
keep in-pod commands simple enough to pass as one argument.

**`Get-LastLine` must out-filter PowerShell.** A naive "last non-empty line" on
captured native output returns PowerShell's error decoration rather than the
command's verdict, and the position line has **two** spellings depending on
where the failing call sits:

```
At line:281 char:12                                       (top level of a script)
At D:\path\attacklib.ps1:281 char:12                      (inside a dot-sourced function)
```

Filtering only the first form let a file path through as a verdict.

**Other traps that produce silence rather than errors**

- `$obj.prop` resolves correctly in a comparison against `[ordered]@{}` but
  **stringifies the dictionary** inside a double-quoted string. Use `-f`.
- Reading `$loopVar` *after* a `foreach` gives only the final iteration. Collect
  into an array inside the loop.
- An `error` from `kubectl` is not a `no`. A set of `can-i` calls that all failed
  will still satisfy "none of them returned yes", so the walk asserts that every
  call returned a real yes-or-no before asserting anything about the yeses.
- `$LASTEXITCODE` must be read before a pipeline is drained by `Out-String`.
- Under `Set-StrictMode`, a use-before-assignment is a hard error that prints a
  blank line and keeps going.
- `Set-Content -Encoding utf8` under PS 5.1 emits CRLF and a BOM.

## Adding a path

1. Write `walk-<id>-<slug>.ps1`, dot-source the lib, and use the harness rather
   than `Write-Host` — the formatting, the pass/fail accounting and the exit code
   all come from `Write-Banner`, `Write-Step`, `Write-Observed`,
   `Write-Assertion`, `Write-Withheld` and `Complete-Attack`.
2. Add a `## <ID> - ...` section to `catalog/privilege-paths.md` with its ATT&CK
   ids. The runner cross-checks the two, in both directions, and fails if an
   entry exists in only one place.
3. Add it to the `$paths` table in `run-all.ps1`.
4. Run `run-all.ps1` and confirm it reports `walkable`.

If a walk cannot hold its assertion, that is not a reason to relax the
assertion. It is a finding, and it belongs in the catalogue with what it means.
