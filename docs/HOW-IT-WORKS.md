# How ZeroTrust-SOC-Lab works, from the beginning

A reading guide. Everything here is meant to be followed with the code open, in the order
given, because the order is most of the explanation: each layer exists because the one below
it could not answer a question.

If you only read one section, read [2. The three trust zones](#2-the-three-trust-zones) and
[7. Why a collector refuses to guess](#7-why-a-collector-refuses-to-guess). Those two carry
the design.

---

## 1. The question the lab asks

> You have a Kubernetes cluster with network policies, workload identities and RBAC. An
> attacker gets in. **Do you notice, and can you prove what you noticed?**

Almost any cluster answers the first half. `kubectl get pods` will show a pod you did not
create. The second half is the hard one, and it is where security work usually goes wrong:
a dashboard that shows a red number with no way to get back to the evidence that produced it.

So this lab is built backwards from the evidence. For every claim the console makes, there
has to be a file you can open and a line in it you can check. If a number cannot be traced
to a record, it does not get shown.

Three things are therefore always true here, and they are the reason the code looks the way
it does:

1. **Nothing is simulated.** The cluster is a real kind cluster, the policies are real
   NetworkPolicies enforced by kube-router, the attacks are real `kubectl` invocations
   against the real API server, and the telemetry is real audit-log and iptables-counter
   data read off the running system.
2. **Every claim is ATT&CK-tagged**, including the ones that are *not* attacks. A
   privilege path, a telemetry rule and a detection each carry the technique ID they
   represent, and the registry that maps them is a file you can read and argue with.
3. **Every check can fail.** A gate that cannot fail is not a gate. This is enforced
   actively — see [8. The mutation harness](#8-the-mutation-harness) — and it is the single
   most-repeated idea in the repository.

---

## 2. The three trust zones

Three namespaces, and the boundaries between them are the point of the exercise.

| Namespace | What lives there | Its problem |
|---|---|---|
| `zerotrust` | `web-frontend`, `orders-api`, `postgres-0` | the business zone. Holds the credential everything else leaks. |
| `zerotrust-build` | `build-runner` | **bound to `cluster-admin`.** This is the lab's central deliberate hole. |
| `zerotrust-observe` | `telemetry-agent` | the lab's own sensor. Grants it observation-only ingress into the business zone. |

Read `identities/00-namespaces.yaml` and `identities/20-rbac.yaml` first. The RBAC file is
short and the reason is in a comment near the top: a build runner holding `cluster-admin` is
not a mistake, it is the fixture. Everything downstream — the privilege paths, the chain, the
detections — exists to answer "what can someone do with that, and what does it look like".

### Why native NetworkPolicies and not a service mesh

The brief asked for native NetworkPolicies. Beyond that, the argument is that a mesh would
hide the thing being taught. With kube-router, the policy objects *are* the enforcement, and
you can go read the iptables chain and see the counter move. A mesh adds a second
implementation of "who may talk to whom" whose relationship to the policy objects is a
matter of configuration — and then a lab about trust boundaries is itself an unexamined trust
boundary.

The enforcement point is per-pod, and that is what makes the counter-based telemetry in
[6](#6-telemetry-seven-schemas) work at all.

### Default-deny, both directions

`identities/31-networkpolicy-default-deny.yaml` denies all ingress and all egress in all
three zones. Everything that is permitted after that is an explicit, reviewable grant. This
matters for reading the attack paths: every "it reached X" in this lab is a statement about
a policy that was written down.

`tools/test-boundaries.ps1` exercises the semantics of those policies directly — including
the cases that are easy to get wrong, like an empty `namespaceSelector` meaning *every*
namespace, and an Egress-only policy not isolating a pod for ingress at all.

---

## 3. Credentials, and the one that leaks

`secrets/credentials.yaml` is **generated at apply time** and gitignored. Only
`credentials.example.yaml` is tracked. `cluster/bootstrap/secrets.ps1` creates it.

This is not only a hygiene decision. The database password exists twice:

- in a `Secret`, mounted into `postgres` and `orders-api`;
- in a `ConfigMap`, which `orders-api` also reads.

`attack/walk-sp-01-configmap-leak.ps1` proves that reading the ConfigMap copy is enough to
reach the database. A credential in a Secret is a credential with an access-control story
attached; the same credential in a ConfigMap is usually just a value in a file that half the
namespace can read. The lab exists to make that difference observable.

`tools/scan-secrets.ps1` and a gitleaks pre-commit hook both run over tracked files. Both
test files in `dashboard/` *discover* the real password from the gitignored telemetry at
runtime rather than hardcoding a fixture — a hardcoded test fixture is a committed secret,
and that is not a hypothetical: gitleaks caught exactly that in this repository once already.

---

## 4. The privilege paths

`attack/run-all.ps1` runs all seven. Each script is a walk: it performs one movement and
then **asserts** what should now be true, so a path that "succeeded" without proving anything
is a failure rather than a pass.

| Script | Class | What it proves |
|---|---|---|
| `walk-wp-01-frontend-root.ps1` | workload | the web frontend is reachable and serves without authentication |
| `walk-wp-02-sensor-token.ps1` | workload | the sensor's token can be read off a pod that cannot otherwise use it |
| `walk-sp-01-configmap-leak.ps1` | service | the ConfigMap copy of the DB password is readable from the business zone |
| `walk-pp-01-cluster-admin.ps1` | privilege | `sa-build-runner`'s `cluster-admin` is usable, and does not stop at the API |
| `walk-pp-02-sensor-reach.ps1` | privilege | the sensor's observation grants are real, and grant nothing more |
| `walk-pp-03-token-mint.ps1` | privilege | a token can be minted for a service account by a non-kubelet caller |
| `walk-pp-04-portforward.ps1` | privilege | a policy-denied port is reachable through the API server's port-forward |

Two of these are worth reading closely because they are the ones that are easy to dismiss:

- **PP-02** is a *control* path, not an attack. It walks a permission that is supposed to
  exist and asserts it exists and grants nothing else. A control you never test is a
  control you do not have.
- **PP-04** is the one that surprises people. `kubectl port-forward` traffic does not pass
  through the pod's NetworkPolicy, because it is tunnelled through the API server. A zone
  boundary enforced only with NetworkPolicy does not contain someone with API access. The
  telemetry catches the attempt because the audit log records `pods/portforward` — a
  completely different signal from any network rule.

`run-all.ps1` continues past a failing path on purpose (the paths are independent), and
re-runs a failure once to tell a **flaky** path from a **changed** one. Conflating those two
is how a suite gets ignored.

---

## 5. The reachability graph

`graph/build-reachability.ps1` answers a question manifests cannot: *what is actually
reachable from here?*

The model is derived from the NetworkPolicy objects, and then **probed** — real pods,
real connections — and the two are compared. `.telemetry/reachability-graph.json` is the
claim; `reachability-verify.json` is whether reality agreed.

The probe design has rules that took several iterations to get right, and they are worth
knowing because each one fixes a way the answer was previously wrong:

- A probe pod must carry the **real workload's `app` label**. A probe with a unique label
  matches no `podSelector` and silently tests nothing.
- **One probe alive at a time.** Two probes with the same label double every measurement.
- Each probe has a **DNS positive control** — if DNS fails you have proved nothing about
  the port you were testing.
- Drops are timed **in-pod from `/proc/uptime`**, because measuring across `kubectl exec`
  measures your own latency. The 600 ms threshold exists to separate "refused" from
  "timed out"; anything faster than that was not a policy decision.
- An edge appears in the graph only for a **modelled-open** pair, and a policy is judged
  **enforced in both directions**.

The graph currently has 5 nodes and 6 open edges. Probe verification compared **25**
cases — every reachable pair plus the blocked ones it had to confirm were actually blocked —
and all 25 agreed with the model.

---

## 6. Telemetry: seven schemas

Three collectors. Everything lands in `.telemetry/`, which is gitignored — the evidence is
local and is not committed.

| Schema | Source | Carries |
|---|---|---|
| `network/denial-counter/v1` | kube-router iptables counters | refused-packet counts per pod, as **deltas** |
| `network/observed-flow/v1` | conntrack | permitted pod-to-pod connections |
| `runtime/container-exec/v1` | audit log | `pods/exec`, `attach`, `portforward` sessions |
| `runtime/pod-log-read/v1` | audit log | `pods/log` reads |
| `runtime/token-request/v1` | audit log | `serviceaccounts/token` requests |
| `runtime/object-create/v1` | audit log | pod creation, and **who** created it |
| `runtime/workload-identity/v1` | the API | the pod spec: service account, security context |

### The audit-log prefilter, and what it cost

The runtime collector prefilters the audit log with `grep subresource`, because that is what
pulls out `exec`, `log`, `portforward` and `token` in one pass.

The problem: **a bare pod create has no subresource**, so it was never read. The chain's
hop 5 — creating a foothold pod in the business zone with `cluster-admin` — produced no
telemetry at all. 183 such events were sitting in the log the entire time. `T1078.001` was
reported as undetectable, and the honest description of why is not "the platform cannot see
this" but "nobody asked for it".

Widening the prefilter then created a second bug worth knowing about: the two greps
**overlap**, because every `pods/exec` record has both a subresource and
`resource: "pods"`. Concatenating two overlapping sets is not a set. Every pod subresource
event was collected twice, and detection hit counts inflated accordingly — `det-0004` read 64
hits over 16 records. The fix is to dedupe on `auditID`, which is unique per record.

A duplicated event is worse than a missing one: a gap is visible and gets asked about, while
a duplicate inflates every count downstream and looks like a busy cluster.

---

## 7. Why a collector refuses to guess

This is the part that separates this lab from a demo, and it is worth reading the code to
see it enforced rather than asserted.

### 7.1 A delta is only defined in one of four states

Network telemetry here is **counter-based, not flow-based**, because kube-router v2.6.1 has
no flow logs. So a detection is a *difference* between two comparable reads of the same
iptables chain, and there are four ways that can go:

| State | What happened | Is a delta meaningful? |
|---|---|---|
| `compared` | same chain, counters moved forward | **yes** |
| `chain-rebuilt` | kube-router reprogrammed the firewall; counters restarted at zero | no |
| `counter-reset` | counters went backwards on an unchanged chain | no |
| `no-baseline` | first sight of this subject | no |

In the three invalid states the collector emits `deltaDenied: null`, sets
`deltaValid: false`, and writes a `deltaReason` saying which one happened. It does not
report the absolute count as if it were new traffic.

`det-0005` (T1046, network service scanning) requires `baselineState: compared` **and**
`deltaDenied > 0`. So when the chains get rebuilt, it fires on nothing — correctly. A
collector that reported the absolute count would have made the rule fire, and it would have
been lying about a rate that never happened.

### 7.1a The ordering this forces, including the two versions that were wrong

Because a delta needs two reads with no policy churn between them, and two stages here churn
policy, the order in `run-lab.ps1` is:

> **graph → chain → seed the network baseline → privilege paths → collect**

The subtlety is *which* stages churn. It is not obvious, and it is worth reading what each
one actually calls:

| Stage | Pod-creating? | Safe between a seed and a read? |
|---|---|---|
| `graph/build-reachability.ps1` | yes — a probe pod per pair measured | no |
| `attack/chain-purple-team.ps1` | yes — hop 5 applies a manifest | no |
| `attack/run-all.ps1` | no — only `kubectl create token`, a subresource | **yes** |
| `tools/test-boundaries.ps1` | yes — a probe pod per case | no |

So the graph and the chain must both finish before the seed, and the walks must come after
it. The walks are the only stage that generates refused traffic *without* creating a pod, so
they are the only thing that can sit between the snapshot and the read.

This took three attempts, and the first two failed in a way that looked healthy:

- **Seed before the graph** — the intuitive order. Every read came back `chain-rebuilt` and
  `det-0005` could never be judged.
- **Seed after the graph, walks in between** — still wrong, and quieter. The *chain* also
  creates a pod, so it rebuilt the chains after the seed. The graph was the obvious suspect
  and was only ever part of the problem. Six of seven rules kept firing throughout, so the
  run looked green.

Worth knowing: `tools/test-boundaries.ps1` could not have been used as the traffic generator
either, because it creates a probe pod per case. Anyone reaching for it to "generate some
denied traffic" will silently invalidate the baseline again.

### 7.1b A rule can declare the window it needs

Even with the ordering right, a `-SkipAttack` run generates no refused traffic, so no
comparable delta exists and `det-0005` correctly matches nothing.

That is a statement about the *window*, not about the rule, and a gate that cannot tell those
apart will either fail on correct code or pass on broken code. So a rule may declare the
precondition it needs, and the gate measures whether the telemetry can supply it:

```yaml
logsource:
  schema: network/denial-counter/v1
  requires:
    field: baselineState
    equals: compared
```

When the window cannot satisfy it, the rule is reported as **not judgeable** and excluded from
the verdict — loudly, with the count of events that could have provided it. It is not a
suppression: the precondition is *data*, declared in the rule file rather than inferred, so a
rule cannot quietly mark itself untestable. And if a comparable delta appears, the rule is
immediately held to liveness and to its baseline count like any other.

One consequence is stated rather than hidden. A mutation that makes a rule match *nothing* is
indistinguishable from a rule that already matched nothing, so in an unjudgeable window the
"impossible value" mutation reports `equivalent` for that rule. That is missing coverage, not
a clean result, and the harness says so where a reader will see it.

### 7.2 Zero chains read is not a quiet cluster

A collection that reads no chains at all must never produce the same artefact as a collection
that finds nothing interesting. The collector now throws rather than writing a well-formed,
correctly-shaped, empty `network-events.jsonl` — because every downstream consumer would read
that as "no traffic was refused", which is a *finding*.

The most expensive silence is the kind that looks like a clean result.

### 7.3 A candidate technique is not a detection

`network/observed-flow/v1` carries `source.role`, which is `workload` or `instrumentation`.
The `instrumentation` value exists because of a measured accident:

> Of the four lab-zone cross-connections in this cluster, **all four** were the telemetry
> agent's own health probes. A T1021 rule that did not exclude them would have fired on
> nothing but the lab checking that its own policies still held — and it would have looked
> like it was working.

`det-0006` (T1021) is the rule this bit. It fires on 4 events, all of them instrumentation,
and the test suite states that in `ALL_HITS_INSTRUMENTATION` so the fact cannot be quietly
forgotten. The lab has no attack step that structurally produces a T1021 positive, and the
project would rather say so than manufacture one.

The same reasoning produced `instrumentation` on pod creation: of 127 operator-created pods,
**114 are the lab's own `probe-*` pods** and 13 are the chain's foothold. The audit record
carries no pod spec, so a label on the probe cannot be seen from it and the name prefix is
all there is. That weakness is recorded on the event and in `det-0012` rather than papered
over, because an attacker who names a foothold `probe-foo` passes straight through the
filter.

### 7.4 The ATT&CK registry

`telemetry/tag-attack-ids.ps1` is not a tagging pass. It is a **declarative table** of which
schema may carry which technique, plus an explicit list of the untagged cases with a reason
and a test for each.

It exists because the alternative failed, visibly. The original design tagged by pattern,
and:

- all 135 service-account token requests got a T1528 tag — including 78 whose own
  `requesterClass` was `kubelet`, the node that *does* run the pod, which is the exact
  opposite of the rationale printed next to the tag;
- all four cross-zone flows got a T1021 tag, and all four were the lab's own sensor.

A tag whose condition its own data refutes is a false positive waiting to be inherited by
the detection layer. So the registry requires every untagged event to match a **verified**
exemption — one with a test evaluated against the event's own fields. An exemption that only
checks "the tag is absent" is a hole with a comment over it.

Current state: **7 schemas, every untagged event justified by an exemption that was
executed.** The exact event count is not quoted here on purpose — the audit log is cumulative
and rotates, so it is a different number on every run, and a document that quotes one goes
stale silently. Read it from the run, not from here.

---

## 8. Detections

`detections/` holds one directory per ATT&CK technique, each with a real Sigma rule and a
note in the rule's own `description` about what it does *not* establish.

| Rule | Technique | Fires on |
|---|---|---|
| `det-0003` | T1609.001, T1550.001 | exec whose command is credential-shaped or shell-escaping |
| `det-0004` | T1552.001 | pod log reads |
| `det-0005` | T1046 | refused-packet bursts on a comparable delta |
| `det-0006` | T1021 | cross-zone connections that are not the lab's own sensor |
| `det-0010` | T1090.001 | `pods/portforward` |
| `det-0011` | T1528 | token requests by a requester off the measured baseline |
| `det-0012` | T1078.001 | pods created directly by a client identity |

Two decisions here are load-bearing.

**The rules are real Sigma.** They are parsed by `pysigma`, the reference implementation, as
part of the gate. A rule that only this repository's own evaluator can read is not a portable
detection, and a "Sigma rule" that is not valid Sigma is a private query language with a
recognisable file extension.

**The evaluator raises on anything it does not implement.**
`detections/engine/sigmalite.py` refuses to guess. If a rule uses a construct the engine
does not handle, the run **stops** rather than silently matching nothing or everything. An
evaluator that quietly skips what it cannot parse is worse than one that cannot parse, because
it reports coverage it does not have.

### Hit counts are a fingerprint, not a target

`test-detections.py` originally enforced exact hit counts. That turned out to be a defect
rather than a strict setting, and understanding why is the point:

- every chain run adds exactly one exec, one portforward, one token request and one created
  pod;
- so the counts move by design, on every use of the lab;
- and the gate therefore could **not pass twice in succession** after a walk, no matter how
  correct everything was.

A floor (`>= want`) is not the fix, because a floor cannot fail. The harness now enforces the
properties that do not depend on the window:

- **liveness** — every rule matches something;
- **schema containment** — no rule fires outside its declared schema;
- **strict subset** — no rule fires on its *entire* schema, because a rule that matches
  everything is a schema guard wearing a detection's name;
- **no duplicate audit records** — within a schema, distinct `auditID`s must equal event
  count. This is what the exact count was accidentally testing, and it needs no fingerprint to
  know what correct looks like.

Counts are still printed, as **drift**, and `--baseline` / `--exact-baseline` enforce them
when the window is genuinely quiesced. The committed `EXPECTED_HITS` table is a fingerprint
of the machine that wrote it, so it is reported rather than enforced: a fresh clone walks the
lab a different number of times against a differently-sized audit log, and enforcing someone
else's number would mean a guaranteed red run on correct code.

### 8.1 The mutation harness

Every rule is then **broken on purpose**, three ways, and the *same* gate is re-run:

| Mutation | What it removes | A rule that survives this is |
|---|---|---|
| schema guard dropped | the `schema` predicate | matching on a coincidental field name |
| condition → match-everything | all discrimination | a schema guard in disguise |
| condition → impossible value | all matches | dead code that looks alive |

Verdicts are `caught`, `equivalent`, or `SURVIVED`. `SURVIVED` fails the build. The harness
calls `verify_rule()` itself rather than re-implementing the check — a mutation harness that
tests its own copy of the gate is testing nothing.

Note that `det-0005` and `det-0006` report `equivalent` for the schema-guard mutation. That
is a real finding, not a suppressed one: dropping the guard genuinely does not change their
result, because their declared schema is narrow enough that no other schema matches the same
field. It is reported because "this mutation is a no-op here" is information.

---

## 8a. Posture checks: a different kind of question

`detections/posture/` is not telemetry detection and does not pretend to be. There are no
events here — the checks read live configuration with `kubectl` and ask whether it is
*acceptable*, not whether something *happened*. So there is no `logsource.schema` and no
`detection:` block, and the Sigma gate explicitly excludes that directory. When it didn't,
`sigmalite` raised `SigmaError: no detection block` and took the whole detection gate down
with it — the engine was right and the caller was wrong.

| Rule | Asks |
|---|---|
| `DET-0001` | is a lab ServiceAccount bound to `cluster-admin`, or to any verb of `*` on `secrets`? |
| `DET-0002` | is a credential-shaped key or value in a ConfigMap? |
| `DET-0007` | is a container's `runAsNonRoot` false or missing, `privileged`, or holding an off-allowlist capability? |
| `DET-0008` | is there a NetworkPolicy in the observe zone that grants ingress? |
| `DET-0009` | is a lab ServiceAccount issued a token while bound to nothing at all? |

### Every finding is expected, so the gate is set equality

This lab is deliberately vulnerable. `sa-build-runner` holds `cluster-admin` on purpose and
`web-frontend` sets `runAsNonRoot: false` on purpose. So "the check fires" is *not* the
test — all five fire in a healthy lab, and a check that fired on nothing would be the broken
one.

What is tested is whether the **set** of findings matches what `posture-rules.yml` declares,
in both directions:

- a finding that is not expected → something changed, or the check got looser
- an expected finding that is gone → a control was removed, or the check broke

That is the same shape as `tools/scan-pods.ps1`, and for the same reason: a one-directional
check cannot notice a control disappearing. Currently 10 findings across 5 checks.

### Three scoping decisions that are measured, not assumed

Each of these was wrong in the first draft and the data said so:

- **`DET-0001` scoped to lab namespaces.** 44 ServiceAccount bindings exist in this cluster
  and **43** are kube-system controllers binding themselves to their own ClusterRole.
  Unscoped, the check reports 44 findings and the one that matters is 1.
- **`DET-0002` matches the value narrowly.** A loose "contains `password`" pattern also hits
  `lab-catalog/privileges.md`, `lab-catalog/weaknesses.yaml` and
  `web-frontend-content/index.html` — all prose. A posture check that flags documentation is
  a check whose output gets ignored, so the value half only matches a credential actually
  embedded in something.
- **`DET-0009` excludes `default`.** 3 of the 6 unbound lab ServiceAccounts are `default`,
  which is true of every Kubernetes cluster ever built and therefore says nothing about this
  one.

And one that was a *bug* rather than a tuning question: the rules declared
`scope.subjectNamespaces` and the code never read it. Every rule carried a scope
declaration that was decorative — narrowing it would have done nothing at all. A declaration
in a config file that the code ignores is worse than no declaration, because it reads like a
control. The gate now resolves each rule's declared scope and rejects one that points
outside the lab.

### Proving they can fail

`detections/posture/test_posture.py` breaks each check four ways and requires the same gate
to object: **vacuous**, **broadened**, **expectation silently widened**, and — the one that
matters — **injected**, where a synthetic violation is added to the snapshot and the check
must report it. 26 cases, all green.

Two of the injections are *negative* cases that must stay silent: prose containing the word
"password", another `default` ServiceAccount, and a kube-system controller binding itself.
The `DET-0002` injection deliberately uses a password string that appears nowhere in the
repository, because that check detects by shape and never by value — if it only fired on the
lab's real credentials, the case would fail and the comment in the rule would be a lie.

---

## 9. The chain

`attack/chain-purple-team.ps1` is the payoff: six hops, end to end, each one a technique.

| Hop | Technique | Step |
|---|---|---|
| 1 | T1609.001 | read the mounted token from inside a pod |
| 2 | T1552.001 | read the ConfigMap copy of the DB password |
| 3 | T1090.001 | port-forward to a port the policy denies |
| 4 | T1528 | mint a fresh token instead of reusing the stolen one |
| 5 | T1078.001 | use that authority to place a pod inside the zone |
| 6 | T1552.001 | spend the stolen credential from the foothold |

Two design points that took work:

- There is a **pre-flight sweep** and a **trap** above hop 1, so the chain fails loudly if
  earlier state leaks into the run instead of quietly inheriting it.
- Hop 4 mints a *new* token rather than reusing hop 1's. That is what makes it T1528 and not
  T1078, and it is why the telemetry distinguishes a kubelet minting a token for a pod it runs
  (the baseline) from any other caller.

`test-detections.py --chain` reports which hops have a rule behind them. This exists because
a chain report that only lists hits reads as "fully detected" even when a hop has no rule at
all. It currently reports every hop covered, and `undetectable: []`.

**What that report does not claim.** It claims a rule for each technique exists and is
matching. It does not claim a given hop *caused* those matches. The chain records verdicts,
not the `auditID`s it caused, so attributing hits to hops by technique would be the
"agreement is not evidence" mistake — a T1552.001 hop would get credited to the pod-log-read
rule simply because that rule carries the tag.

---

## 10. The console

`dashboard/server.py`, on `http://127.0.0.1:8099`, loopback only, no authentication. It is a
Flask app with read endpoints plus a small allowlist of actions.

**It can mint a `cluster-admin` token.** That is deliberate: it has the same authority the
chain steals, so testing the console is testing the compromise. It is loopback-only and
unauthenticated for exactly that reason. Do not bind it anywhere else.

Two properties worth knowing:

- **Redaction is shape-based, never value-based**, and it lives in the *server*, not the
  collector — because the collector's output is the evidence, and a redacted collector cannot
  be trusted to be complete. Key names and fingerprints are deliberately *not* redacted; a
  `password` field with a redacted value still tells you a credential is there.
- Mutating actions require `?confirm=yes`, and the action list is a fixed allowlist. No
  endpoint runs a shell command — `dashboard/test_server.py` asserts this, because a console
  that can mint `cluster-admin` and also shell out is a very different risk.

`dashboard/static/topology.js` overlays the live trust topology on the console: real edges
from the reachability graph, arrowheads for direction, a blocked toggle, and live animation
on measured edges.

---

## 11. Running it

```powershell
./run-lab.ps1                          # everything: build, attack, collect, verify, detect
./run-lab.ps1 -SkipBootstrap -SkipAttack  # re-collect and re-verify; the rule-editing loop
./run-lab.ps1 -Recreate                # delete the cluster and build it again
./run-lab.ps1 -Serve                   # ...and leave the console up
```

Ten stages, in an order that is not obvious and is the reason the script exists.

**The graph and the chain run before the network seed; the privilege paths run after it.**
Not because of timing — because those first two create pods, kube-router regenerates its
iptables chains and resets the counters when policy changes, and network telemetry is a delta
between two comparable reads. The walks generate the refused traffic that makes the delta
non-zero and create no pods, so they are the only stage that can sit between the snapshot and
the read. See [7.1a](#71a-the-ordering-this-forces-including-the-two-versions-that-were-wrong);
both obvious orderings get this wrong and fail while looking healthy.

**The attack runs before collection**, because telemetry describes what happened and the
thing that has to happen first is the attack. The reverse produces a green run over an empty
audit log, and an empty audit log is indistinguishable from a quiet cluster.

The script stops at the first failing stage, unlike `run-all.ps1`. The privilege paths are
independent, so continuing past a failure there buys information; the stages in `run-lab.ps1`
are a pipeline, so continuing produces a mostly-green run that means nothing.

The ledger at the end says which stages ran and how long each took, whether the run passed or
failed, and is written to `.telemetry/run-lab.json` on both paths. A reproduction script that
only speaks up when it breaks leaves you guessing which of ten stages actually ran — and "the
graph step did not run" versus "the graph step found no drift" is the whole result.

### The stages that check the lab, not the attack

- `tools/scan-pods.ps1` — fails on any pod no manifest declares, **and** on any declared
  workload that is gone. Both directions. This is the check that would have caught a foothold
  pod left running for six hours.
- `tools/scan-drift.ps1` — Kustomize source vs applied state, both directions.
- `tools/scan-images.ps1` — every running image is the pinned digest. A mutable tag is a
  supply-chain hole in a lab about trust boundaries.
- `tools/scan-secrets.ps1` — no credential-shaped value in tracked files.

### Cluster-free self-tests

`tools/run-selftests.ps1` runs six suites with no cluster, and it is the pre-commit gate. Each
suite **proves it can fail**: the reachability classifier is broken on purpose, the Sigma
evaluator is mutated, the redactor is given a credential-shaped string to leak, and the server
is handed an endpoint that would shell out. A suite that cannot fail is not a test, and the
counts in its output are there so you can tell the difference.

---

## 12. What this lab does not do

Stated plainly, because a lab that oversells itself teaches the wrong lesson.

- **T1078.001 is only partly covered.** `det-0012` catches *pod creation by a client
  identity*. It does not establish escalation, and it cannot separate an operator running
  `kubectl apply` by hand from an attacker holding `cluster-admin` — in this cluster the
  operator identity *is* the attacker. The rule says so in its own description.
- **T1021 has no attack-step positive.** `det-0006` fires only on the lab's own sensor, by
  construction: the only cross-zone grants in the cluster are PP-02's observation grants.
  Manufacturing a T1021 attack would mean inventing a grant the lab does not need.
- **Network telemetry is counters, not flows.** A refused connection is counted; the
  destination and port are not available at the enforcement point, and a Service ClusterIP on
  an unexposed port is dropped before policy evaluation, so it is never counted at all.
  `.telemetry` events say so in a `resolution` field rather than leaving a reader to infer it.
- **T1190 is not detected.** It is in the catalogue; nothing collected carries it.
- **Audit log rotation silently ate 91k records** during development. Both collectors read
  only the current file. They now glob `audit*.log` oldest-first — but the lesson stands:
  *silent telemetry loss is indistinguishable from a quiet cluster*, and any collector that
  can lose records without saying so will eventually do exactly that.

---

## 13. A suggested reading order

If you are reading the repository rather than running it:

1. `run-lab.ps1` — the whole thing as an ordered list, with the reasons.
2. `identities/20-rbac.yaml` — the deliberate hole everything else is about.
3. `telemetry/tag-attack-ids.ps1` — why this is a registry and not a tagging pass. The header
   comment is the best single explanation in the repository.
4. `telemetry/network/collect-network.ps1`, the baseline/delta section — four states, one
   valid.
5. `telemetry/runtime/collect-runtime.ps1`, the `object-create` block — a collection gap
   closed, and the three wrong turns that got there.
6. `attack/chain-purple-team.ps1` — the payoff, and the trap above hop 1.
7. `detections/test-detections.py`, `verify_rule` and the mutation harness — what "a check
   that can fail" means in practice.
8. `detections/posture/posture-rules.yml` — the other kind of check, and why it is not
   Sigma. The scoping comments are where the measured numbers live.
9. `docs/audit-2026-09-27.md` — a real audit of this codebase, including what it got wrong.

That last one is worth saying explicitly: the most useful document in the repository is the
record of the bugs found in it. Several of them — an inverted mutation harness that reported
the opposite of what it measured, a cleanup flag declared *below* the assignment that set it
so cleanup silently did nothing while printing a 6/6 summary, a `$footholdCreated` that never
guarded anything — passed every static check, every secret scan and every test suite, and were
found only by reading the rendered result. Mojibake in delivered files passed `node --check`,
gitleaks and every mutation harness.
