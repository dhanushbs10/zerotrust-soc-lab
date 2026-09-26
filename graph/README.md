# Correlation graph

## What this answers

One question: **given an identity in this cluster, what can it reach, and on
which ports.**

That answer is the deliverable. The diagram is only its output, and a diagram
that disagrees with the firewall is worse than no diagram, because it will be
believed.

## The answer, measured

Six paths are open out of twenty-five modelled:

| from | to | port | how it was known |
|---|---|---|---|
| web-frontend | orders-api | 8080 | connected, 0 ms |
| orders-api | postgres | 5432 | connected, 10 ms |
| telemetry-agent | web-frontend | 80 | connected, 0 ms |
| telemetry-agent | orders-api | 8080 | connected, 440 ms |
| telemetry-agent | postgres | 5432 | connected, 0 ms |
| telemetry-agent | **telemetry-agent** | 8080 | **permitted, nothing listening**, 0 ms |

The other nineteen are dropped by the firewall. Last run: **25 modelled, 25
confirmed against the datapath, 0 mismatches**, with the drop-versus-refuse
classifier seen to separate 19 drops from 6 answers.

The millisecond figures are one run's evidence, and they move between runs by
two orders of magnitude on a busy machine. What does not move is the set: which
six paths are open is a property of the policies, and that is the part the
graph is claiming.

That last row is the one worth reading twice. The sensor can reach itself, and
that is what the policy says — `telemetry-agent-ingress` admits the whole
observe zone, and the sensor is in the observe zone. It is also useless as an
attack path, because there is no server on the other end. The graph reports the
two facts separately instead of flattening them, because a diagram showing a
sensor pointing at itself invites the conclusion that it exposes something, and
it does not.

## How it is built

`build-reachability.ps1` does two things, in this order, and the order is the
point.

**1. Model the live NetworkPolicies.** Nodes are the running lab workloads read
from the API — namespace, zone label, service account, pod IP, and the ports
their Service exposes. Edges are computed by evaluating the live policies with
real Kubernetes semantics:

- A connection needs **both sides to agree**. The source's egress policy and the
  destination's ingress policy must each permit it. One-sided permission is not
  permission.
- Selecting a pod for a direction **isolates it in that direction**. If any
  policy selects it with `Ingress` in `policyTypes` and no rule matches, the
  answer is deny regardless of what any other rule says.
- A bare `podSelector` means the policy's **own namespace**. A
  `namespaceSelector` alone spans namespaces. Both together mean pods matching
  the selector inside namespaces matching the namespace selector.
- An omitted `ports` list means **every port**, which is how
  `telemetry-agent-ingress` admits its whole zone.
- Policies are **additive**: any selecting policy that admits is a permit.
- A rule with no `from`/`to` admits **every** peer. Legal, and almost never what
  a reviewer means.

`endPort` ranges are not modelled. If a policy uses one, the script **throws**
rather than guessing — a silently wrong reachability answer is the one failure
mode this file exists to prevent.

**2. Check every modelled pair against the datapath.** For each source identity
an ephemeral probe pod is created carrying that identity's service account and
**the workload's own `app` label**, and it opens a real TCP connection to the
destination Service's ClusterIP. ClusterIP rather than pod IP, because ClusterIP
is the address a real client dials, so the service proxy and the DNAT path are
exercised rather than bypassed.

One probe is alive at a time. Each is given its own control check, measured
while that check is green, then deleted before the next is created.

Both directions are checked, and that is deliberate. A model that permits
something the firewall refuses is an **over-approximation**: it invents access
that does not exist, which is the dangerous kind. A model that refuses something
the firewall permits is an **under-approximation**: it hides real access.
Checking only the permitted edges would find the first kind and never the
second.

## Telling a blocked connection from a dead one

`nc` failing does not mean the network blocked it. It means either the firewall
**dropped** the SYN, or the path was fine and the far end sent **RST** because
nothing was listening behind it. Those are completely different facts, and
collapsing them turns a policy finding into a fake security result.

This was not hypothetical. The model says the sensor can reach itself on 8080,
because `telemetry-agent-ingress` admits its whole zone. The datapath agreed.
But `netstat -lnt` inside the sensor returns **no sockets at all** — it runs a
shell probe loop, not a server — so the connection was refused at the
application layer, and the first version of the script reported a policy
violation that did not exist.

busybox `nc -v` prints `open` on success and **nothing** on failure, so the
reason is not available from `nc` at all. The only remaining signal is elapsed
time, and it has to be measured for the right reason:

- Timing it from the host does not work. `kubectl exec` overhead alone measured
  **630 ms**, and the gap underneath it is under a second — inside the noise of
  a loaded machine. `-w` does not move it at all: the attempt ends when the
  kernel finishes its own SYN retry, not when `nc`'s timeout expires.
- So the clock is read **inside the pod**, from `/proc/uptime`, immediately
  before and after `nc`. Across a full 25-pair run:

  | outcome | elapsed |
  |---|---|
  | something answered | 0 ms … 600 ms |
  | refused (RST), nothing listening | 0 – 100 ms |
  | dropped (silence) | 1000 ms … 2070 ms |

  Two populations with an empty decade between them, and the cut at **600 ms**.
  `-SelfTest` pins both sides of that boundary to the measured extremes so the
  threshold cannot drift silently.

The exit code is tested **first**, so a successful connection is `open` however
slow it was, and the threshold only ever decides what a *failure* was. That is
what makes the margin safe rather than lucky, because the answered population is
much less tidy than the failure population: a busy run answered a DNS control in
600 ms, which would be alarming if a slow success could be called a drop. It
cannot. The failure that has to be classified correctly is a refusal, and a
refusal is a RST raised by the kernel on the far side — not something network
latency can stretch.

A `permitted-refused` result **agrees** with a model that says open. The model
is about the network, not about whether a server is deployed. Edges like that are
emitted with `noListener: true` and said so on the console, because "the sensor
points at itself" reads as an exposed service and it is not one.

## The positive control, and why it is not optional

A verification harness in which every probe returns "blocked" looks exactly like
a perfectly isolated cluster. Those two states are indistinguishable from the
output alone, so a broken probe mechanism would be reported as a security
result.

Before any probe's results are believed, **that probe must open a TCP connection
to kube-dns on port 53**. DNS egress is permitted in all three lab namespaces
and `kube-system` carries no policies at all, so that connection is open
independently of everything this script models. If it fails for a given identity,
that identity's results are discarded and the run stops — the check is per probe,
not once for the run, so one broken probe cannot contaminate the other four.

This control earned its place on the first run. The initial probe was labelled
`app: probe`, and the result was:

- all 5 DNS controls **passed** — `allow-dns-egress` selects every pod in a
  namespace regardless of label
- all 5 app-specific edges came back **blocked**, including the two that
  `tools/test-boundaries.ps1` independently asserts are open

A working probe to one address and a refused connection to every other is what a
**mislabelled probe** looks like. The control did not catch it on its own, but it
narrowed the fault to policy selection rather than to connectivity, which is
what pointed at the label.

### Probes are also Service endpoints

A probe carries the workload's real `app` label so the firewall treats it as
that workload — and every lab Service selects on exactly that label. A live
probe is therefore an **endpoint of its own Service**, and leaving probes running
means a later test of `web-frontend → orders-api:8080` may be answered by an
alpine container with no server on 8080. The result flips to "blocked" for a
reason that has nothing to do with the policy under test.

One probe at a time removes the hazard: the only Service a live probe pollutes
is its own, and a probe is never the destination of another probe's test.

## Bugs this found, all silent

None of these raised an error. Each produced a confident, plausible, wrong
answer, which is the entire reason `test-reachability-selftest.ps1` exists.

**`policyTypes` casing.** `policyTypes` is a Kubernetes enum and is capitalised
(`Ingress`); the spec field holding the rules is lower-case (`ingress`). The
first version used one variable for both, which matches nothing — so no pod was
ever considered isolated and the model reported **25 of 25 pairs open** with no
complaint. A model that permits everything looks like a badly configured
cluster; a model that permits nothing looks like a working one. Both are equally
untrustworthy without a datapath check.

Worth being precise about what this bug was and was not: it was the **direction**
that was conflated, not the field name. PowerShell resolves `$obj.Ingress` and
`$obj.ingress` to the same property, so a case-only mutation is a no-op and
cannot be caught by any test. The mutation harness keeps that entry in, labelled
uncatchable, rather than quietly dropping it.

**Namespace selector matched against the wrong map.** The peer check passed the
whole map of namespace→labels where it needed the labels of *the peer's own
namespace*. That is type-compatible, so it compiled and ran, and it silently
denied every cross-zone rule: the three PP-02 observation edges vanished from
the graph. The tell was a model whose *egress* was fine and whose *ingress* was
refused with "no rule admits this peer" — for a rule that plainly does.

**An empty array is not an array.** `return @()` in a PowerShell function emits
**nothing**, so the caller received `$null` and `.Count` threw under
`Set-StrictMode`. It only failed on the path where the answer was "nothing",
which is to say only where nobody was looking.

**`endPort` was guessed at.** Now it throws. A port range evaluated as if it were
a single port produces a confidently wrong edge, and refusing is the only honest
option. No policy in this lab uses one.

**Agreement is not openness.** The worst one, and the only one no test caught. A
pair the model called *blocked* and the datapath *dropped* is an **agreement** —
the model was right — so it belongs in the same set as a pair that genuinely
connected. Selecting edges on "did the model and the datapath agree" therefore
emitted **all 25 pairs as `kind: reachable`**, including the 19 the firewall had
just refused. The graph claimed twenty-five paths across a cluster that has six.

Nothing about the run looked wrong. `25/25 agree, 0 mismatches`, exit 0, every
comparison verified, classifier shown to be discriminating. The wrong answer was
in the `edges` array, and only reading the output found it. The script now
states the invariant — an edge exists for a modelled-open pair and for nothing
else — and checks it on every run, in both directions: no edge without a
modelled-open pair, and no modelled-open pair without exactly one edge. Because
that defect agreed with itself, no amount of inspecting the run's own
conclusions could have surfaced it.

**A strict-mode property error is a warning, not a wall.** The first version of
the integrity check above ran before the edge objects were built, and reached
for `$e.from` on a row that carries `source` and `dest`. PowerShell raised
`PropertyNotFoundStrict`, printed it, and **carried on to a clean exit 0 with
the graph written**. `$ErrorActionPreference = 'Stop'` did not stop it, because
the access was inside a `Where-Object` scriptblock.

That is worth stating plainly, because the rest of this file relies on
`Set-StrictMode` to turn a missing property into a hard stop. Inside a
pipeline scriptblock it is not one. So no check here may depend on an error
halting the run: each one sets its own flag and reports it, and the final
verdict is the AND of those flags rather than the absence of an exception.

## What the graph deliberately does not contain

**RBAC.** `sa-build-runner` holds `cluster-admin`, which is the single most
consequential permission in the lab and is completely invisible here, because
cluster-admin is not a network flow. That gap is the point of PP-01, and
pretending a network graph covers it would be the most misleading thing this
file could do.

**The API server as a node.** No pod can reach it. kube-router DNATs the
ClusterIP before the policy chain is consulted, so the control plane is reached
by an authenticated client from *outside* the cluster. An exec-based detection
therefore cannot use "who" as a discriminator in this lab; it has to use "what".
That is a property of the lab, not a gap in this script.

**Kubernetes' own traffic.** The graph covers lab workloads. `kube-system`
carries no policies, so coredns, the local path provisioner and the kubelets are
unrestricted and are not modelled — they appear in
`.telemetry/network-events.jsonl` as `scope: cluster-internal` flows instead.

## Reading the output

`.telemetry/reachability-graph.json`

- `verified` — true only if probes ran, every comparison completed, none
  disagreed, and the drop classifier was shown to discriminate. An unverified
  graph says so in this field and in every edge's `evidence` string.
- `nodes[]` — the workloads, with `zone` and `serviceAccount` for correlation.
- `edges[]` — `kind` is one of:
  - `reachable` — modelled open **and** observed permitted. The only kind that
    asserts access. `noListener: true` means the path is real and nothing is
    serving on the far end; `elapsedMs` and `observed` record how that was known.
  - `disputed-open` / `disputed-blocked` — model and datapath disagreed. Not
    treated as an edge, because picking a winner by assumption is how a wrong
    graph becomes a trusted one.
- `blockedPairs[]` — refusals **with the policy that caused them**, because an
  unexplained deny is indistinguishable from a modelling error.

`.telemetry/reachability-verify.json` holds the full modelled-versus-observed
table, including the model's reasoning for every row and the elapsed time of
every probe, so it is readable even when run with `-SkipProbes`.

## Proving the checker can fail

`build-reachability.ps1 -SelfTest` runs the decision logic against 34 fixtures
where the right answer is known, and touches no cluster. It exists because every
bug above was silent: a wrong model and a working one look identical from the
output, so passing against a live cluster is not evidence of anything.

```powershell
.\graph\build-reachability.ps1 -SelfTest
```

But a suite that has never failed is not evidence either, so
`test-reachability-selftest.ps1` breaks the real script on purpose, in a
throwaway copy, and requires the self-test to notice:

```powershell
.\graph\test-reachability-selftest.ps1
```

Each mutation reintroduces a bug this project actually hit. The harness verifies
the text it is about to mutate matched **exactly once** before running anything,
because a mutation that silently matched nothing would report a pass for a test
that never happened. It also distinguishes a mutation caught by an assertion from
one caught by a crash, because a suite that only ever dies is testing less than
it appears to.

Current state: **34 assertions, 9 mutations, 9 caught**, one of which is
deliberately labelled uncatchable to record a negative result.

## Running

```powershell
.\graph\build-reachability.ps1                          # model + verify
.\graph\build-reachability.ps1 -Namespace zerotrust     # one zone
.\graph\build-reachability.ps1 -SkipProbes              # model only, marked unverified
.\graph\build-reachability.ps1 -KeepProbes              # leave the last probe up
.\graph\build-reachability.ps1 -SelfTest                # decision logic, no cluster
.\graph\test-reachability-selftest.ps1                  # prove the above can fail
```

Probe pods are deleted as each identity finishes unless `-KeepProbes` is given.
The script refuses to emit a graph that modelled zero pairs, and refuses to emit
one that permits nothing at all, because "everything is closed" and "my model is
broken" are indistinguishable from the output and only one of them is a finding.

Exit code is non-zero on any disagreement between model and datapath, and on any
verification that did not run to completion.
