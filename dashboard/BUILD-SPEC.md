# Build spec: a better SOC console for ZeroTrust-SOC-Lab

This is a handover document. It is written for an engineer or an AI that has
**not** seen this repository and cannot see the lab. Everything needed to build
against the existing backend is here, with real field names taken from the real
data files rather than from the code that reads them.

There is a working console already. Section 6 lists what is wrong with it. Build
the replacement against the same HTTP API and nothing on the backend has to
change.

---

## 1. What this system is

A deliberately vulnerable Kubernetes cluster running locally in Docker, plus the
tooling to attack it and detect the attack. The point is that every claim is
measured: every attack runs as a script, every detection fires against real
telemetry, and every "this is blocked" statement is confirmed against the
datapath rather than inferred from a manifest.

- Cluster: `kind` v1.34.0, named `soc-lab`, 3 nodes
- Namespaces / trust zones: `zerotrust` (business), `zerotrust-build` (CI),
  `zerotrust-observe` (monitoring)
- CNI: kube-router, chosen because it genuinely enforces NetworkPolicy
- Workloads: `web-frontend`, `orders-api`, `postgres-0`, `build-runner`,
  `telemetry-agent`
- All telemetry is normalised into JSON Lines under `.telemetry/`
- Detections are standard Sigma rules, validated by pySigma

Ten ATT&CK techniques are in play, mapped to six telemetry schemas:

| Schema | Techniques |
|---|---|
| `runtime/container-exec/v1` | T1609.001, T1090.001 |
| `runtime/token-request/v1` | T1528 |
| `runtime/pod-log-read/v1` | T1552.001 |
| `network/denial-counter/v1` | T1046 |
| `network/observed-flow/v1` | T1021 |
| `runtime/workload-identity/v1` | inventory only, no technique |

## 2. Non-negotiable constraints

**The telemetry contains a live credential.** SP-01 exists to prove a ConfigMap
holds a working *superuser* password for the orders database, and that password
appears verbatim in `commandLine` of exec events:

```
sh -c env PGPASSWORD=<LIVE VALUE> psql -h postgres -U orders -d acme -t -A -c select\ id\ from\ orders
```

The backend redacts it. **If you build a new frontend, do not reintroduce it**,
and do not add any endpoint that serves unredacted events. `redaction.py` in
`dashboard/` is the reference implementation and `dashboard/test_redaction.py`
proves it. A value is considered leaked if it matches a credential *shape*:

| shape | example |
|---|---|
| URL password | `postgres://orders:<VALUE>@host:5432/acme` |
| credential key | `PGPASSWORD=<VALUE>`, `DB_PASSWORD=<VALUE>`, `api_key=<VALUE>` |
| JWT | `eyJ….….…` three base64url segments |
| auth header | `Authorization: Bearer <VALUE>` |
| password flag | `--password <VALUE>`, `--token=<VALUE>` |

Two things must **not** be redacted, because they are the evidence:

- **Fingerprints** — `A069F0C1482A91C8` is SP-01's stable non-reversible label
  for the credential. It is the only thing that tells an analyst the ConfigMap
  copy and the Secret copy are the same password.
- **Key names** — the line should read `PGPASSWORD=<redacted>`, not be deleted.
  An analyst needs to know the variable was used.

**The backend can mint a cluster-admin token, create pods, and port-forward into
the database.** It binds to loopback only and has no authentication. Do not
expose it, and do not put it behind a proxy on a real interface. Do not add
"run this command" endpoints; the action list is a fixed allowlist for a reason.

**No secrets in git.** `.gitignore` covers `secrets/*` and `.telemetry/`. A
gitleaks pre-commit hook enforces it and it has already caught the real password
being committed inside the redaction test's own fixtures. Never hardcode a
credential, not even a fake JWT — assemble it at runtime.

## 3. The HTTP API you build against

Base URL `http://127.0.0.1:8099`. Everything is JSON and already redacted.

### Read

| Endpoint | Returns |
|---|---|
| `GET /api/health` | `{cluster, artifacts: {name: {bytes, ageSeconds}}}` |
| `GET /api/summary` | `{walks, chain, coverage, graph, detections}` — see §4 |
| `GET /api/detections` | `{rules: [...], eventsConsidered}` — see §5 |
| `GET /api/graph` | the full reachability graph — see §6 |
| `GET /api/chain` | chain summary and per-hop verdicts |
| `GET /api/walks` | privilege-path sweep summary |
| `GET /api/attack-coverage` | ATT&CK registry report |
| `GET /api/boundaries` | boundary assertion results |
| `GET /api/telemetry?schema=<s>&limit=<n>` | raw events, `limit` capped at 1000, default 100 |

### Control

| Endpoint | Behaviour |
|---|---|
| `GET /api/actions` | `{name: {mutating: bool, about: string}}` for all 10 |
| `POST /api/action/<name>` | `202 {job}`. `409` if `mutating` and no `?confirm=yes` |
| `GET /api/job/<id>` | `{job}` — poll this |
| `GET /api/jobs` | all jobs |

A job looks like:

```json
{
  "id": "3f9a1c2e4b7d", "name": "chain", "state": "running",
  "exitCode": null, "elapsedSeconds": 12.4,
  "command": "powershell -NoProfile ...",
  "output": ["hop-1 [T1609.001] read the mounted token in-pod", "..."]
}
```

`state` is `running` | `done` | `failed`. `output` is a bounded tail (400 lines
in the registry, 200 served). Jobs live in memory and are lost on server restart
— poll aggressively and treat a 404 as "gone", not "failed".

The 10 actions and whether they change cluster state:

| action | mutating | what it does |
|---|---|---|
| `collect-audit` | no | export the audit log |
| `collect-runtime` | no | derive exec / token / log-read events |
| `collect-network` | no | read kube-router counters. **Run twice** — the first is a baseline, only the second has deltas |
| `attack-tag` | no | check every event against the ATT&CK registry |
| `graph` | no | re-derive and re-verify who-can-reach-what |
| `boundaries` | no | 33 assertions over namespaces, RBAC, NetworkPolicies |
| `drift` | no | live state vs manifests, both directions |
| `detections` | no | run the detection gate |
| `walks` | **yes** | walk all 7 privilege paths |
| `chain` | **yes** | the 6-hop intrusion: creates a pod, mints a cluster-admin token, reads the database |

**Design note for the control panel:** `collect-network` is the one action where
pressing it once gives a misleading result. The collector emits one of four
baseline states per counter — `no-baseline`, `compared`, `chain-rebuilt`,
`counter-reset` — and only `compared` carries a delta. Surface the state, and
consider a "collect ×2" affordance.

## 4. Data contracts, from the real files

### `GET /api/summary` → `walk-summary.json`

```json
{
  "generatedAt": "2026-09-26T19:26:47Z",
  "pathsWalked": 7,
  "assertions": { "held": 54, "failed": 0 },
  "attackIds": ["T1046","T1078.001","T1090.001","T1190","T1528","T1550.001","T1552.001","T1610","T1611"],
  "catalogAgrees": { "catalogOnly": [], "runnerOnly": [] },
  "results": [
    { "id":"PP-01", "file":"walk-pp-01-cluster-admin.ps1", "kind":"privilege path",
      "verdict":"walkable", "exitCode":0, "passed":10, "failed":0,
      "attackIds":["T1078.001","T1190","T1550.001"] }
  ]
}
```

Path ids: `PP-01` `PP-02` `PP-03` `PP-04` `WP-01` `WP-02` `SP-01`.
`verdict` is `walkable` | `CHANGED` | `ERRORED`.

### `GET /api/chain` → `chain-summary.json`

```json
{
  "generatedAt": "2026-09-26T19:16:38Z",
  "chainRun": "20260926-191638",
  "hopsSucceeded": 6, "hopsFailed": 0,
  "techniques": ["T1078.001","T1090.001","T1528","T1552.001","T1609.001"],
  "undetectable": ["T1078.001"],
  "hops": [
    { "id":"hop-1", "attackId":"T1609.001", "ok":true,
      "what":"read the mounted token in-pod",
      "detail":"subject system:serviceaccount:zerotrust-build:sa-build-runner, 1229 chars, value not printed" }
  ]
}
```

The six hops, in order: read the mounted token off the build runner · read the
duplicated DB password from a ConfigMap · port-forward to a policy-denied port ·
mint a token for the cluster-admin ServiceAccount · create a foothold pod in the
business zone · read application data with the stolen password.

**`undetectable` is the most important field in this file.** T1078.001 is walked
for real but no telemetry schema carries it, so no rule can fire on it. Render it
prominently. Do not render a green "fully detected" badge.

### `GET /api/graph` → `reachability-graph.json`

```json
{
  "generatedAt": "...",
  "verified": true,
  "verification": {
    "ran": true, "trustworthy": true,
    "comparisons": 25, "agreed": 25, "mismatched": 0,
    "edges": 6, "edgeListConsistent": true,
    "method": "one ephemeral probe pod per source identity at a time, carrying that identity's service account and the workload's own app label, dialling the destination Service ClusterIP so the DNAT path is exercised rather than bypassed",
    "positiveControl": "each probe pod was required to reach kube-dns on TCP 53, which no lab policy governs, and its results were discarded if that failed",
    "dropClassifier": "busybox nc reports nothing on failure, so a dropped SYN is told from a refused one by elapsed time measured inside the pod from /proc/uptime. This run: the slowest attempt that drew an answer was 380ms, the fastest silent drop was 1000ms, and the cut is at 600ms."
  },
  "nodes": [
    { "id":"build-runner", "pod":"build-runner-7cb5c4877-k4786",
      "namespace":"zerotrust-build", "zone":"", "serviceAccount":"sa-build-runner",
      "podIp":"10.244.2.4", "exposedPorts":["TCP/8080"] }
  ],
  "edges": [
    { "from":"telemetry-agent", "to":"orders-api", "port":8080, "protocol":"TCP",
      "kind":"reachable", "noListener":false, "observed":"open", "elapsedMs":380,
      "evidence":"modelled from live NetworkPolicy and confirmed by an observed TCP connection",
      "decidedBy":["orders-api-ingress","telemetry-agent-egress"] }
  ],
  "blockedPairs": [
    { "from":"build-runner", "to":"build-runner", "port":8080,
      "why":"egress denied: selected for egress by allow-dns-egress, default-deny-all and no rule admits this peer on this port; ...",
      "evidence":"the SYN was dropped after 1220ms with no answer, which no listening service can produce" }
  ]
}
```

Current state: **5 nodes, 6 open edges, 19 blocked pairs, 25/25 comparisons
agreed, 0 mismatched.**

`observed` is `open` or (absent/false) for blocked. `noListener: true` marks a
permitted-but-refused edge — there is one, `telemetry-agent → telemetry-agent:8080`,
and it is worth distinguishing from a genuine open path.

**Known data gap: `zone` is empty on every node.** The namespaces are the trust
zones (`zerotrust`, `zerotrust-build`, `zerotrust-observe`) and the field exists,
but nothing populates it. Either derive the zone from `namespace` in the
frontend, or fix the generator in `graph/build-reachability.ps1`. Deriving in the
frontend is a one-line map and does not need a cluster.

`blockedPairs` is the more interesting half of this file than `edges`, and the
current console barely shows it. A pair where `why` names the deciding policy is
the actual output of a zero-trust review.

### `GET /api/attack-coverage` → `attack-tag-report.json`

Key fields: `eventCount`, `knownTechniques[]`, `schemaRegistry[]`, `coverage[]`,
`emittedIds[]`, `unexercised[]`, `phase7Exclusions{}`, `instrumentationFlows`,
`workloadLabFlows`, `offBaselineTokens`, `passed`, `failures[]`.

`coverage[]` is the per-schema table — this is what a coverage chart wants:

```json
{ "schema":"network/observed-flow/v1", "coverage":"conditional",
  "observed":170, "tagged":4, "exempt":166, "untaggedUnjustified":0,
  "techniques":["T1021"], "exemptionsUsed":[...] }
```

`coverage` is one of `always` (every event must carry a technique),
`conditional`, or `inventory`. Current: 170 observed flows, 4 tagged, 166
exempt — and the 4 are all the lab's own sensor probes.

`phase7Exclusions` is prose a detector author needs and a UI should surface
verbatim, e.g. *"A T1021 rule must exclude source.role=instrumentation. Without
that exclusion its only hits in this cluster are the telemetry agent's own
health probes."*

### `GET /api/detections`

```json
{ "rules": [ { "id":"03170000-...-000003", "title":"...", "level":"high",
    "techniques":["T1609.001","T1550.001"], "schema":"runtime/container-exec/v1",
    "hits":108, "sample":[{"collectedAt":"...","techniqueIds":["T1609.001"],
      "summary":"kubernetes-admin exec zerotrust/postgres-0 (exec)"}] } ],
  "eventsConsidered": 1569 }
```

### `GET /api/telemetry`

Six schemas, ~1570 events total. Field names differ per schema; these are the
ones worth surfacing.

**`runtime/container-exec/v1`** (the big one, 1050 events) —
`collectedAt, auditId, firstSeen, auditStages, auditLines, subresource, target{namespace,pod,container,resolved}, command[], commandLine, interactive, tty, redactedQueryKeys[], identity{effectiveIdentity,authenticatedUser,impersonatedUser,impersonated,groups[],impersonatedGroups[]}, sourceIPs[], userAgent, granted, outcomeKnown, responseCodes[], outcome, resolution, candidateTechniques[{id,name,why}], note`

`subresource` is `exec` or `portforward`. `granted` is bool; `responseCodes` holds
`101` (granted) or `403` (refused).

**`runtime/token-request/v1`** (257) — `collectedAt, auditId, namespace,
serviceAccount, isLabServiceAccount, identity{...}, sourceIPs[], userAgent,
responseCode, requesterClass, attestedNode, labPodsMatchingThisSaOnThatNode,
interpretation, resolution, candidateTechniques[], note`

`requesterClass` is the whole detection for T1528: `kubelet` and
`control-plane-component` are the floor (208 of 257), `other` / `impersonated`
are the signal (15).

**`runtime/pod-log-read/v1`** (50) — `collectedAt, auditId, timestamp, stage,
namespace, pod, resolvedWorkload, identity{...}, sourceIPs[], userAgent,
responseCode, resolution, candidateTechniques[], note`

**`network/observed-flow/v1`** (170) — `collectedAt, scope, source{name,pod,
port,role,serviceAccount}, dest, destPort, state, resolution, attribution,
candidateTechniques[], note`

`scope` is `lab-zone` or `cluster-internal`. `source.role` is `workload` or
`instrumentation` — see §6.

**`network/denial-counter/v1`** (2) — `collectedAt, node, chain,
subject{ip,pod,namespace,app,serviceAccount,zone}, identityStale,
baselineState, deltaValid, deltaReason, counter{deniedPackets, loggedPackets,
acceptedPackets, totalPackets, deltaDenied, deltaLogged, deltaAccepted,
deltaTotal}, policiesApplied[], resolution, attribution, packetsPerRefusal,
candidateTechniques[], note`

**`runtime/workload-identity/v1`** (19) — inventory: `namespace, zone, pod,
podUid, app, container, serviceAccount, image, imageId, imageIntegrity, phase,
node, podIp, restartCount, lastExitCode, lastReason, securityContext, ...`

### `GET /api/boundaries` → `boundary-tests.json`

`{generatedAt, passed:33, failed:0, total:33, results:[{name, expected,
observed, detail, passed}]}`

## 5. What the current console does wrong

Ranked by how much they cost a person trying to use this during an incident.

1. **Nothing updates while an attack runs.** Views load once on tab switch. The
   phase is called "watch the console during a live attack" and it cannot. You
   press `chain`, wait for a job to finish, and only then see anything. Poll the
   read endpoints while a job is `running`.

2. **The graph is a flat list, not a graph.** 6 edges rendered as rows. The
   interesting structure is zones (`zerotrust` / `zerotrust-build` /
   `zerotrust-observe`) and which edges cross between them — that is the entire
   subject of the file. And `blockedPairs` (19 of 25) is barely surfaced, when
   it is the more informative half.

3. **No cross-linking.** The same technique appears in detections, the chain and
   the event stream as three unrelated rows. Clicking `T1528` should get you
   every hop, rule and event for it.

4. **No search or filter on the event stream** beyond a schema dropdown, and no
   full-text over `commandLine` — which is where the interesting strings are.

5. **Job output is a raw `<pre>` blob.** The scripts emit a consistent
   `[PASS]` / `[FAIL]` / `[DONE]` / `hop-N [Txxxx]` line format. Parse it into
   something structured.

6. **Coverage bars are meaningless as drawn.** They normalise against the largest
   schema, so a schema with 2 events and one with 1050 look equally "full". Use
   `tagged / observed` per schema, which is the number that means something, and
   show `coverage: always|conditional|inventory` as a badge.

7. **No technique names.** Only `T1528` — an analyst has to know it means
   *Steal Application Access Token*. The names are in `knownTechniques[]` in the
   coverage report and in the Sigma `title` fields.

8. **Nothing says what to do.** Each rule has a `level` and a `description`
   explaining the false positives. A detection without a triage hint is a
   notification, not a detection.

9. **Staleness is one number.** `artifacts[].ageSeconds` is per file but nothing
   ties it to the view using it. A detection count from a two-hour-old collection
   should say so.

10. **Redaction is invisible.** A field reads `PGPASSWORD=<redacted>` and
    nothing marks that a value was removed. Consider a subtle marker so an
    analyst knows evidence was withheld.

## 6. Things the data will mislead you about

These are not bugs in your UI. They are places where a naive reading produces a
confident wrong answer, and the lab has been bitten by each of them at least
once.

- **`source.role = instrumentation`.** All 4 T1021 cross-zone flows are the
  telemetry sensor's own health probes. A "cross-zone connection" rule that
  ignores this fires only on the lab checking itself. But the field is a lab
  annotation, not a property of the traffic — a compromised sensor produces
  byte-identical flows. Filtering it is right here and wrong in the one case
  that matters most. Say so on screen.

- **`unexercised: []` does not mean full coverage.** It means every technique
  with a *mapping* has at least one event. T1078.001 has no mapping and no rule,
  so it never appears there. Check `chain.undetectable`, not `unexercised`.

- **`observed: open` in the graph means the datapath agreed.** A reachability
  graph is blind to remote service use by an actor already inside a permitted
  path, and to `pods/portforward`, which relays through the API server and never
  traverses the pod-to-pod path any policy governs.

- **`agreed: 25, mismatched: 0` is a consistency check, not a security result.**
  An earlier version reported 25/25 agreement *while calling all 25 pairs
  reachable*, 19 of which were dropped. Check `verification.positiveControl` and
  `edgeListConsistent` are both true, and do not treat agreement as openness.

- **A rule firing is not a hop being detected.** The chain report says "rule
  fires" for exactly this reason. A rule carrying a technique tag existing and
  matching is not evidence that the hop caused the match.

- **Counter deltas are not connections.** `packetsPerRefusal` is measured at 2
  per refused attempt and retries to an already-refused IP are counted again, so
  a `deltaDenied` of 2 is one refused connection, not two.

- **A quiet lab and a broken collector look identical.** This lab lost 91,479
  audit records to log rotation while the exporter reported success. Always show
  artifact age next to any count derived from it.

## 7. What to build

**Stack:** whatever you like, but keep it dependency-light and add no build step
the repo cannot reproduce. No Node/npm is the current house rule; a single
`pip install -r requirements.txt` is the precedent. If you need a chart or graph
library, vendor it or accept the dependency explicitly.

**Views, in priority order:**

1. **Live overview** — the four numbers, the coverage gap, artifact freshness,
   and an event feed that updates while a job runs. Poll the read endpoints
   every 2s while any job is `running`, drop to 15s when idle.
2. **Chain timeline** — the 6 hops as a sequence, each showing technique name,
   pass/fail, detail, and whether a rule exists. Prominently flag
   `undetectable`.
3. **Graph** — zones as columns or clusters, edges as arcs, blocked pairs
   reachable behind a toggle. Show `verification` as a provenance strip: 25/25
   agreed, positive control passed, edge list consistent.
4. **Detections** — rules with technique *names*, `tagged/observed` rather than
   raw counts, a `description` and `falsepositives` disclosure, and a click
   through to matched events.
5. **Event stream** — filter by schema, free-text over `commandLine`, technique
   filter, time range. Show which fields were redacted.
6. **Control** — the 10 actions, mutating ones visually distinct and double-
   confirmed, structured job output, and a visible "collect twice for network"
   hint.

**Cross-linking is the single highest-value feature.** One technique id should
be the join key across every view.

**Honesty requirements.** Do not render a green "fully detected" state while
`chain.undetectable` is non-empty. Do not present a reachability graph as
complete. Show the provenance of every number — which file, how old, and what
method produced it. This project's standard is that a number without its method
attached is a claim, not a measurement, and several of the bugs in its history
were exactly a number escaping from the method that constrained it.

## 8. Verifying what you build

```
powershell telemetry\audit\export-audit-log.ps1
powershell telemetry\runtime\collect-runtime.ps1
powershell telemetry\network\collect-network.ps1
powershell telemetry\network\collect-network.ps1     # twice: the second has deltas
python dashboard\server.py
```

Then, in the UI:

- `/api/detections` should report 6 rules, all with `hits > 0`. Current counts:
  `det-0003` 108, `det-0004` 32, `det-0005` 2, `det-0006` 4, `det-0010` 15,
  `det-0011` 24. **These are a fingerprint of the current lab state, not
  targets** — they move every time anything is walked.
- The chain view must show 6 hops and **must not** show "fully detected".
- No rendered page may contain a credential-shaped value. Check the raw
  responses, not just the rendered text.
- Press `chain`, and while it runs the event feed should show exec sessions
  appearing. That is requirement 1 in §7.
- Press `collect-network` once and confirm the UI explains why there is no delta
  yet.
