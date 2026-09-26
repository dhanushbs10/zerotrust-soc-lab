# Telemetry

Three collectors, each reading from the place where the fact is actually
recorded. None of them infers a conclusion from a manifest, because a manifest
says what was requested and the enforcement point says what happened.

| Collector | Reads from | Answers |
|---|---|---|
| `audit/export-audit-log.ps1` | API server audit log | who called which API, as which identity |
| `network/collect-network.ps1` | iptables counters and conntrack, on all 3 nodes | which pod had traffic refused, and which pod was on the other end of a permitted connection |
| `runtime/collect-runtime.ps1` | audit log plus the API | who ran what command in which container, who minted which token, and what identity each workload runs as |

Output lands in `.telemetry/`, which is gitignored. Nothing here is a
credential store; the one place a secret could plausibly appear, an exec command
line, is passed through a redactor before it is written.

## What this lab does not have, and why

Three things a SOC would normally rely on are absent, and pretending otherwise
would be the easiest way to make this lab lie:

**No flow logs.** kube-router v2.6.1 is started with exactly
`--run-router --run-firewall --run-service-proxy --bgp-graceful-restart
--kubeconfig`. There is no flow-log option, no metrics port, and no API that
reports which policy applied to which pod. So "who talked to whom" has to be
read out of the kernel, which is what the network collector does. NFLOG rules
are present in the ruleset with `nflog-group 100`, and there is no `nflog`
binary on the node to read them, so they are decoration.

**No eBPF, no runtime security agent.** Falco or an equivalent would give
process-level visibility inside a container. Instead the runtime collector uses
the API server's own audit log, which turns out to be better than expected at
`Metadata` level — see below.

**No packet capture.** Refused traffic is visible only as a count. Which port
and which destination was attempted is genuinely not present at the enforcement
point, because the REJECT rule is policy-agnostic: it matches
`mark match ! 0x10000/0x10000`, meaning "anything not marked allowed". The
collector states this on every event rather than leaving it to be discovered.

## The finding that matters most

At `Metadata` audit level, the full `requestURI` is logged. For a pod exec that
includes every argument:

```
/api/v1/namespaces/zerotrust-build/pods/build-runner-7cb5c4877-k4786/exec
  ?command=sh&command=-c&command=ls+-l+%2Fvar%2Frun%2Fsecrets%2F...%2B+2%3E%261
  %3B+echo+---&container=runner&stderr=true&stdout=true
```

Decoded, that is the first step of PP-01: listing the service account token
directory. 17 sessions in this cluster ran
`sh -c cat /var/run/secrets/kubernetes.io/serviceaccount/token` and one ran
`head -c 120 /var/run/secrets/kubernetes.io/serviceaccount/token`. The
credential-theft step of a privilege-escalation path is legible in the log, in
the exact words the adversary used, without raising the policy above
`Metadata` and without an agent in the container.

Two encoding details, both measured, both of which produce plausible wrong
output if missed:

- kubectl writes a space as a literal `+` (0x2B), not `%20`.
  `[uri]::UnescapeDataString` leaves `+` alone, so it must be converted to a
  space *before* percent-decoding. Miss this and the command parses as
  `cat+/var/run/secrets/...`, which no detection can grep for.
- An exec is logged **twice**, once at stage `ResponseStarted` and once at
  `ResponseComplete`, under one shared `auditID`. 1294 lines are 647 sessions.
  Counting lines reports exactly double.

## Measured behaviour of the network counters

Everything below was measured on this cluster, not inferred.

**A refusal is counted on the chain of the pod whose policy refused it.** Egress
refused by the source's own policy lands on the source's chain. Ingress refused
by the target's policy lands on the *target's* chain — so the telemetry agent
probing `build-runner` registers against `build-runner`, and a target's counter
cannot answer "was anything aimed at me".

**A refusal is only visible if policy evaluation happened.** DNAT is installed
per exposed Service port and runs before the pod's policy chain:

```
pod IP    10.244.1.2   -> :12401   REJECT +3
ClusterIP 10.96.19.167 -> :12402   REJECT +0    (no DNAT for that port)
```

This is a trap for detection tests. A scan written against Service DNS names can
walk every port it likes, register nothing, and still look like it is generating
hostile traffic. To make a refusal observable, address the pod IP or a port the
Service actually exposes.

**The counter counts packets, at 2 per refused connection attempt, and retries
are counted again.** Three attempts to one brand-new port gave +2, +2, +2; four
attempts to four brand-new ports gave +8.

An earlier reading of this lab concluded the opposite — that conntrack
deduplicates retries so only distinct flows count. That conclusion was wrong. It
came from probes to `postgres.zerotrust.svc`, which is NXDOMAIN; the resolvable
name is `postgres.zerotrust.svc.cluster.local`. Nothing was sent, so the counter
correctly did not move, and a counter that did not move was read as
deduplication. A measurement that proves nothing looks exactly like a measurement
that proves something surprising.

**Counters are not monotonic, and chain names are not identities.** kube-router
tears down and rebuilds the pod chains when it reprograms the firewall. All
eight were observed with different names, and lower counters, between two
collections minutes apart with no kube-router restart in between. The network
collector therefore keys its baseline on node plus pod name, and every event
declares one of four states — `no-baseline`, `compared`, `chain-rebuilt`,
`counter-reset` — emitting a delta only when `compared`. All four states are
exercised by the test run, including both failure states, and neither failure
state can produce a negative delta.

**Most of what conntrack sees is not lab traffic.** Of 173 observed flows, 169
are `kube-system` to `kube-system` coredns chatter. They are labelled
`scope: cluster-internal` rather than dropped, so the count stays auditable, and
they carry no candidate technique — a rule that fires on DNS says nothing about
this lab.

## Measured baseline for token requests

`serviceaccounts/token` is legitimately busy: every kubelet mints a token for
each pod it runs. This cluster has made 135 such requests, and all 135 are
baseline — 78 from `system:node:*` kubelets, 57 from
`system:kube-controller-manager` for its own controller accounts.

So the event carries `requesterClass` of `kubelet`,
`control-plane-component`, `impersonated` or `other`, and only the last two are
outside the measured baseline. An earlier version of this collector treated
anything not matching `system:node:*` as unusual and reported 57 such requests.
All 57 were the control plane doing its job. A field that cries wolf 57 times
teaches an analyst to stop reading it, which is worse than having no field.

The token value is never in the audit log, so a token minted here cannot be read
back from this source. What is logged is the request, not the credential.

## Two things this telemetry cannot do

**It cannot distinguish the operator from an attacker by identity.** All 647
exec sessions in this cluster were run by `kubernetes-admin`, because no pod in
the lab can reach the API server and every in-pod action is therefore driven
from outside by the operator. An exec-based detection cannot use "who" as a
discriminator here. It has to use what — the command, the target pod, the
service account whose token was read. This is a property of the lab, not a bug
in the collector, and it is the reason Phase 7 detections are written against
behaviour.

**It records requests, not consequences.** The audit log shows that
`cat /var/run/secrets/.../token` ran. It does not show whether the file existed,
whether the read succeeded, or what was done with the bytes. A read of a
credential file and a read of `/dev/null` are the same event in this telemetry.

## ATT&CK tagging

Every emitted event carries `candidateTechniques`, each with an `id`, a `name`,
a `why`, and a `mappingBasis` explaining why that technique was chosen.

These are **candidates, not detections**. Nothing in this directory fires,
alerts, or decides anything. Deciding whether an event is an attack is Phase 7,
and a rule that claims otherwise is a rule nobody has tested. The
`mappingBasis` field exists so a reader can disagree with a mapping on its
merits — two of the mappings here are recorded as judgement calls and one is
recorded as weak, explicitly, rather than presented as settled.

## Running

```powershell
.\telemetry\audit\export-audit-log.ps1          # -> .telemetry/audit-events.jsonl
.\telemetry\network\collect-network.ps1         # -> .telemetry/network-events.jsonl
.\telemetry\runtime\collect-runtime.ps1         # -> .telemetry/runtime-events.jsonl
```

The runtime collector takes `-FromFile` to re-derive from an existing export
with no cluster running, and `-SinceMinutes` to bound the window. A bounded
window is always labelled, because a truncated window that is not labelled is
indistinguishable from a quiet cluster.
