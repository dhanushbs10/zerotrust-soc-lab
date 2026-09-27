# ZeroTrust-SOC-Lab

A self-contained Kubernetes security range. A deliberately vulnerable cluster, real detection
tooling, and a console that shows whether an intrusion was caught.

Everything runs locally. Nothing phones home. The cluster is disposable: build it, break it,
delete it, rebuild it.

## Quick start

```powershell
./run-lab.ps1                # build, attack, collect, verify, detect
python dashboard/server.py   # then open http://127.0.0.1:8099
```

One command builds the cluster, walks seven privilege paths, runs a six-hop intrusion,
collects the evidence, proves every detection fires, and leaves a console to read it in.

The ordering inside that command is not arbitrary and is documented where it matters. The
graph and the attack chain both run **before** the network baseline is seeded, and the
privilege paths **after** it — because the first two create pods, kube-router regenerates its
iptables chains and resets the counters when it does, and network telemetry is a delta
between two comparable reads. Both obvious orderings get this wrong, and they fail while
looking healthy. Separately, the attack runs **before** collection, because telemetry
describes what happened and the thing that has to happen first is the attack; the reverse
produces a green run over an empty audit log, and an empty audit log is indistinguishable
from a quiet cluster.

```powershell
./run-lab.ps1 -SkipBootstrap -SkipAttack  # re-collect and re-verify; the rule-editing loop
./run-lab.ps1 -Recreate                    # delete the cluster and build it again
./run-lab.ps1 -Serve                       # ...and leave the console up
```

**New here, or picking it up cold: read
[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).** It explains the zones, the credential model,
the seven telemetry schemas, the ATT&CK registry, the detection gate, and — most usefully —
what the lab does *not* detect.

## What this is

A local Kubernetes attack-to-detection lab. A deliberately vulnerable cluster, real telemetry
read off the running system, ATT&CK-tagged detections that are proven to fire, and a console
that shows whether an intrusion was caught.

Current state: 3 trust zones, 5 workloads, 7 privilege paths (54 assertions), 6 chain hops,
7 telemetry schemas, 7 Sigma rules, 5 posture checks, 5-node reachability graph.

Two different kinds of check, and they are not interchangeable:

| | reads | asks | where |
|---|---|---|---|
| **detection** | telemetry | did this event happen? | `detections/*/`, Sigma |
| **posture** | live configuration | is this acceptable? | `detections/posture/` |

The second kind has no events, so it has no `logsource.schema` and no `detection:` block.
The Sigma gate excludes it explicitly — when it didn't, `sigmalite` raised
`SigmaError: no detection block` and took the whole detection gate down with it.

## What this is not

- Not a production cluster template. The security holes are intentional and tracked.
- Not a simulation. The monitoring is real tooling and the attacks are real.
- Not a beginner tutorial. It assumes you can read a Kubernetes manifest.
- Not a claim of completeness. `docs/HOW-IT-WORKS.md` has a section on exactly what it does
  not detect, and why.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Desktop | WSL2 backend, data on a drive with 40GB+ free |
| kind | Cluster runtime |
| kubectl | Cluster control |
| Helm | Package installs |
| Node.js 20+ | Dashboard build |
| Python 3.11+ | Detection tooling |

## Layout

```
run-lab.ps1   one command: the whole lab, in order, with the reasons
cluster/      bootstrap and Kustomize base plus overlays
identities/   workload identity and trust boundaries
workloads/    lab applications
attack/       privilege paths, the attack chain, red-team scripts
telemetry/    collection: audit, runtime, network, and the ATT&CK registry
detections/   Sigma rules, one directory per technique, plus the gate
graph/        reachability derivation and its probe-based verification
attack-data/  ATT&CK mapping, entity schema, risk model
data/         risk scoring
dashboard/    SOC console
tools/        drift, image, pod and secret scanners; the self-test gate
docs/         HOW-IT-WORKS.md, progress.md, the audit record
```

## Hygiene

This repo treats secrets and cluster state as hostile to version control.

```bash
pre-commit install          # once, after cloning
pre-commit run --all-files  # before pushing
```

Pre-commit runs YAML lint, Kubernetes schema validation, secret scanning, shell and Dockerfile
linting, and Markdown lint. CI runs the same hooks and fails on a dirty tree.

The last hook is the one worth explaining: `tools/run-selftests.ps1` runs six suites that need
no cluster, and each suite **proves it can fail** before it is trusted. The reachability
classifier is broken on purpose, the Sigma evaluator is mutated, the redactor is handed a
credential-shaped string to leak. A suite that cannot fail is not a test, and the counts in
its output exist so you can tell the difference.

## Contributing

Read [AGENTS.md](AGENTS.md) first. It documents the rules that are not obvious from the code.
