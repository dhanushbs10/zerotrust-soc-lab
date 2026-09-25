# ZeroTrust-SOC-Lab

A self-contained Kubernetes security range. A deliberately vulnerable cluster, real detection
tooling, and a console that shows whether an intrusion was caught.

Everything runs locally. Nothing phones home. The cluster is disposable: build it, break it,
delete it, rebuild it.

## Status

Early. The repository skeleton and hygiene tooling are in place. Cluster bootstrap is the next
increment. See [docs/progress.md](docs/progress.md) for where each phase stands.

## What this is not

- Not a production cluster template. The security holes are intentional and tracked.
- Not a simulation. The monitoring is real tooling and the attacks are real.
- Not a beginner tutorial. It assumes you can read a Kubernetes manifest.

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
cluster/      bootstrap and Kustomize base plus overlays
identities/   workload identity and trust boundaries
workloads/    lab applications
attack/       privilege paths and red-team scripts
telemetry/    collection: audit, runtime, network
detections/   Sigma rules, one directory per technique, each with tests
attack-data/  ATT&CK mapping, entity schema, risk model
data/         graph builder and risk scoring
dashboard/    SOC console
docs/         architecture, runbook, decisions
```

## Hygiene

This repo treats secrets and cluster state as hostile to version control.

```bash
pre-commit install          # once, after cloning
pre-commit run --all-files  # before pushing
```

Pre-commit runs YAML lint, Kubernetes schema validation, secret scanning, shell and Dockerfile
linting, and Markdown lint. CI runs the same hooks and fails on a dirty tree.

## Contributing

Read [AGENTS.md](AGENTS.md) first. It documents the rules that are not obvious from the code.
