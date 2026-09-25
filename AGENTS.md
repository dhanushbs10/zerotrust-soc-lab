# Agent guide

## What this repo is

A local Kubernetes security lab: a deliberately vulnerable cluster, real detection tooling,
and a console that shows whether an intrusion was caught. Nothing here is a simulation.

## Layout

| Path | Contents |
|---|---|
| `cluster/` | Bootstrap config and Kustomize base plus overlays |
| `identities/` | Workload identity definitions and trust boundaries |
| `workloads/` | Lab applications |
| `attack/` | Privilege paths and red-team emulation scripts |
| `telemetry/` | Collection: audit, runtime, network |
| `detections/` | Sigma rules, one directory per technique, each with tests |
| `attack-data/` | ATT&CK mapping, entity schema, risk model |
| `data/` | Graph builder and risk scoring |
| `dashboard/` | SOC console |
| `docs/` | Architecture, runbook, design decisions |

## Non-negotiable rules

1. No secrets, kubeconfigs, tokens, or cluster state in git. `.gitignore` enforces this; never
   bypass it with `-f`.
2. Every detection ships with a test that proves it fires. An untested rule is not a detection.
3. Every detection, attack step, and telemetry rule carries an ATT&CK technique ID.
4. Manifests go through Kustomize, never hand-applied with `kubectl apply` in scripts.
5. Pin image versions by digest in anything that runs in the cluster. `:latest` is banned.
6. The lab is intentionally insecure in the directories named for it. Do not "fix" the
   vulnerabilities in `attack/` or `workloads/` — they are the test fixtures.

## Hygiene

- Run `pre-commit install` once after cloning.
- Run `pre-commit run --all-files` before pushing.
- Commit messages follow Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`.
- One logical change per commit.
- Never commit generated cluster output, detection results, or run transcripts.

## Working order

Build the environment, verify it, then attack it, then detect the attack. Do not add
detections before there is something to detect.
