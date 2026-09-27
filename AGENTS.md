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
| `telemetry/` | Collection: audit, runtime, network, and the ATT&CK registry |
| `detections/` | Sigma rules, one directory per technique, plus `posture/` for live-config checks |
| `graph/` | Reachability derivation and its probe-based verification |
| `tools/` | Drift, image, pod and secret scanners; the cluster-free self-test gate |
| `dashboard/` | SOC console |
| `docs/` | Architecture, runbook, design decisions |

`attack-data/`, `data/` and `scripts/` existed as empty directories in the early
skeleton and were listed here as if they held the ATT&CK mapping, a risk model and
a graph builder. None of that content was ever written; the ATT&CK registry that
does exist lives in `telemetry/tag-attack-ids.ps1`. The entries are removed rather
than left describing something that is not there.

There is one script at the repository root, `run-lab.ps1`, which is the whole lab
in order. Read it first.

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
