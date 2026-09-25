# Progress

Phases are build order, not scope reduction. Each ends with something runnable.

| # | Phase | Status | Done when |
|---|---|---|---|
| 0 | Foundations | in progress | repo is clean, hooks pass, one command builds a 3-node cluster |
| 1 | Trust boundaries | not started | namespaces default-deny; every pod has a distinct identity |
| 2 | Least privilege | not started | no workload holds an unneeded permission; drift fails a test |
| 3 | Secrets and supply chain | not started | secret sprawl and vulnerable images catalogued |
| 4 | Privilege paths | not started | each documented path is walkable by script |
| 5 | Telemetry | not started | audit, runtime, and network data tagged with ATT&CK IDs |
| 6 | Correlation graph | not started | who-can-reach-what answers correctly |
| 7 | Detections | not started | every rule fires against a real attack step |
| 8 | Purple team | not started | full chain runs end to end, every step detected |
| 9 | SOC console | not started | dashboard readable during a live attack |
| 10 | Packaging | not started | fresh clone plus one command reproduces everything |

## Open decisions

- Dashboard visual direction: which design skill owns it.
- Repository name: `ZeroTrust-SOC-Lab` used so far, rename if preferred.
- Lab vulnerabilities: synthetic misconfigurations versus pinned real CVEs.
- Branch protection and required checks on `main`.
