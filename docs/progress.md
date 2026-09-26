# Progress

Phases are build order, not scope reduction. Each ends with something runnable.

| # | Phase | Status | Done when |
|---|---|---|---|
| 0 | Foundations | **done** | repo is clean, hooks pass, one command builds a 3-node cluster |
| 1 | Trust boundaries | not started | namespaces default-deny; every pod has a distinct identity |
| 2 | Least privilege | not started | no workload holds an unneeded permission; drift fails a test |
| 3 | Secrets and supply chain | not started | secret sprawl and vulnerable images catalogued |
| 4 | Privilege paths | not started | each documented path is walkable by script |
| 5 | Telemetry | **partial** | audit, runtime, and network data tagged with ATT&CK IDs |
| 6 | Correlation graph | not started | who-can-reach-what answers correctly |
| 7 | Detections | not started | every rule fires against a real attack step |
| 8 | Purple team | not started | full chain runs end to end, every step detected |
| 9 | SOC console | not started | dashboard readable during a live attack |
| 10 | Packaging | not started | fresh clone plus one command reproduces everything |

## Phase 0 deliverables

- `cluster/bootstrap/kind-config.yaml` — 3 nodes, zone labels, audit logging enabled
- `cluster/bootstrap/bootstrap.ps1` — idempotent build with three-state handling
- `cluster/demo/nginx-pod.yaml` — smallest complete manifest, used as a teaching artifact
- `telemetry/audit/export-audit-log.ps1` — normalized audit events as JSONL
- `telemetry/audit/README.md` — how audit logging works and how it fails

## Findings so far

- **Kubernetes does not log API activity by default.** A default cluster has no
  record of who did what. Enabling it needs four things at once: the policy
  file on the node, `extraVolumes` to expose it to the API server container,
  `--audit-policy-file`, and `--audit-log-path`. Setting only the log path
  produces a healthy API server that silently records nothing.
- **`user.username` is not the identity RBAC decided on.** Impersonation records
  the authenticated caller in `user` and the claimed identity in
  `impersonatedUser`. Detection rules must match the resolved
  `effectiveIdentity` or they will miss impersonation-based escalation.

## Open decisions

- Dashboard visual direction: which design skill owns it.
- Repository name: `ZeroTrust-SOC-Lab` used so far, rename if preferred.
- Lab vulnerabilities: synthetic misconfigurations versus pinned real CVEs.
- Branch protection and required checks on `main`.
- Audit policy level: raise to `RequestResponse` for a narrow resource set, or
  keep `Metadata` everywhere and accept losing request bodies.
