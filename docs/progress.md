# Progress

Phases are build order, not scope reduction. Each ends with something runnable.

| # | Phase | Status | Done when |
|---|---|---|---|
| 0 | Foundations | **done** | repo is clean, hooks pass, one command builds a 3-node cluster |
| 1 | Trust boundaries | **done** | namespaces default-deny; every pod has a distinct identity |
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

## Phase 1 deliverables

- `cluster/networking/kube-router.yaml` — CNI providing **real** NetworkPolicy enforcement
- `identities/` — 3 namespaces, 5 ServiceAccounts, 4 RBAC objects, 14 NetworkPolicies
- `workloads/` — web-frontend, orders-api, postgres, build-runner, telemetry-agent
- `cluster/bootstrap/secrets.ps1` — credential generation plus the deliberate SP-01 leak
- `secrets/credentials.example.yaml` — the committed template; values never are
- `tools/validate-yaml.py` — strict YAML with digest-pin enforcement
- `tools/test-boundaries.ps1` — 33 assertions against a running cluster
- `attack/catalog/privilege-paths.md` — PP-01, PP-02, WP-01, WP-02, SP-01

### Verified, not assumed

`tools/test-boundaries.ps1` — **33 passed, 0 failed** (`.telemetry/boundary-tests.json`)

- 16 authorization assertions via `kubectl auth can-i`, including 4 that must be
  **allowed** because PP-01 is the lab's headline weakness. If those flip to
  `no`, the weakness is gone and every detection written against it is untestable,
  so its absence is a failure of the test suite.
- 17 network assertions. Each source identity is a probe pod carrying that
  workload's labels, in that workload's namespace, dialing that workload's
  Service ClusterIP.
- Preflight refuses to run if kube-router is not ready on every node. Under
  kindnet every network assertion would report confidently and wrongly.

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
- **A missing `---` silently deletes a Kubernetes object.** PyYAML and
  `check-yaml` both accept a document whose duplicate `apiVersion` key is
  discarded, and `kubectl apply --dry-run=client` reports success. Six
  NetworkPolicies vanished this way while every hook passed.
  `tools/validate-yaml.py` now rejects duplicate keys.
- **RBAC and network reach are independent axes.** PP-01's service account is
  network-isolated to DNS-only and still reads every Secret in the cluster,
  because control-plane access is not pod-to-pod traffic. The network policy is
  in no position to stop it.
- **An ingress allowance can be live in review and dead in the datapath.**
  `web-frontend-ingress` admitted two sources whose own egress policies
  permitted neither. `tools/test-boundaries.ps1` caught it; the dead rules were
  deleted rather than made live.
- **NetworkPolicy cannot be used to restrict access to the API server.**
  kube-router's service proxy DNATs `10.96.0.1:443` to the control-plane node
  on 6443 in the nat table, before the policy chain runs in the filter table.
  The rule then describes an address that no longer exists. Verified by reading
  the generated iptables rules and the destination ipset.
- **A permission that cannot be exercised is a liability.**
  `sa-telemetry-agent` held a read-only ClusterRole that never worked, for the
  reason above. It was removed; the token stays, because it is the sensor's
  identity in the audit log.

## Open decisions

- Dashboard visual direction: which design skill owns it.
- Repository name: `ZeroTrust-SOC-Lab` used so far, rename if preferred.
- Lab vulnerabilities: synthetic misconfigurations versus pinned real CVEs.
  Current answer, recorded in `attack/catalog/privilege-paths.md`: synthetic
  misconfigurations only, no fabricated CVEs in real pinned images.
- Branch protection and required checks on `main`.
- Audit policy level: raise to `RequestResponse` for a narrow resource set, or
  keep `Metadata` everywhere and accept losing request bodies.
