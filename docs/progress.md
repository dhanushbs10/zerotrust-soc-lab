# Progress

Phases are build order, not scope reduction. Each ends with something runnable.

| # | Phase | Status | Done when |
|---|---|---|---|
| 0 | Foundations | **done** | repo is clean, hooks pass, one command builds a 3-node cluster |
| 1 | Trust boundaries | **done** | namespaces default-deny; every pod has a distinct identity |
| 2 | Least privilege | **done** | no workload holds an unneeded permission; drift fails a test |
| 3 | Secrets and supply chain | **done** | secret sprawl and vulnerable images catalogued |
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

## Phase 2 deliverables

- `tools/scan-drift.ps1` — compares each service account's real grants against
  its documented need, and reports hardening gaps
- `drift/baseline.json` — the 10 expected findings, each with a written reason

### Verified, not assumed

`tools/scan-drift.ps1` — **10 expected, 10 observed, 0 new, 0 disappeared**
(`.telemetry/drift-scan.json`)

Both drift directions were proved to fail, which is the only thing that makes a
baseline meaningful:

- **New finding.** A `RoleBinding` granting `sa-postgres` the config-reader role
  produced 2 findings, graded MEDIUM for the ConfigMap and HIGH for the Secret,
  and exit 1. Removing it returned the scan to exit 0.
- **Disappeared finding.** A baseline entry naming a finding that no longer
  exists produced `disappeared 1` and exit 1. This is the direction that matters
  most: every baselined finding is a planted weakness, so losing one means a
  detection written against it can no longer be tested, and nothing else in the
  suite would notice.

Three design decisions worth keeping:

- **Expectations are longhand, not derived from the manifests.** A scanner that
  reads the RBAC files and reports that the RBAC files match itself cannot fail.
  `sa-build-runner`'s documented need is the empty set, which is the honest
  answer for a CI runner and is what makes PP-01 report as HIGH rather than
  quietly pass.
- **Finding keys use namespace, app label and resource name, never a pod name.**
  Pod names embed a ReplicaSet hash and a random suffix, so keying on one turns
  every rollout into phantom drift in both directions.
- **Unknown-ServiceAccount checks are scoped to the lab namespaces.** An
  unscoped version flagged all 50-odd `kube-system` accounts and buried the 10
  findings that matter.

## Phase 3 deliverables

- `tools/scan-images.ps1` — reads each running container's package database and
  queries OSV.dev, producing a real vulnerability catalogue
- `tools/scan-secrets.ps1` — measures credential sprawl, including whether any
  live credential has reached the committed git tree
- `drift/images-baseline.json` — pinned digests and known advisories
- `drift/secrets-baseline.json` — the known sprawl, with fingerprints

### Verified, not assumed

All four harnesses pass together: **33 boundary assertions, 10 drift findings,
85 image advisories, 2 secret findings.**

**85 advisory records across 6 images**, none of them simulated. Every number
comes either from a file read out of a running container or from a response
cached in `.telemetry/osv-cache/`.

| image | distro | packages | advisories |
|---|---|---|---|
| `nginx:…65645c7b` — web-frontend, orders-api | Alpine 3.21.3 | 68 | 30 |
| `docker:…851f91d2` — build-runner | Alpine 3.21.3 | 34 | 16 |
| `kube-router:…5215719695` | Alpine 3.22.1 | 52 | 9 |
| `postgres:…721873c3` | Alpine 3.24.2 | 45 | 0 |
| `alpine:…d9e853e8` — telemetry-agent | Alpine 3.20.10 | 14 | 0 |

The nginx digest is the worst of them, and its 30 advisories include
`libpng` ×9, `libxml2` ×6, `curl` ×3, `busybox`, `c-ares`, `musl`, `tiff`,
`zlib` and `libxpm`. kube-router's 9 include a `musl` advisory scoring
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`.

`postgres` and `telemetry-agent` are clean against ecosystems calibrated to hold
102 and 73 records for a single package respectively, so that clean is a
measured result rather than an absence of data.

**SP-01 is 2 findings, not 21.** One credential, fingerprint `A069F0C1482A91C8`,
leaked twice: verbatim as `app-config-leak/DB_PASSWORD`, and embedded inside
`app-config-leak/DATABASE_URL`. The embedded copy is the worse of the two,
because it also hands out the host and database name, and an equality-only test
ranks it below the bare copy and misses it.

**A zero is not believed without calibration.** OSV does not validate ecosystem
names: `Alpine:v9.99` is accepted and returns an empty response byte-identical to
a clean result. Every ecosystem is therefore probed first with a package known to
be densely covered. Measured: `Alpine:v3.20` → 73, `v3.21` → 86, `v3.24` → 102,
`Debian:12` → 260, `Alpine:v9.99` → 0. A workload on an ecosystem that fails
calibration is reported UNVERIFIED and fails the scan.

**Both drift directions proved, per tool.** For images: a changed nginx digest
produced `IMAGE DIGEST CHANGED` and exit 1; removing kube-router's advisories
from the baseline produced `9 NEW ADVISORY/ADVISORIES` and exit 1. For secrets: a
file containing a live credential, added to the index, produced a CRITICAL
finding and exit 1, and removing it returned exit 0.

The image drift check then proved itself on a real change rather than a
synthetic one. Swapping `build-runner` off nginx produced
`IMAGE DIGEST CHANGED`, 8 new advisories and 22 resolved, exit 1 — and the
baseline was only regenerated after reading that diff.

### The build-runner was nginx, and the justification for it was false

`build-runner` ran nginx, and the comment in its manifest explained why:

> A CI system exposes an HTTP endpoint that accepts build requests, so this is
> not a web server bolted onto a CI runner for the sake of the lab.

That is not how CI systems work. Jenkins and GitLab Runner **agents** do not
accept build submissions over HTTP; the *controller* holds the API and the agent
dials out to collect work. The lab asserted a fact about CI architecture to
justify a stand-in, and the assertion was wrong, which made the stand-in
unnecessary as well as dishonest.

It now runs `docker:27-cli`, the standard CI agent base image, pinned to
`sha256:851f91d2…`. Verified by running things inside it rather than by reading
its documentation: `git 2.47.2` and `docker 27.5.1` are present, and the pod
genuinely clones and builds. Its advisory count fell from 30 to 16 at the same
time, and the lab total from 99 to 85.

**PP-01 is completely unaffected, and that is the more interesting result.** The
pod is hardened on every axis that is cheap — non-root UID 101, read-only root
filesystem, all capabilities dropped, default seccomp — and it is still a total
compromise of the cluster. The token is mounted into the pod by the kubelet
before the container's first instruction, so the container has no say in it. A
pod can be correctly hardened and still be fully owned, because the permission
that matters was granted to its *identity* rather than to its *container*.

**The listener stayed, but it is now labelled a fixture rather than an
architecture claim.** `test-boundaries.ps1` connects to `build-runner:8080` from
three zones and requires every attempt to fail. That assertion is worth nothing
if nothing is listening: a closed port refuses connections whether or not a
NetworkPolicy exists, so testing the policy against a silent pod returns green
while measuring nothing. The health endpoint exists so the policy has a real
port to block. It is served by busybox `nc` from inside the same image, nothing
is installed at boot — a container that installs things on start has contents
that differ from its digest, which defeats the pinning that makes the image
reviewable — and the manifest now says plainly that this is a measurement
fixture and not a claim about CI.

### Remaining stand-in, deliberately not changed here

`orders-api` is **still nginx**, serving static content. The manifest frames it
as a deliberately hardened web workload and that framing is defensible, so
changing it is a separate decision rather than something to fold into this
commit. It is recorded here so the Phase 7 risk graph does not present it as a
real API. The lab total of 85 advisories includes its 30.

### Two more things about the lab itself

- **The CNI is the second most vulnerable image in the lab.** 9 advisories,
  including the serious `musl` one. It runs with host networking and privileges
  that no application pod has, which is the usual shape of CNI risk and is worth
  being in the catalogue rather than assumed away.
- **`postgres-credentials` still carries `legacy_password`.** An unused key in a
  live Secret is a credential with no reader, no rotation, and no owner. It is
  not flagged as sprawl because nothing reads it, which is precisely why it is
  worth noticing.

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
- **PowerShell silently unrolls an empty array returned from a function.**
  `return @()` emits nothing, so the caller gets `$null`, not an empty array,
  and the first `.Count` on it throws under `Set-StrictMode`. The fix is a
  leading comma — `return , @()` — which undoes exactly one level of unrolling.
  Every array accessor in `tools/scan-drift.ps1` depends on this, and the same
  trap makes `@($null)` a one-element array, which printed an empty `accepted:`
  line for every finding that was not an accepted risk.
- **`Set-StrictMode` makes every optional Kubernetes property a landmine.** A
  `ClusterRoleBinding` has no `metadata.namespace` and most RBAC rules have no
  `resourceNames`; reading either directly aborts the scan on the first platform
  object it meets. All Kubernetes object access goes through a `Get-Prop`
  accessor for this reason.
- **`param([string] $a, [string] $b) {` on one line does not define a function
  body.** PowerShell parses the brace as a *scriptblock argument to `param`*, so
  the function returns its own source text. Every call site silently receives a
  `ScriptBlock` where a string was expected, every comparison against it fails,
  and a scanner reports zero of everything without a single error. The param
  block must end the line, with the body's opening brace implied. Found in
  `Get-ValueKind`; `grep -n 'param([^)]*)[[:space:]]*{'` now audits the whole
  tree for it.
- **The `, @()` array idiom is correct in exactly one of three positions.**
  With a direct assignment it stops an empty result unrolling to `$null`. Piped,
  it hands the next command the inner array as a single object, so
  `PSObject.Properties['id']` returns null and the match is discarded — this is
  how `scan-images.ps1` reported 29 real CVEs in the nginx image as "clean".
  Wrapped in `@()` at the call site, it produces a *nested* array, so a `foreach`
  iterates once holding an array and every property read returns null — this is
  how `scan-secrets.ps1` found 0 credentials while two Secrets sat in the
  cluster. The only form that is right in all three positions is a plain
  unrolled return plus `@()` at the call site, which is what both tools use now.
- **A detector's first clean bill of health is its least trustworthy output.**
  The image scanner reported all six workloads clean on its first successful
  run. It was wrong, by 29 advisories, and the only reason that was caught is
  that the result was distrusted and re-probed with a known-vulnerable version
  (`busybox@1.36.1-r5` → 6 CVEs, against the installed `1.37.0-r31` → 0).
  `querybatch` and `query` were then compared on both a vulnerable and a patched
  version and agree exactly, which is what makes the zero mean something.
- **A username is an identifier, not a secret.** The lab's database user is the
  word `orders`. Substring-matching it as a credential produced 21 findings, 13 of
  them CRITICAL claims that a live credential was committed — in the scanner's
  own source, in the manifest that creates the service account, in the HTML the
  lab serves. `Get-ValueKind` now classifies Secret keys as credential or
  identifier before anything is matched, and the minimum matchable length is 12
  characters. Every one of those 19 extra findings was noise; a scanner that
  accuses its own source of leaking a password gets switched off.
- **Never print a credential, and provide no switch to.** Findings report
  location, length, and a 16-hex prefix of the SHA-256, which is enough to
  correlate two copies of one password and useless to anyone who wants the
  password. Two copies of the same credential share a fingerprint, so "how far
  has this spread" is answerable without handling the value.
- **PowerShell resolves `$obj.prop` differently in a comparison than in a
  string.** `$now.image -ne $before` is correct against an `[ordered]@{}`
  entry, because the comparison operators resolve the key. But `"$now.image"`
  inside a double-quoted string stringifies the `OrderedDictionary` and appends
  the literal text `.image`, printing
  `now System.Collections.Specialized.OrderedDictionary.image`. The drift
  verdict was right and its explanation was nonsense, which is the worst
  combination a drift report can have: it announces that the pinned image moved
  without saying what it moved to. All such messages use `-f` formatting now.
- **A boundary test against a closed port measures nothing.** `test-boundaries.ps1`
  proves the build zone denies ingress by connecting to `build-runner:8080` from
  three zones and requiring failure. With nginx removed and nothing listening,
  those assertions would still pass — a closed port refuses connections whether
  or not a NetworkPolicy exists. This is why replacing the build-runner's image
  required keeping a real listener rather than treating one as an nginx
  leftover, and why the manifest calls that listener a fixture. A green test
  that cannot fail for the reason it claims to be testing is worse than no test.
- **`Set-Content -Encoding utf8` under Windows PowerShell 5.1 emits CRLF and a
  BOM.** The `mixed-line-ending` pre-commit hook then rewrites the file and fails
  the commit, so every regenerated baseline produced a spurious hook failure and
  a dirty diff. All three scanners share a `Write-JsonFile` helper that writes LF
  with no BOM and is verified byte-stable. The same CRLF hazard applies to shell
  scripts handed to busybox: a here-string written on Windows produces a script
  that dies with `syntax error: unexpected end of file (expecting "fi")`.

## Open decisions

- Dashboard visual direction: which design skill owns it.
- Repository name: `ZeroTrust-SOC-Lab` used so far, rename if preferred.
- Lab vulnerabilities: synthetic misconfigurations versus pinned real CVEs.
  Current answer, recorded in `attack/catalog/privilege-paths.md`: synthetic
  misconfigurations only, no fabricated CVEs in real pinned images.
- Branch protection and required checks on `main`.
- Audit policy level: raise to `RequestResponse` for a narrow resource set, or
  keep `Metadata` everywhere and accept losing request bodies.
