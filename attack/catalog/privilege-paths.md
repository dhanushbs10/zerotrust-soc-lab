# Privilege paths and planted weaknesses

Every entry below is a real, reachable condition in the running cluster. Nothing
here is aspirational or described-only: each one is asserted by a test in
`tools/test-boundaries.ps1` or demonstrated by an attack script, and the
assertion states the expected outcome so that a regression fails loudly.

The distinction between the two kinds of entry matters:

- **Privilege path** — an identity that holds more authority than its job
  requires. Exploitable by an attacker who obtains that identity.
- **Weakness** — a workload that is misconfigured. Exploitable by an attacker
  who reaches the workload, and often the thing that turns a foothold into a
  foothold *with privilege*.

The overlap is the point. `build-runner` is network-isolated, which is
irrelevant to the escalation it enables, and `web-frontend` runs as root, which
is irrelevant until something can reach its process.

---

## Inventory

| ID | Kind | Summary | ATT&CK | Verified by |
|----|------|---------|--------|-------------|
| PP-01 | Privilege path | `sa-build-runner` is bound to `cluster-admin` | T1078.001, T1098.003 | `test-boundaries.ps1` (4 `can-i` checks) |
| PP-02 | Privilege path | The sensor can open a TCP path to all three business workloads | T1078.001 | `test-boundaries.ps1` (3 network checks) |
| WP-01 | Weakness | `web-frontend` runs as root with no `securityContext` | T1610, T1611 | Phase 2 drift test |
| WP-02 | Weakness | `sa-telemetry-agent` holds a mounted token that grants nothing | T1550.001 | Phase 2 drift test |
| SP-01 | Weakness | The database password is duplicated in a readable ConfigMap | T1552.001 | Phase 3 scanner |

---

## PP-01 — `sa-build-runner` holds `cluster-admin`

**Resource** `ClusterRoleBinding/build-runner-cluster-admin`
→ `ClusterRole/cluster-admin`
**Techniques** T1078.001 Valid Accounts: Default Accounts · T1098.003 Account
Manipulation: Additional Cloud Roles

### Why it exists

This is the lab's headline weakness and the one worth understanding properly,
because the interesting part is what it is *not* protected by.

The build zone is genuinely isolated. `identities/34-networkpolicy-zones.yaml`
gives `build-runner` no ingress at all and egress to DNS only, and
`identities/31-...default-deny.yaml` denies everything else in the namespace.
An attacker inside the build runner cannot reach the database, the frontend, or
the API server over the network.

That containment is irrelevant here, and this is the lesson:

> **RBAC and network reach are independent axes.** Control-plane access is not
> pod-to-pod traffic. The attacker does not send a packet to `postgres`. They
> authenticate to the API server, ask it for the credential, and then open the
> one connection the network policy does permit.

The network policy stops nothing on this path. The compensating control that
should have existed — not granting a CI job control-plane admin — is the one
that is missing.

### What an attacker does with it

```
# 1. read the credential the pod should never have been able to read
kubectl get secret postgres-credentials -n zerotrust -o jsonpath='{.data.password}' | base64 -d

# 2. create a pod in the business zone; no policy stops this, because it is
#    not a pod-to-pod connection
kubectl run exfil --image=postgres -n zerotrust --restart=Never -- \
  env PGPASSWORD=<decoded> psql -h postgres -U orders -d acme -c '\dt'

# 3. or simply read every Secret in the cluster with `kubectl get secrets -A`
```

Step 3 needs no network path at all. That is what `cluster-admin` means.

### Detection

`DET-0001` — a ServiceAccount bound to a role granting `cluster-admin`, or any
`*` verb on `secrets`. Fires on the binding itself, so it fires before the
attack rather than during it.

---

## PP-02 — the sensor can reach every business workload

**Resource** `NetworkPolicy/{web-frontend,orders-api,postgres}-ingress`
→ rule admitting `sa-telemetry-agent` in the observe zone
**Technique** T1078.001 Valid Accounts: Default Accounts

### Why it exists

Evidence collection requires reach. A SOC that cannot probe the database cannot
tell "healthy" from "unreachable", and silently losing that distinction turns an
outage into an incident.

The sensor is granted exactly three ports, in three policies, scoped to the
single `telemetry-agent` pod by *both* a namespace selector and a pod selector.
A second pod dropped into `zerotrust-observe` does not inherit the path.

### Why it is survivable

The compensating control is that `sa-telemetry-agent` holds **no** Kubernetes
API permissions. It can open a TCP connection to 5432 and go no further,
because it has no database credential. That is the difference between seeing
that a door is open and walking through it.

This is also the one privilege path in the lab that is granted on purpose
rather than planted by mistake, and it is here because a monitor with no reach
is a monitor nobody can debug. The risk is real: an attacker who compromises the
sensor inherits observation of the whole business zone, and the sensor is by
construction the only pod allowed to touch all three.

The honest summary is that observation authority is a privilege, and this lab
carries it explicitly rather than pretending detection is free.

### What an attacker does with it

```
# from a compromised sensor pod: probe every business workload
kubectl exec -n zerotrust-observe <sensor-pod> -- nc -w 3 postgres.zerotrust.svc.cluster.local 5432
```

Useful for reconnaissance (which is T1046 Network Service Discovery) and as a
pivot to a service that admits nothing else. It is not sufficient to read the
database without also obtaining the credential.

### Detection

`DET-0008` — a NetworkPolicy granting ingress to a pod in the observe zone.
Fires on the rule, so it is a posture check rather than an attack signal, and
it is expected to fire exactly once in a correctly configured lab.

---

## WP-01 — `web-frontend` runs as root

**Resource** `Deployment/web-frontend`
**Techniques** T1610 Deploy Container · T1611 Escape to Host

### The condition

No `runAsNonRoot`, no `allowPrivilegeEscalation: false`, no dropped
capabilities, no read-only root filesystem. The container starts as uid 0. If an
attacker reaches the process they are root inside it before exploiting anything.

The fix is four lines. It is omitted so there is something real for a detection
to find. `workloads/10-frontend-and-api.yaml` contains the corrected version in
`orders-api`, immediately below, for direct comparison.

### Detection

`DET-0007` — a workload with no `securityContext.runAsNonRoot`, or with
`privileged: true`, or with an added capability beyond a small allowlist.

---

## WP-02 — the sensor mounts a token that grants nothing

**Resource** `ServiceAccount/sa-telemetry-agent`
**Technique** T1550.001 Use Alternate Authentication Material: Application
Access Token

### The condition

`automountServiceAccountToken: true` on an identity with no API permissions.

This started the other way around: the sensor was granted a read-only
ClusterRole over pods, ConfigMaps, RBAC and NetworkPolicies, and then discovered
the permissions could not be exercised — kube-router DNATs the API server
ClusterIP before the policy chain runs, so no NetworkPolicy written against
`10.96.0.1:443` can ever match. A permission that cannot be used is
indistinguishable from a missing one during an incident, and is a privilege path
besides.

So the RBAC was removed and the token stayed, deliberately. The token is the
sensor's identity: without it, every connection the sensor opens appears in the
audit log as an anonymous pod rather than as `sa-telemetry-agent`, and an
unattributable sensor is a sensor nobody can trust afterwards.

### Detection

`DET-0009` — a ServiceAccount with a mounted token and no RoleBinding. Cheap to
check, and it catches the common shape of this problem: a token left behind by
RBAC that was tightened later.

---

## SP-01 — the database password is duplicated in a ConfigMap

**Resource** `ConfigMap/app-config-leak`
**Technique** T1552.001 Unsecured Credentials: Credentials In Files

### The condition

The same password from `Secret/postgres-credentials`, in plaintext, in a
ConfigMap, annotated `zerotrust.lab/weakness: SP-01`.

ConfigMaps require `get configmaps`, which is far more commonly granted than
`get secrets`. Copying a password out of a Secret into a ConfigMap "so the
pipeline does not need secret access" is one of the ordinary ways credentials
leak, and it leaves no trace in any audit log.

The correct value is in a Secret, referenced by name in
`ConfigMap/orders-api-config` (`DB_PASSWORD_SECRET: postgres-credentials`), and
projected into the pod at runtime. The leak exists to be found.

### Detection

`DET-0002` — a credential-shaped string in a ConfigMap. Detection is by shape
(`://` with a password field, `password=`, `PASSWORD`, `TOKEN`, `SECRET`), not
by comparison against a known value, because a detector that knows the password
in order to find the password is not a detector.

---

## Paths deliberately not taken

Recorded so their absence reads as a decision rather than an oversight.

**No `hostPath` mounts, no `hostNetwork`, no privileged containers** in any
workload. A container escape is the highest-value target in a container lab and
the least interesting one to build, because the interesting question is what an
attacker can reach *without* escaping. WP-01 gives that question a real answer
without needing root on the node.

**No simulated CVEs.** Every weakness is a configuration error or an
authorization mistake, which is what a zero-trust lab is actually about. A
synthetic CVE in a pinned, real nginx image would be a fabrication wearing the
costume of a finding.

**No mesh.** Native NetworkPolicy only. A service mesh would add identity-aware
mTLS and change which control is load-bearing; then the lab would be measuring
the mesh rather than the platform.

**No `default` ServiceAccount usage.** All five workloads use a named
ServiceAccount, so the audit log attributes an action to an app rather than to
`system:serviceaccount:zerotrust:default`. Anything reaching the API server
through the anonymous identity becomes visible immediately, because there is
nothing else it could be.
