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

| ID | Kind | Summary | ATT&CK | Walked by | Assertions |
|----|------|---------|--------|-----------|-----------|
| PP-01 | Privilege path | `sa-build-runner` is bound to `cluster-admin`, and the token leaves the zone it is sealed in | T1078.001, T1190, T1550.001 | `walk-pp-01-cluster-admin.ps1` | 10 |
| PP-02 | Compensating control | The sensor can open a TCP path to all three business workloads and holds no credential for any of them | T1046, T1550.001 | `walk-pp-02-sensor-reach.ps1` | 7 |
| PP-03 | Privilege path | A token for the `cluster-admin` ServiceAccount can be minted by impersonating it — same authority as PP-01, no file read | T1528 | `walk-pp-03-token-mint.ps1` | 7 |
| PP-04 | Privilege path | `pods/portforward` relays through the API server, so NetworkPolicy does not constrain it | T1090.001 | `walk-pp-04-portforward.ps1` | 5 |
| WP-01 | Weakness | `web-frontend` explicitly sets `runAsNonRoot: false` and has no container-level `securityContext` | T1610, T1611 | `walk-wp-01-frontend-root.ps1` | 9 |
| WP-02 | Weakness | `sa-telemetry-agent` mounts a token that carries no permission on any cluster resource | T1550.001 | `walk-wp-02-sensor-token.ps1` | 5 |
| SP-01 | Weakness | The database password is duplicated in a ConfigMap, and it is a live superuser credential | T1552.001 | `walk-sp-01-configmap-leak.ps1` | 11 |

Run them all with `attack\run-all.ps1`. It exits non-zero if any path's
assertions stop holding, and it cross-checks this table against the walk scripts
so an entry cannot be quietly deleted from one place and left in the other.

### What the walks changed about these entries

Every summary above was revised after being measured, and three of the five were
wrong in the direction of overstating the risk. That is recorded here rather than
silently corrected, because a catalogue that only ever gets edited to look more
alarming is not a catalogue.

- **PP-01** claimed the attacker operates from inside the build pod. They cannot.
  The build zone cannot reach the API server at all, so the walk reads the token
  in-pod and spends it from outside. See the correction below.
- **PP-02** was catalogued as T1078.001. It is not an account at all; it is
  reconnaissance, T1046, plus the token half it shares with WP-02.
- **WP-01** claimed "no `securityContext`". The pod sets one, and it sets
  `runAsNonRoot: false`. An opt-out is a stronger finding than an omission.
- **WP-02** claimed the token "grants nothing". It grants
  `system:basic-user` and the public discovery URLs, which every authenticated
  identity inherits. The posture is right; the phrasing was not.
- **SP-01** claimed an unprivileged workload could read the leak. None can. The
  finding is weaker than catalogued and different in kind.
- **PP-03** was first written against `sa-orders-api` and asserted the mint
  succeeded. It is refused. Impersonation cannot raise authority, because RBAC is
  judged as the impersonated identity. The escalation is the mirror image and
  needed the `cluster-admin` ServiceAccount to be the target. See the correction
  below.
- **PP-04** was not in this catalogue at all until Phase 7, because nothing in the
  lab had used `pods/portforward`. Phase 6's reachability graph reported 19 of 25
  modelled pairs as dropped and could not see this path; the gap is the relay, not
  the policy.

---

## PP-01 — `sa-build-runner` holds `cluster-admin`

**Resource** `ClusterRoleBinding/build-runner-cluster-admin`
→ `ClusterRole/cluster-admin`
**Techniques** T1078.001 Valid Accounts: Default Accounts · T1190 Exploit
Public-Facing Application · T1550.001 Use Alternate Authentication Material:
Application Access Token
**Walked by** `attack/walk-pp-01-cluster-admin.ps1` — 10 assertions

> **Corrected by measurement.** This entry previously claimed that control-plane
> access is simply "not pod-to-pod traffic", and demonstrated it by having the
> attacker sit inside the build runner and use its token. That demonstration does
> not work, and finding out why changed the lesson.

### Why it exists

This is the lab's headline weakness and the one worth understanding properly,
because the interesting part is what it is *not* protected by.

The build zone is genuinely isolated. `identities/34-networkpolicy-zones.yaml`
gives `build-runner` no ingress at all and egress to DNS only, and
`identities/31-...default-deny.yaml` denies everything else in the namespace.
The container itself is hardened too: uid 101, read-only root filesystem,
all capabilities dropped, default seccomp profile. It is a real CI agent, running
`git` and `docker`, not a web server pretending to be one.

### What the walk found, and why it matters more

Measured from inside the pod:

```
kubernetes.default.svc  -> resolves to 10.96.0.1
nc -z kubernetes.default.svc 443   -> BLOCKED
nc -z postgres.zerotrust.svc 5432 -> BLOCKED
```

The build runner cannot reach the API server. So the attacker cannot sit in the
build zone and exercise `cluster-admin` from there, and the walk does not pretend
otherwise: it reads the projected token off the filesystem, carries it out, and
spends it from the operator host.

The lesson that replaces the old one is sharper:

> **A NetworkPolicy constrains a workload. A copied credential is no longer a
> workload.**

The isolation was real, it was measured, and it did nothing — because the thing
that made PP-01 dangerous was never traffic. The pod's identity was over-granted,
and identity travels with the token no matter how well the network around the pod
is sealed. No egress allow was added to make the demo work; a fragile
post-DNAT exception would have taught the wrong lesson and weakened the lab to
prove a point.

Worth stating alongside it: **no pod in this cluster can reach the API server.**
All four workload identities are blocked from 443. Every service account token
here is latent, and the network policies are carrying the entire containment
while RBAC does none of the work. "Default-deny plus narrow RBAC" reads like two
independent controls; in this cluster only one of them is load-bearing.

### What an attacker does with it

```
# 1. read the credential the pod should never have been able to read
kubectl get secret postgres-credentials -n zerotrust -o jsonpath='{.data.password}' | base64 -d

# 2. or read it from the ConfigMap instead, which needs no base64 decode
kubectl get configmap app-config-leak -n zerotrust -o jsonpath='{.data.DB_PASSWORD}'

# 3. create a pod in the business zone; no policy stops this, because it is
#    not a pod-to-pod connection
kubectl run exfil --image=postgres -n zerotrust --restart=Never -- \
  env PGPASSWORD=<decoded> psql -h postgres -U orders -d acme -c '\dt'
```

Step 3 needs no network path from the build zone at all. The pod it creates is
a *new* workload in a *new* place, and the policy that sealed the runner has
nothing to say about it. That is what `cluster-admin` means.

### Detection

`DET-0001` — a ServiceAccount bound to a role granting `cluster-admin`, or any
`*` verb on `secrets`. Fires on the binding itself, so it fires before the
attack rather than during it.

---

## PP-02 — the sensor can reach every business workload

**Resource** `NetworkPolicy/{web-frontend,orders-api,postgres}-ingress`
→ rule admitting `sa-telemetry-agent` in the observe zone
**Techniques** T1046 Network Service Scanning · T1550.001 Application Access Token
**Walked by** `attack/walk-pp-02-sensor-reach.ps1` — 7 assertions

> **Corrected by measurement.** Catalogued as T1078.001, which is a valid account
> technique. It is not an account: this is reconnaissance plus reach, and the
> walk measures it as such.

### Why it exists

Evidence collection requires reach. A SOC that cannot probe the database cannot
tell "healthy" from "unreachable", and silently losing that distinction turns an
outage into an incident.

The sensor is granted exactly three ports, in three policies, scoped to the
single `telemetry-agent` pod by *both* a namespace selector and a pod selector.
A second pod dropped into `zerotrust-observe` does not inherit the path.

### Why it is survivable

Reachability is not access, and the walk asserts both halves rather than only
the flattering one.

Measured: all three business workloads are `REACHABLE` from the sensor, and the
API server is `BLOCKED`. The sensor's full environment was read — every variable
is a service-discovery entry, `PATH`, `HOME`, `HOSTNAME` or
`PROBE_INTERVAL_SECONDS`, and the count of `PG*` / `DATABASE*` / `DB_*` variables
is **0**. Its service account token cannot list Secrets, cannot list pods, and
cannot create a pod.

So the sensor can see three open doors and holds no key to any of them. The
compensating control is the *combination*: the reach is bounded to three ports on
one named pod, and the authority is empty.

This is also the one grant in the lab made on purpose rather than planted by
mistake, and it is here because a monitor with no reach is a monitor nobody can
debug. The risk is real: an attacker who compromises the sensor inherits
observation of the whole business zone, and the sensor is by construction the only
pod allowed to touch all three.

The honest summary is that observation authority is a privilege, and this lab
carries it explicitly rather than pretending detection is free.

### What an attacker does with it

```
# from a compromised sensor pod: probe every business workload
kubectl exec -n zerotrust-observe <sensor-pod> -- nc -w 3 postgres.zerotrust.svc.cluster.local 5432
```

Useful for reconnaissance (T1046) and as a pivot to a service that admits nothing
else. It is not sufficient to read the database without also obtaining the
credential — and the sensor cannot obtain it, because the ConfigMap carrying it
is unreadable to this identity and the API server is blocked.

The chain that *does* work is PP-01 plus PP-02: steal a cluster-admin token from
the CI runner, read the password, then act from a pod that already sits inside the
permitted path. That chain is assembled in Phase 8 out of two separately
catalogued findings rather than a third planted weakness.

### Detection

`DET-0008` — a NetworkPolicy granting ingress to a pod in the observe zone.
Fires on the rule, so it is a posture check rather than an attack signal, and
it is expected to fire exactly once in a correctly configured lab.

---

## PP-03 — a token can be minted for the `cluster-admin` ServiceAccount

**Resource** `ClusterRoleBinding/build-runner-cluster-admin` → `ClusterRole/cluster-admin`
**Technique** T1528 Steal Application Access Token
**Walked by** `attack/walk-pp-03-token-mint.ps1` — 7 assertions

> **Corrected by measurement.** The first version of this walk impersonated
> `sa-orders-api` and asserted the mint succeeded. It is refused:
>
> ```
> error: failed to create token: serviceaccounts "sa-orders-api" is forbidden:
>   User "system:serviceaccount:zerotrust:sa-orders-api" cannot create resource
>   "serviceaccounts/token" in API group "" in the namespace "zerotrust"
> ```
>
> Impersonation does not launder privilege. RBAC is evaluated as the
> *impersonated* identity, so `--as` can only reduce authority. A walk asserting
> the opposite would have been demonstrating a vulnerability this cluster does
> not have — the same error SP-01's walk made before it was corrected.

### Why it exists

The escalation is the mirror image of the refusal. `sa-build-runner` holds
`cluster-admin`, so asking *as* that identity is permitted, and the token that
comes back names it:

```
minted sub = system:serviceaccount:zerotrust-build:sa-build-runner
audience   = https://kubernetes.default.svc.cluster.local
exp        = 1790450420        (bounded; this is the mitigation)
```

Measured authority of the minted credential, with the identical question asked of
the low-privilege identity for contrast:

| check | minted `sa-build-runner` token | `sa-orders-api` |
|-------|--------------------------------|-----------------|
| `list secrets --all-namespaces` | **yes** | no |
| `list pods --all-namespaces` | **yes** | no |
| `get configmap/app-config-leak -n zerotrust` | **yes** | no |
| `create pods -n zerotrust` | **yes** | no |

Both rows are necessary. The grants alone would prove nothing, because the caller
was already `cluster-admin`; the refusals alone would prove nothing, because
nothing was attempted. What makes it a privilege path is that the *only* variable
between the two columns is which ServiceAccount was impersonated.

### How it differs from PP-01

Same blast radius, no filesystem access:

| | PP-01 | PP-03 |
|---|---|---|
| how the credential is obtained | read off the pod | minted from nothing |
| evidence left on the pod | a file access | none |
| requires reaching the pod | yes | no |
| expires | no, it is the mounted token | yes, TokenRequest lifetime |

PP-03 is the worse of the two to detect, and that is the reason it is catalogued
separately. A file read leaves traces a rule can key on; a TokenRequest is an
ordinary API call that succeeds.

### Detection

`DET-0011` — a `TokenRequest` whose requester is neither the kubelet that owns
the pod nor a control-plane component. In this cluster 208 of 209 token requests
are one of those two, so the single exception is the signal. A rule that did not
require `requesterClass` in `(other, impersonated)` would fire on all 209 and
mean nothing — which is the mistake the Phase 5 registry was built to prevent.

---

## PP-04 — `pods/portforward` reaches ports NetworkPolicy denies

**Resource** `NetworkPolicy/*` (all of them) vs `pods/portforward`
**Technique** T1090.001 Proxy: Internal Proxy
**Walked by** `attack/walk-pp-04-portforward.ps1` — 5 assertions

> **Not in this catalogue until Phase 7**, because nothing in the lab had used
> `port-forward`. Phase 6 verified 19 of 25 modelled pairs as dropped by the
> policy chain. This is the boundary of that verification.

### Why it exists

`kubectl port-forward` does not open a connection from the client to the pod. The
API server opens a connection *from the kubelet into the pod's network namespace*
and relays bytes over an existing stream. The traffic that reaches `postgres`
never traverses the pod-to-pod path kube-router governs, so no policy written
against that path can match it.

Measured in one run, from the same pod, to the same port:

```
build-runner -> postgres.zerotrust.svc.cluster.local:5432   control resolved, no connection
port-forward -> postgres:5432 (via 127.0.0.1:15432)        connected
```

The DNS resolution in the first line is a positive control and is not decoration.
Every verdict in that step is inferred from the *absence* of a postgres banner,
and absence of output is also what a broken resolver produces. Without the
control, the walk would report a policy bypass that is really a DNS failure.

### The honest framing

The control is not weak. It is comprehensive, it is enforced, and it does not
apply here. That is a different claim from "the policy is misconfigured", and it
calls for a different fix: this is a gap in what NetworkPolicy is *able* to
express, not a gap in what it was configured to do. A SOC that reasons purely
from a reachability graph — as Phase 6's does — will report this path as closed.

### Detection

`DET-0010` — `verb=get, subresource=portforward` in the audit log. It arrives as
its own subresource and is easy to mistake for an exec session; the collector
keeps both in one schema and routes them to different techniques, so a
T1609.001 rule that does not exclude `portforward` will report a tunnel as a
container exec, and in a cluster where tunnels are rare that misattribution is
invisible.

---

## WP-01 — `web-frontend` runs as root

**Resource** `Deployment/web-frontend`
**Techniques** T1610 Deploy Container · T1611 Escape to Host
**Walked by** `attack/walk-wp-01-frontend-root.ps1` — 9 assertions

> **Corrected by measurement.** This entry said "no `securityContext`". The pod
> has one. It sets `runAsNonRoot: false`, which is a decision rather than an
> oversight, and it is a worse finding than the one that was written down.

### The condition

Measured from the running pod:

```
pod-level securityContext       : {"runAsNonRoot": false}
container-level securityContext : absent entirely
id -u                           : 0
```

So: an explicit opt-out of non-root, and on top of that no
`allowPrivilegeEscalation: false`, no `readOnlyRootFilesystem`, no
`capabilities.drop`, and no `seccompProfile`. `orders-api`, immediately below it
in `workloads/10-frontend-and-api.yaml`, sets all five on the **same image
digest** — which is what makes this a controlled comparison rather than an
opinion.

### What uid 0 is actually worth here, measured

"It runs as root" is a claim every scanner makes. The walk puts a number on it by
asking both pods the same question with `test -w`, which queries the kernel and
changes nothing:

```
web-frontend (uid 0,  no securityContext) : document-root-WRITABLE
orders-api   (uid 101, readOnly rootfs)   : document-root-readonly
```

Identical image, identical filesystem layout, opposite capability. The only
variable is the `securityContext`.

That matters because `web-frontend` serves content to users. A root process in
that container can rewrite what is served, so compromising this pod is
compromising whatever the user is looking at at that moment. The walk also
confirms the process can rewrite its own `/etc/passwd` and can address `/proc/1/root`
— the preconditions for persistence inside the container and for an escape
attempt respectively. Neither the rewrite nor the escape is performed; both are
printed under "withheld" with the exact command.

The fix is four lines. It is omitted so there is something real for a detection
to find.

### Detection

`DET-0007` — a workload with no `securityContext.runAsNonRoot`, or with
`runAsNonRoot: false`, or with `privileged: true`, or with an added capability
beyond a small allowlist. The `runAsNonRoot: false` case is in the rule on
purpose: an explicit `false` is a decision someone made, and a scanner that only
looks for a missing key will not see it.

---

## WP-02 — the sensor mounts a token with no authority behind it

**Resource** `ServiceAccount/sa-telemetry-agent`
**Technique** T1550.001 Use Alternate Authentication Material: Application
Access Token
**Walked by** `attack/walk-wp-02-sensor-token.ps1` — 5 assertions

> **Corrected by measurement.** This entry said the token "grants nothing". It
> does not. It grants `system:basic-user` and the public discovery URLs, because
> every authenticated identity in every Kubernetes cluster inherits those. The
> posture is correct and the phrasing was not.

### The condition

`automountServiceAccountToken: true` on an identity with no permission on any
cluster resource.

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

### What the walk measures, precisely

Asked of the API server rather than read out of a manifest, because a manifest
can be out of step with what is actually bound:

```
SelfSubjectRulesReview: 24 entries
  resource-scoped, self-review only : 3   (system:basic-user)
  non-resource, public discovery    : 20  (system:discovery, system:public-info-viewer)
  anything else                     : 0
```

and four explicit denials — `list secrets`, `list pods`, `create pods`,
`get configmaps` — all refused.

The three self-review creates let an identity ask the API server what it may do.
That is a read of its own permissions, not access to anything, and it is granted
to `system:authenticated`. This is the finding stated honestly rather than
dramatically: **the token carries no permission on any cluster resource, only
what every identity already has.**

### The real point: PP-01 and WP-02 are the same pod setting

```
pod spec          automount   identity                        grants on cluster resources
telemetry-agent   True        sa-telemetry-agent (observe)    none beyond the baseline
build-runner      True        sa-build-runner (build)         cluster-admin, everything
```

Identical pod spec, opposite blast radius, and the only difference is a
`ClusterRoleBinding` that no pod manifest mentions. Neither can be judged by
reading a workload file, which is why both are walked.

A latent token is still a credential: a token worth nothing today becomes
worth something the moment a `RoleBinding` is added, with no change to the pod,
no restart, and nothing in the spec to review. The correct long-term answer is
`automountServiceAccountToken: false`, which is a redesign rather than a tweak —
a reachability sensor that cannot reach the API server cannot report what it
finds.

### Detection

`DET-0009` — a ServiceAccount with a mounted token and no RoleBinding. Cheap to
check, and it catches the common shape of this problem: a token left behind by
RBAC that was tightened later.

---

## SP-01 — the database password is duplicated in a ConfigMap

**Resource** `ConfigMap/app-config-leak`
**Technique** T1552.001 Unsecured Credentials: Credentials In Files
**Walked by** `attack/walk-sp-01-configmap-leak.ps1` — 11 assertions

> **Corrected by measurement, twice.** The original entry said an attacker with
> a foothold could read the leak. None of the lab's workload identities can. The
> finding is weaker than catalogued, and it is about something other than what it
> was assumed to be about.

### The condition

The same password from `Secret/postgres-credentials`, in plaintext, in a
ConfigMap, annotated `zerotrust.lab/weakness: SP-01` — and a second time,
embedded verbatim inside `DATABASE_URL`. Both copies fingerprint to
`A069F0C1482A91C8` under the same algorithm `tools/scan-secrets.ps1` uses, so the
walk and the scanner agree on which copy is which.

ConfigMaps require `get configmaps`, which is far more commonly granted than
`get secrets`. Copying a password out of a Secret into a ConfigMap "so the
pipeline does not need secret access" is one of the ordinary ways credentials
leak, and it leaves no trace in any audit log.

The correct value is in a Secret, referenced by name in
`ConfigMap/orders-api-config` (`DB_PASSWORD_SECRET: postgres-credentials`), and
projected into the pod at runtime. The leak exists to be found.

### Who can actually read it

Measured with `auth can-i`, one call per identity:

| identity | verdict |
|----------|---------|
| `sa-web-frontend` | no |
| `sa-orders-api` | no |
| `sa-telemetry-agent` | no |
| `sa-build-runner` | **yes** |

`sa-orders-api` *can* read ConfigMaps in `zerotrust`, but its Role is narrowed
with `resourceNames: [orders-api-config]`, so the leak falls outside the grant.
That is a real control working as designed.

The only identity that can read the leak is the one that already owns the entire
cluster via PP-01. **So this is not privilege escalation**, and a walk that
demonstrated it would have been demonstrating a vulnerability the lab does not
have.

### The part that does hold: it is a live superuser credential

Reachability is not the finding. The finding is that this specific visible string
is a current, valid, superuser password, proven rather than assumed.

The obvious test is worthless, and fails in the most dangerous way available:

```
psql -h 127.0.0.1 ...                 no password   -> succeeds
PGPASSWORD=wrong psql -h 127.0.0.1 ...              -> succeeds
```

Both succeed, because `pg_hba.conf` rule 2 trusts `127.0.0.1`. A walk written
that way would have "proved" the leaked password works while actually proving the
database ignores passwords entirely. The walk asserts this inadequacy explicitly
before relying on anything downstream.

The real test uses the pod's routable address, where rule 7 applies
`scram-sha-256` — one route, one query, three passwords:

```
10.244.1.7:5432   no password     -> refused
                   wrong password  -> FATAL: password authentication failed for user "orders"
                   leaked password -> orders
```

Two failures and one success is what makes the success mean something. And the
role it authenticates as is not a scoped reporting account:

```
rolname | rolsuper | rolcreatedb | rolcreaterole
orders  | t        | t           | t
```

The name says `orders`; the privilege says superuser.

### Why the real risk is rotation, not theft

Three things follow, and none of them is "an unprivileged workload steals the
database password":

1. **PP-01 gets a second, quieter route to the same secret.** ConfigMap data
   needs no base64 decode, so it is a smaller and less obviously security-relevant
   step than `get secrets`.
2. **Two copies means two things to rotate.** Rotating `postgres-credentials`
   does not touch this ConfigMap. An operator who rotates the Secret and considers
   the job done has left the previous password in the cluster in clear text.
3. **A stale copy is undetectable by eye.** Only a fingerprint comparison tells a
   rotated credential from a live one, which is why the walk compares
   fingerprints and never prints the values.

The rotation trap is argued here from the mechanism — a copy that nothing rotates
is a copy that outlives the rotation meant to revoke it. Demonstrating it by
actually rotating and re-testing is Phase 8 work, where a rotation can be done and
undone deliberately.

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
