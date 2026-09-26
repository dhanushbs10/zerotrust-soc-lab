# API server audit log

The audit log is this lab's primary evidence source. It is a complete,
append-only record of every request made to the Kubernetes API server.

## Why it matters

A compromised workload cannot delete audit records. That property is what makes
it usable for detection and for answering "what happened, in what order, and who
did it" after the fact.

## It is off by default

A freshly created cluster records nothing. A real cluster with audit logging
disabled is a breach waiting to happen: you would have no timeline, no evidence,
and no way to scope what was reached.

This lab enables it in `cluster/bootstrap/kind-config.yaml`. Getting that right
took three attempts and the failure modes are worth recording, because they are
easy to hit again:

| Attempt | Change | Result |
|---|---|---|
| 1 | `--audit-log-path` plus an `extraMounts` copy of the policy file | API server would not start |
| 2 | `--audit-log-path` only | API server started, logged **nothing**, no error |
| 3 | `preKubeadmCommands` in kubeadm `v1beta3` | Rejected: `unknown field` |
| 4 | `extraVolumes.hostPath` as an object | Rejected: `v1beta3` expects a plain string |
| 5 | `extraMounts` + `extraVolumes` + `--audit-policy-file` | Works |

Two traps in there are worth internalising:

**A file on the node is not a file in the container.** `extraMounts` copies the
policy onto the node, which is not sufficient. The API server is a static pod
that mounts only specific paths, so a file sitting in `/etc/kubernetes` on the
node is invisible to it. `extraVolumes` is what actually exposes the directory
to the container.

**There is no default audit policy.** Setting only `--audit-log-path` produces a
healthy API server that silently records nothing. An observability control that
fails open and silent is worse than one that is obviously broken.

## Reading it

```powershell
.\telemetry\audit\export-audit-log.ps1
.\telemetry\audit\export-audit-log.ps1 -SinceMinutes 10
```

Output lands in `.telemetry/audit-events.jsonl`, one normalized JSON object per
line. The raw log stays inside the control plane node at
`/var/log/kubernetes/audit/audit.log`.

To watch it live:

```powershell
docker exec soc-lab-control-plane tail -f /var/log/kubernetes/audit/audit.log
```

## Impersonation: the trap in `user.username`

Every record carries two identities:

- `authenticatedUser` — who actually presented a credential
- `impersonatedUser` — who that caller claimed to be

A caller running `kubectl --as=system:serviceaccount:zerotrust:default`
authenticates as `kubernetes-admin` and *impersonates* the service account. The
RBAC decision is made against the impersonated identity:

```json
{"verb":"list","authenticatedUser":"kubernetes-admin",
 "impersonatedUser":"system:serviceaccount:zerotrust:default",
 "effectiveIdentity":"system:serviceaccount:zerotrust:default",
 "decision":"forbid"}
```

A rule matching on `authenticatedUser` alone attributes this to the admin and
misses the escalation entirely. Detection rules must match `effectiveIdentity`.

## Record fields used by detections

| Field | Use |
|---|---|
| `effectiveIdentity` | Who RBAC actually decided on. Match on this. |
| `impersonated` | `true` when identity was assumed. Worth alerting on. |
| `verb` | `create`, `get`, `list`, `watch`, `patch`, `delete`, `exec` |
| `resource` / `subresource` | e.g. `secrets`, `pods/exec` |
| `decision` | `allow` or `forbid` |
| `sourceIP` | Correlates a request with a specific node or pod |
| `userAgent` | Distinguishes `kubectl`, `kubelet`, controllers |
| `timestamp` | Ordering. From `stageTimestamp`; `requestReceivedTime` is absent because the policy omits the `RequestReceived` stage. |

## Policy level

The lab uses `Metadata`: who, what, when, which object, and whether it was
allowed. Request bodies are deliberately **not** recorded, because bodies carry
credentials and writing them to disk creates a second, less protected secret
store.

A later phase raises the level to `RequestResponse` for a narrow set of
resources where the body is genuinely needed, such as `RoleBinding` creation.
That is the correct shape: detail where it earns its keep, metadata everywhere
else.
