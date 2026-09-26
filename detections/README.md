# Detections

One directory per ATT&CK technique, holding the Sigma rules for it.

AGENTS.md rule 2: *every detection ships with a test that proves it fires. An
untested rule is not a detection.* `test-detections.py` is that test, and it is
the only thing in this directory that decides whether a rule counts.

## What is here

| Directory | Technique | Rule | Fires on |
|---|---|---|---|
| `T1021-remote-services/` | T1021 Remote Services | `det-0006` | a flow crossing a trust-zone boundary |
| `T1046-network-service-scanning/` | T1046 Network Service Scanning | `det-0005` | refused egress on one pod, counter comparable |
| `T1090.001-proxy-internal-proxy/` | T1090.001 Proxy: Internal Proxy | `det-0010` | a granted `pods/portforward` |
| `T1528-steal-application-access-token/` | T1528 Steal Application Access Token | `det-0011` | a TokenRequest from an off-baseline requester |
| `T1552.001-credentials-in-files/` | T1552.001 Credentials In Files | `det-0004` | business-zone pod logs read by an operator |
| `T1609.001-container-admin-command/` | T1609.001 Container Administration Command | `det-0003` | an exec that reads a credential or probes an escape |

## How a rule is proved

```
python detections/test-detections.py
```

Three things are checked.

**The rules are real Sigma.** Every rule is loaded by pySigma, the reference
implementation. That is the guarantee that the selection syntax, condition
grammar and modifiers mean what they say, and it comes from something other
than this lab's own code.

**Each rule fires, and fires only inside its own schema.** The hit count is an
*exact* equality, not a floor, and every hit's `schema` must equal the schema
the rule declares. Both halves are load-bearing:

- A floor (`>= 4`) is a gate that cannot fail. Replacing a rule's condition with
  one matching its whole schema *raises* the count and passes. That is how the
  first version of this harness shipped a green result for a suite that was not
  constraining anything.
- The schema guard is what stops a rule written for exec events from matching a
  flow event that happens to share a field name.

**The suite can fail.** Each rule is mutated three ways and the *same*
`verify_rule()` is re-run. A mutation counts as caught only when the gate itself
objects, because a harness that re-implements the check is testing its own copy.

## The three-way mutation verdict

| verdict | meaning | counts as |
|---|---|---|
| `caught` | the gate objected | pass |
| `equivalent` | the gate agreed *and* the hit set is byte-identical | reported, not failed |
| `SURVIVED` | behaviour changed and the gate did not notice | **failure** |

`equivalent` is a real finding rather than a pass. Five of the six rules report
one: dropping the `schema` guard changes nothing, because their other selections
are already specific enough that no other schema carries those fields. The guard
is defence in depth on those five and load-bearing on `det-0004`, where removing
it does let the rule match `kube-system` log reads.

## Why the rules key on the command, not the identity

All 978 exec sessions in this cluster were opened by `kubernetes-admin`, because
the lab is driven from the operator host. An identity-based rule would fire on
every one of them and mean nothing. So `det-0003` discriminates on *what was
run* — the projected token path, an inline `PGPASSWORD`, a `pg_authid` query,
`/proc/1/root`, `/etc/passwd` — which is also the more portable choice.

No rule carries a credential value. The leaked database password appears
verbatim in `.telemetry/`, and `det-0003` matches the shape `PGPASSWORD=`
rather than the secret, which is both what a real detector does and what
survives rotation.

## The one rule with no attack-step positive

`det-0006` (T1021) fires on 4 events, and **all 4 are the lab's own sensor**,
labelled `source.role = instrumentation`. That is structural, not an oversight:
the only cross-zone paths the lab grants are PP-02's three sensor grants, so no
other workload *can* produce a cross-zone flow. Adding a grant to give the rule a
positive would weaken the lab to prove a point — the trade PP-01's walk
explicitly declined when it refused to add a post-DNAT egress exception.

The rule is still proved: it fires, and it is silent on the 166
`cluster-internal` flows.

The instrumentation label is also a blind spot, and it is the interesting part.
`role` is a lab annotation, not a property of the traffic. A compromised sensor
produces byte-identical flows and would be suppressed by any rule filtering on
that field — and PP-02 makes that reachable, because the sensor is the only pod
permitted to touch all three business workloads. The exclusion is right for this
lab and wrong in the exact case that matters most.

## What is not here yet

The catalogue's posture findings — `DET-0001` (ServiceAccount bound to
`cluster-admin`), `DET-0002` (credential-shaped string in a ConfigMap),
`DET-0007` (`runAsNonRoot: false` / privileged / added capabilities),
`DET-0008` (NetworkPolicy admitting the observe zone) and `DET-0009` (mounted
token with no RoleBinding) — are configuration checks against live cluster
state, not rules over collected events. They are a different class with a
different input, and they are not written yet. The catalogue already names what
each one should assert, so the specification exists even though the
implementation does not.

## The engine

`engine/sigmalite.py` evaluates the rules; `engine/test_sigmalite.py` proves the
evaluator itself works, including four mutations that must be caught.

sigmalite is **not** a Sigma implementation and is not described as one. It
supports the constructs listed in its module docstring and **raises** on
anything else. A rule using an unimplemented construct is a test failure, never a
rule that quietly matches nothing — silence is the one outcome a detection tool
must never produce by accident.

Note one deliberate divergence: bare equality is **case-sensitive**. Sigma's
default is case-insensitive, and this lab has already been bitten by
case-insensitive comparison once, when the `policyTypes` enum and the
lower-case spec field were conflated in Phase 6. A rule that needs
case-insensitivity here must say `|contains`.
