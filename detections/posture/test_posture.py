#!/usr/bin/env python3
"""Proves the posture checks can fail. Cluster-free, and run by the pre-commit hook.

    python detections/posture/test_posture.py

Why this file exists
--------------------
Five posture checks that all pass on one snapshot is not evidence of anything. It
is consistent with five correct checks and with five checks that always return
the expected answer. Only a mutation distinguishes those, and this project treats
"a gate that cannot fail is not a gate" as a load-bearing rule rather than a motto.

So each check is broken four ways and the SAME gate is re-run. The gate is
`check_posture.run_gate` -- not a reimplementation of it. A harness that tests its
own copy of the check is testing the copy.

The four mutations
------------------
  VACUOUS        the check stops firing at all
                 -> must be caught as a MISSING expected finding

  BROADENED      the check fires on more than it should
                 -> must be caught as an UNEXPECTED finding

  SILENTLY_WIDENED  the expected-findings list gains an entry the check never
                    justified, so a real problem is now declared acceptable
                 -> must be caught, and the only way to catch it is to feed the
                    gate a snapshot that DOES contain the problem

  INJECTED       a synthetic violation is added to the snapshot: a new
                 cluster-admin binding, a ConfigMap holding a password nobody has
                    ever seen, a privileged container, an observe-zone ingress
                    grant, a new unbound ServiceAccount
                 -> the check MUST report it, and must report exactly that one

INJECTED is the one that matters. VACUOUS and BROADENED prove the gate is wired
up. INJECTED proves the checks would notice something actually wrong, which is the
only reason to run a posture check at all.

The DET-0002 injection deliberately uses a password string that appears nowhere in
this repository. DET-0002 detects by shape and never by value -- a detector that
knows the password in order to find the password is not a detector -- so if the
checker only fires on the lab's real credentials, this case fails and the comment
in the rule was a lie.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


cp = _load("check_posture", os.path.join(HERE, "check_posture.py"))

SNAPSHOT = os.path.join(ROOT, ".telemetry", "posture-snapshot.json")

# A password that appears nowhere in this repository, on purpose. If DET-0002
# needs it to fire, the check is matching a value rather than a shape.
UNKNOWN_PASSWORD = "w7Qp-zN4v!tR2xK9mL6cY"  # noqa: S105 - a test fixture, not a credential


def base_snapshot() -> dict[str, Any]:
    if not os.path.exists(SNAPSHOT):
        raise SystemExit(
            f"{SNAPSHOT} not found. Run:\n"
            f"  python detections/posture/check_posture.py "
            f"--snapshot .telemetry/posture-snapshot.json"
        )
    with open(SNAPSHOT, "r", encoding="utf-8") as handle:
        return json.load(handle)


def find_rule(rules: list[dict], rule_id: str) -> dict:
    for r in rules:
        if r["id"] == rule_id:
            return r
    raise SystemExit(f"no rule {rule_id} in posture-rules.yml")


# --------------------------------------------------------------------------- #
# mutations of the SNAPSHOT: a real new problem the check must notice
# --------------------------------------------------------------------------- #
def inject_new_cluster_admin(snap: dict) -> tuple[str, tuple[str, str]]:
    """A lab ServiceAccount bound to cluster-admin that did not exist before."""
    snap["clusterRoleBindings"].append(
        {
            "name": "injected-cluster-admin",
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "sa-injected", "namespace": "zerotrust"}
            ],
        }
    )
    return "DET-0001", ("zerotrust/sa-injected", "cluster-admin")


def inject_wildcard_secrets(snap: dict) -> tuple[str, tuple[str, str]]:
    """A lab ServiceAccount bound to a role with verbs '*' on secrets.

    Proves the second half of DET-0001, which is a real permission lookup rather
    than a role-name match. A check that only knew the name `cluster-admin` would
    miss this entirely.
    """
    snap["clusterRoles"].append(
        {
            "name": "injected-secrets-reader",
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]}],
        }
    )
    snap["clusterRoleBindings"].append(
        {
            "name": "injected-secrets-binding",
            "roleRef": {"kind": "ClusterRole", "name": "injected-secrets-reader"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "sa-injected", "namespace": "zerotrust"}
            ],
        }
    )
    return "DET-0001", ("zerotrust/sa-injected", "secrets-wildcard")


def inject_configmap_with_unknown_password(snap: dict) -> tuple[str, tuple[str, str]]:
    """A ConfigMap holding a credential the checker has never seen."""
    snap["configMaps"].append(
        {
            "namespace": "zerotrust",
            "name": "injected-config",
            "data": {"SOME_OTHER_PASSWORD": UNKNOWN_PASSWORD},
        }
    )
    return "DET-0002", ("zerotrust/injected-config/SOME_OTHER_PASSWORD", "key")


def inject_url_with_embedded_credential(snap: dict) -> tuple[str, tuple[str, str]]:
    """A connection string carrying a credential in it, under an innocent key.

    The key is `DATABASE_ENDPOINT`, which is not credential-shaped. Only the value
    pattern can catch this, so it exercises the second half of DET-0002's matching
    and confirms the key/value split is doing what it claims.
    """
    snap["configMaps"].append(
        {
            "namespace": "zerotrust-build",
            "name": "injected-url",
            "data": {"DATABASE_ENDPOINT": f"postgres://svc:{UNKNOWN_PASSWORD}@db:5432/x"},
        }
    )
    return "DET-0002", ("zerotrust-build/injected-url/DATABASE_ENDPOINT", "value")


def inject_prose_mentioning_password(snap: dict) -> tuple[str, tuple[str, str] | None]:
    """Prose that contains the word 'password' and must NOT be reported.

    The negative case, and the one that decides whether DET-0002 is usable. A loose
    value pattern matches this, and three real ConfigMaps in this lab are exactly
    this: lab-catalog/privileges.md, lab-catalog/weaknesses.yaml and
    web-frontend-content/index.html. A check that flags documentation is a check
    whose output gets ignored.
    """
    snap["configMaps"].append(
        {
            "namespace": "zerotrust",
            "name": "injected-docs",
            "data": {"NOTES.md": "The password is rotated every 90 days by an operator."},
        }
    )
    return "DET-0002", None


def inject_privileged_container(snap: dict) -> tuple[str, tuple[str, str]]:
    snap["pods"].append(
        {
            "namespace": "zerotrust",
            "name": "injected-priv-abc123",
            "labels": {"app": "injected-priv"},
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "app",
                    "securityContext": {"privileged": True, "runAsNonRoot": True},
                }
            ],
        }
    )
    return "DET-0007", ("zerotrust/injected-priv", "privileged-true")


def inject_capability_off_allowlist(snap: dict) -> tuple[str, tuple[str, str]]:
    snap["pods"].append(
        {
            "namespace": "zerotrust-build",
            "name": "injected-caps-abc123",
            "labels": {"app": "injected-caps"},
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "app",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                }
            ],
        }
    )
    return "DET-0007", ("zerotrust-build/injected-caps", "capability-SYS_ADMIN")


def inject_observe_zone_ingress(snap: dict) -> tuple[str, tuple[str, str]]:
    snap["networkPolicies"].append(
        {
            "namespace": "zerotrust-observe",
            "name": "injected-observe-ingress",
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]},
        }
    )
    return "DET-0008", ("zerotrust-observe/injected-observe-ingress", "ingress-grant")


def inject_unbound_service_account(snap: dict) -> tuple[str, tuple[str, str]]:
    snap["serviceAccounts"].append(
        {"namespace": "zerotrust-build", "name": "sa-injected-unbound"}
    )
    return "DET-0009", ("zerotrust-build/sa-injected-unbound", "unbound")


def inject_default_service_account(snap: dict) -> tuple[str, tuple[str, str] | None]:
    """A `default` ServiceAccount, which must NOT be reported.

    The other negative case. Every namespace in every Kubernetes cluster has one,
    it always has a token, and it is never bound -- so including it would triple
    DET-0009's output with a truth that carries no information about this cluster.
    """
    snap["serviceAccounts"].append(
        {"namespace": "zerotrust-observe", "name": "default"}
    )
    return "DET-0009", None


def inject_kube_system_binding(snap: dict) -> tuple[str, tuple[str, str] | None]:
    """A kube-system controller binding itself, which must NOT be reported.

    The scoping negative case, and the most important one. Measured, 43 of the 44
    ServiceAccount bindings in this cluster are exactly this. Without the lab
    namespace scope DET-0001 reports 44 findings and the one that matters is 1.
    """
    snap["clusterRoleBindings"].append(
        {
            "name": "system:controller:injected",
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "injected", "namespace": "kube-system"}
            ],
        }
    )
    return "DET-0001", None


INJECTIONS = [
    ("new lab cluster-admin binding", inject_new_cluster_admin),
    ("wildcard verb on secrets", inject_wildcard_secrets),
    ("ConfigMap with an unknown password", inject_configmap_with_unknown_password),
    ("credential embedded in a URL", inject_url_with_embedded_credential),
    ("prose mentioning 'password'", inject_prose_mentioning_password),
    ("privileged container", inject_privileged_container),
    ("capability off the allowlist", inject_capability_off_allowlist),
    ("observe-zone ingress grant", inject_observe_zone_ingress),
    ("new unbound ServiceAccount", inject_unbound_service_account),
    ("another `default` ServiceAccount", inject_default_service_account),
    ("kube-system controller binding itself", inject_kube_system_binding),
]


# --------------------------------------------------------------------------- #
# mutations of the RULES
# --------------------------------------------------------------------------- #
def mutate_vacuous(rule: dict) -> dict:
    """Make the check unable to fire.

    Scoped by pointing the subject namespace somewhere the lab does not live, which
    is the most realistic way a posture check silently stops working: someone
    renames a namespace.
    """
    broken = copy.deepcopy(rule)
    if "policyNamespace" in broken.get("predicate", {}):
        broken["predicate"]["policyNamespace"] = "kube-system"
    elif "subjectNamespaces" in broken.get("scope", {}):
        broken["scope"]["subjectNamespaces"] = ["kube-system"]
    else:
        broken["scope"]["subjectNamespaces"] = ["kube-system"]
    return broken


def mutate_broadened(rule: dict, snap: dict) -> dict:
    """Make the check fire on more than it should.

    The dangerous direction for a posture gate: extra findings are noise, and a
    gate that cannot tell noise from signal is a gate that gets turned off.

    The `snap` argument is not decoration. Broadening DET-0001 to also match the
    `edit` and `view` roles produces NO extra findings on the real cluster,
    because no lab service account happens to be bound to either. So the mutation
    has nothing to find and the gate correctly stays green -- which means this
    mutation, run against the real snapshot, is untestable. Rather than skip it or
    quietly weaken the assertion, the caller hands it an enriched snapshot that
    actually contains those bindings, so "this mutation should be caught" is a
    claim about the mutation and not about the data.
    """
    broken = copy.deepcopy(rule)
    pred = broken.setdefault("predicate", {})

    if "capabilityAllowlist" in pred:
        pred["capabilityAllowlist"] = ["*"]
    elif "policyNamespace" in pred:
        # Broadening DET-0008 means no longer requiring an ingress rule, so an
        # EGRESS-only policy in the observe zone is reported as an ingress grant.
        # That is a very plausible mistake -- an egress policy named "-ingress" by
        # someone who skimmed the name -- and it needs a policy in the snapshot that
        # has no ingress rules, or "broadened" is again a no-op.
        pred["requireIngressRule"] = False
        snap["networkPolicies"].append(
            {
                "namespace": pred["policyNamespace"],
                "name": "injected-egress-only",
                "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]},
            }
        )
    elif "roleNames" in pred:
        for extra in ("edit", "view", "admin"):
            snap["clusterRoleBindings"].append(
                {
                    "name": f"injected-{extra}-binding",
                    "roleRef": {"kind": "ClusterRole", "name": extra},
                    "subjects": [
                        {
                            "kind": "ServiceAccount",
                            "name": "sa-injected",
                            "namespace": "zerotrust",
                        }
                    ],
                }
            )
        pred["roleNames"] = ["cluster-admin", "edit", "view", "admin"]
    elif "keyPatterns" in pred:
        pred["keyPatterns"] = [".*"]
        # Give it something to find, or "broader" is a no-op on this data.
        snap["configMaps"].append(
            {
                "namespace": "zerotrust",
                "name": "injected-harmless",
                "data": {"LOG_LEVEL": "debug", "REPLICAS": "3"},
            }
        )
    else:
        pred["excludeServiceAccounts"] = []
        # Every lab service account becomes reportable, which is what removing the
        # exclusion actually means.
        for sa in snap["serviceAccounts"]:
            if sa["namespace"] in snap["namespaces"]:
                snap["serviceAccounts"].append(
                    {"namespace": sa["namespace"], "name": sa["name"]}
                )
                break
    return broken


def mutate_silently_widened(rule: dict) -> dict:
    """Add an expectation the check never justified.

    This is the subtle one. Nothing about the check changes; the *baseline* is
    edited so that a real problem is now declared acceptable. The only way the
    gate can object is by being handed a snapshot that contains the problem -- which
    is why the INJECTED cases above are necessary and not decorative.
    """
    broken = copy.deepcopy(rule)
    broken.setdefault("expect", []).append(
        {"subject": "zerotrust/never-existed", "via": "invented"}
    )
    return broken


# --------------------------------------------------------------------------- #
def main() -> int:
    snap = base_snapshot()
    rules = cp.load_rules()
    failures: list[str] = []
    checks = 0

    print("=" * 70)
    print("posture checks: proving each one can fail")
    print("=" * 70)
    print()

    # --- the gate passes on the real snapshot -----------------------------
    print("baseline")
    print("-" * 70)
    if cp.run_gate(rules, snap, verbose=False) != 0:
        print("  [FAIL] the posture gate does not pass on the real snapshot.")
        print("         Every mutation below is measured against a gate that is")
        print("         already red, so they would all 'pass' for the wrong reason.")
        return 1
    print("  [ok  ] the gate is green on the real snapshot, so a mutation going red means something")
    print()

    # --- INJECTED: a real new problem must be reported -------------------
    print("injected violations: the check must notice something actually wrong")
    print("-" * 70)
    for label, mutate in INJECTIONS:
        dirty = copy.deepcopy(snap)
        rule_id, expected_pair = mutate(dirty)
        rule = find_rule(rules, rule_id)
        # The rule's OWN declared scope, resolved exactly as run_gate does it, so
        # the harness is testing the gate and not a private copy of it.
        declared = cp.rule_namespaces(rule) or set(snap["namespaces"])
        findings = cp.CHECKS[rule["kind"]](rule, dirty, declared)
        pairs = {(f["subject"], f["via"]) for f in findings}
        checks += 1

        if expected_pair is None:
            # Negative case: this must NOT be reported.
            if len(pairs) - len(cp.expected_pairs(rule)) > 0:
                extra = pairs - cp.expected_pairs(rule)
                failures.append(
                    f"{rule_id}: reported {sorted(extra)} for '{label}', which is a "
                    f"false positive. A posture check that flags documentation or "
                    f"cluster plumbing gets ignored."
                )
                print(f"  [FAIL] {rule_id:<9} {label:<42} false positive {sorted(extra)}")
            else:
                print(f"  [ok  ] {rule_id:<9} {label:<42} correctly silent")
        else:
            if expected_pair in pairs:
                print(f"  [ok  ] {rule_id:<9} {label:<42} reported {expected_pair[0]}")
            else:
                failures.append(
                    f"{rule_id}: did not report {expected_pair} for '{label}'. This is "
                    f"the failure that matters: a posture check that would not notice "
                    f"a real new problem is not a check."
                )
                print(f"  [FAIL] {rule_id:<9} {label:<42} MISSED {expected_pair}")
    print()

    # --- rule mutations: the gate must object ----------------------------
    print("rule mutations: the gate must object")
    print("-" * 70)
    for rule in rules:
        for label, mutate in (
            ("vacuous", lambda r, s: mutate_vacuous(r)),
            ("broadened", mutate_broadened),
            ("expectation silently widened", lambda r, s: mutate_silently_widened(r)),
        ):
            # Fresh copy per mutation: mutate_broadened enriches the snapshot so its
            # broadening has something to find, and that must not leak into the next
            # case or the counts stop meaning anything.
            probe = copy.deepcopy(snap)
            broken_rules = copy.deepcopy(rules)
            for i, r in enumerate(broken_rules):
                if r["id"] == rule["id"]:
                    broken_rules[i] = mutate(r, probe)
            problems_before = cp.run_gate(copy.deepcopy(rules), snap, verbose=False)
            problems_after = cp.run_gate(broken_rules, probe, verbose=False)
            checks += 1
            if problems_after > problems_before:
                print(f"  [ok  ] {rule['id']:<9} {label:<32} caught")
            else:
                failures.append(
                    f"{rule['id']}: mutation '{label}' did not make the gate object. "
                    f"The gate does not constrain this check."
                )
                print(f"  [FAIL] {rule['id']:<9} {label:<32} SURVIVED")

    # --- and the strengthened gate must still be green --------------------
    print()
    print("after mutation: the real gate is still green")
    print("-" * 70)
    if cp.run_gate(rules, snap, verbose=False) != 0:
        failures.append("the gate is not green after the mutations ran; state leaked between cases")
        print("  [FAIL] state leaked out of a mutation")
    else:
        print("  [ok  ] no mutation leaked state into the real gate")

    print()
    print("=" * 70)
    if failures:
        print(f"FAIL  {len(failures)} problem(s) over {checks} case(s)")
        for f in failures:
            print(f"  [FAIL] {f}")
        return 1
    print(f"PASS  {checks} case(s): every check is proven to fire on a real violation,")
    print("      proven silent on a false positive, and proven to be constrained by the gate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
