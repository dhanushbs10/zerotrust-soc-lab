#!/usr/bin/env python3
"""Posture checks against live cluster state. The gate for DET-0001/0002/0007/0008/0009.

    python detections/posture/check_posture.py                  # read the live cluster
    python detections/posture/check_posture.py --from-file X    # read a snapshot
    python detections/posture/check_posture.py --snapshot X     # write a snapshot

What this is, and what it is not
-------------------------------
This is NOT a telemetry detector. There are no events here and there is no audit
log. Each check reads a piece of configuration -- a RoleBinding, a ConfigMap, a
securityContext, a NetworkPolicy, a ServiceAccount -- and asks whether it is
acceptable. That is why these are declarative rules in posture-rules.yml rather
than Sigma: a Sigma rule selects fields out of events, and there are no events.

The gate is exact set equality, in both directions
--------------------------------------------------
Every finding here is EXPECTED. This lab is deliberately vulnerable: sa-build-runner
holds cluster-admin on purpose and web-frontend sets runAsNonRoot: false on
purpose. So "the check fires" is not the test -- every check fires in a healthy
lab, and a check that fired on nothing would be the broken one.

What is tested is whether the SET of findings matches what posture-rules.yml
declares, exactly:

  * a finding not in the expected set  -> something changed, or the check is loose
  * an expected finding that is absent -> a control was removed, or the check broke

Both directions, because a one-directional check cannot notice a control
disappearing. That is the same shape as tools/scan-pods.ps1 and the same reason.

Why the cluster is snapshotted
------------------------------
--from-file exists so the checks can be tested without a cluster, which is what
detections/posture/test_posture.py does. It is also how you inspect what the
checker saw after the fact instead of re-deriving it. The snapshot is gitignored:
it describes one cluster at one moment and is not a fact about the rules.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "posture-rules.yml")
DEFAULT_SNAPSHOT = os.path.join(ROOT, ".telemetry", "posture-snapshot.json")

CLUSTER_ADMIN = "cluster-admin"


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #
def kubectl_json(*args: str) -> Any:
    """Run kubectl and parse the result.

    Resolved from PATH, like every other component in this lab. The first version
    shelled through `docker exec soc-lab-control-plane kubectl`, justified by the
    claim that "the kubeconfig for a kind cluster lives inside the node container".
    That is not true on a machine where kind has written a host kubeconfig -- which
    is the normal case, and is how scan-pods.ps1, build-reachability.ps1 and the
    attack chain all reach the cluster. The result was one component in a
    repository that otherwise agree on how to talk to Kubernetes, and a posture
    snapshot path that was the only thing here still working without a host
    kubeconfig.
    """
    proc = subprocess.run(
        ["kubectl", *args, "-o", "json"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"kubectl {' '.join(args)} failed (exit {proc.returncode}):\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def build_snapshot() -> dict[str, Any]:
    """Read everything the five checks need, in one pass over the API.

    Read once and evaluated many times, deliberately. Five separate `kubectl get`
    calls per check would mean fifteen round trips and fifteen chances for the
    cluster to change underneath the evaluation, so a finding could be a real one
    and an absence a false negative from a different instant.
    """
    namespaces = ["zerotrust", "zerotrust-build", "zerotrust-observe"]
    snap: dict[str, Any] = {
        "readAt": None,
        "namespaces": namespaces,
        "roleBindings": [],
        "clusterRoleBindings": [],
        "clusterRoles": [],
        "configMaps": [],
        "pods": [],
        "networkPolicies": [],
        "serviceAccounts": [],
    }

    for b in kubectl_json("get", "rolebinding", "-A")["items"]:
        snap["roleBindings"].append(
            {
                "namespace": b["metadata"]["namespace"],
                "name": b["metadata"]["name"],
                "roleRef": b["roleRef"],
                "subjects": b.get("subjects") or [],
            }
        )
    for b in kubectl_json("get", "clusterrolebinding")["items"]:
        snap["clusterRoleBindings"].append(
            {
                "name": b["metadata"]["name"],
                "roleRef": b["roleRef"],
                "subjects": b.get("subjects") or [],
            }
        )
    snap["clusterRoles"] = [
        {"name": r["metadata"]["name"], "rules": r.get("rules") or []}
        for r in kubectl_json("get", "clusterrole")["items"]
    ]
    for ns in namespaces:
        for c in kubectl_json("get", "configmap", "-n", ns)["items"]:
            snap["configMaps"].append(
                {"namespace": ns, "name": c["metadata"]["name"], "data": c.get("data") or {}}
            )
    for p in kubectl_json("get", "pods", "-A")["items"]:
        ns = p["metadata"]["namespace"]
        if ns not in namespaces:
            continue
        spec = p["spec"]
        snap["pods"].append(
            {
                "namespace": ns,
                "name": p["metadata"]["name"],
                "labels": p["metadata"].get("labels") or {},
                "securityContext": spec.get("securityContext") or {},
                "containers": [
                    {
                        "name": c["name"],
                        "securityContext": c.get("securityContext") or {},
                    }
                    for c in (spec.get("containers") or [])
                ],
            }
        )
    for np in kubectl_json("get", "networkpolicy", "-A")["items"]:
        ns = np["metadata"]["namespace"]
        if ns not in namespaces:
            continue
        snap["networkPolicies"].append(
            {
                "namespace": ns,
                "name": np["metadata"]["name"],
                "spec": np["spec"],
            }
        )
    for ns in namespaces:
        for sa in kubectl_json("get", "serviceaccount", "-n", ns)["items"]:
            snap["serviceAccounts"].append(
                {"namespace": ns, "name": sa["metadata"]["name"]}
            )
    return snap


# --------------------------------------------------------------------------- #
# findings
#
# A finding is a plain dict: {rule, subject, via, detail}. Kept as data rather
# than a class so the mutation harness can assert on it and so the JSON report is
# the same shape the gate compares.
# --------------------------------------------------------------------------- #
def check_det0001(rule: dict, snap: dict, lab_ns: set[str]) -> list[dict]:
    """A lab ServiceAccount bound to cluster-admin, or to any verb on secrets.

    Scoped to lab namespaces, and the scoping is the whole difficulty. Measured on
    this cluster: 44 ServiceAccount bindings, 43 of them kube-system controllers
    binding themselves to their own ClusterRole. Without the scope this check
    reports 44 findings and the one that matters is 1.
    """
    pred = rule["predicate"]
    findings: list[dict] = []

    bindings = list(snap["roleBindings"]) + list(snap["clusterRoleBindings"])
    role_rules: dict[str, list[dict]] = {r["name"]: r["rules"] for r in snap["clusterRoles"]}

    for b in bindings:
        for s in b.get("subjects") or []:
            if s.get("kind") != "ServiceAccount":
                continue
            ns = s.get("namespace")
            if ns not in lab_ns:
                continue
            subject = f"{ns}/{s['name']}"
            role_name = b["roleRef"]["name"]

            if role_name in pred.get("roleNames", []):
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": role_name,
                        "detail": f"bound to {role_name} via "
                        f"{b.get('namespace', '<cluster>')}/{b['name']}",
                    }
                )
                continue

            # The second half: any verb of '*' over secrets, resolved from the
            # ClusterRole rather than matched by name. This is a real permission
            # lookup, which is why this check reads roles as well as bindings --
            # and it is why a rule that only knew role NAMES would miss it.
            if b["roleRef"]["kind"] == "ClusterRole" and role_name in role_rules:
                for r in role_rules[role_name]:
                    verbs = r.get("verbs") or []
                    resources = r.get("resources") or []
                    if pred.get("verbsOnSecrets") == "*" and "*" in verbs:
                        if "secrets" in resources or "*" in resources:
                            findings.append(
                                {
                                    "rule": rule["id"],
                                    "subject": subject,
                                    "via": "secrets-wildcard",
                                    "detail": f"role {role_name} grants verbs={verbs} "
                                    f"on resources={resources}",
                                }
                            )
                            break
    return findings


def check_det0002(rule: dict, snap: dict, lab_ns: set[str]) -> list[dict]:
    """A credential-shaped key or value in a ConfigMap. By shape, never by value.

    The value patterns are deliberately narrow. A loose 'password' value pattern
    matches prose: measured, it also hit lab-catalog/privileges.md,
    lab-catalog/weaknesses.yaml and web-frontend-content/index.html, all of which
    merely contain the word. So the value half only matches a credential actually
    embedded in something -- a URL with a password field, or KEY=value where the
    KEY is itself credential-shaped.
    """
    pred = rule["predicate"]
    key_res = [re.compile(p) for p in pred.get("keyPatterns", [])]
    val_res = [re.compile(p) for p in pred.get("valuePatterns", [])]
    findings: list[dict] = []

    for cm in snap["configMaps"]:
        if cm["namespace"] not in lab_ns:
            continue
        for key, value in (cm.get("data") or {}).items():
            subject = f"{cm['namespace']}/{cm['name']}/{key}"
            hit = next((r.pattern for r in key_res if r.search(key)), None)
            via = "key"
            if hit is None:
                hit = next((r.pattern for r in val_res if r.search(str(value))), None)
                via = "value"
            if hit is not None:
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": via,
                        # The matched PATTERN is reported, never the value. A
                        # posture report that quoted the credential it found would
                        # be a credential in a gitignored file that nobody reads
                        # carefully.
                        "detail": f"{via} matched {hit!r}",
                    }
                )
    return findings


def check_det0007(rule: dict, snap: dict, lab_ns: set[str]) -> list[dict]:
    """runAsNonRoot false or missing, privileged, or a capability off the allowlist.

    The effective runAsNonRoot is pod-then-container, because a container inherits
    the pod's value. Reading the container key alone would call every lab container
    compliant, since none of them set it -- the pod sets it. That is the
    "scanner that only looks for a missing key" failure the catalogue names, in the
    opposite direction from the one it describes.
    """
    pred = rule["predicate"]
    allow = set(pred.get("capabilityAllowlist", []))
    findings: list[dict] = []
    flags = pred.get("flags", {})

    def subject_of(pod: dict) -> str:
        """The WORKLOAD, not the pod instance.

        Pod names carry a ReplicaSet hash: `web-frontend-7cd8cbf8c4-xnwm7`. A
        posture finding whose subject changes on every rollout cannot be put in an
        expected-findings list, and a list that has to be regenerated whenever a
        Deployment is rescheduled is a list nobody maintains. So the subject is
        the `app` label when there is one, which is stable, and the pod name goes
        in the detail for traceability.
        """
        app = (pod.get("labels") or {}).get("app")
        return f"{pod['namespace']}/{app or pod['name']}"

    for pod in snap["pods"]:
        if pod["namespace"] not in lab_ns:
            continue
        psc = pod.get("securityContext") or {}
        for c in pod.get("containers") or []:
            csc = c.get("securityContext") or {}
            subject = subject_of(pod)
            where = f"pod {pod['name']}, container {c['name']}"

            if csc.get("privileged") is True or psc.get("privileged") is True:
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": "privileged-true",
                        "detail": f"{where} runs privileged",
                    }
                )

            effective = csc.get("runAsNonRoot")
            if effective is None:
                effective = psc.get("runAsNonRoot")
            if effective is False and flags.get("runAsNonRootFalse") == "fail":
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": "runAsNonRoot-false",
                        # An explicit false is called out separately from a
                        # missing key, because it is a decision someone made.
                        "detail": f"{where}: runAsNonRoot is explicitly false, not "
                        f"merely unset",
                    }
                )
            elif effective is None and flags.get("missingRunAsNonRoot") == "fail":
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": "runAsNonRoot-missing",
                        "detail": f"{where}: no runAsNonRoot at pod or container level",
                    }
                )

            added = (csc.get("capabilities") or {}).get("add") or []
            extra = [cap for cap in added if cap not in allow]
            if extra:
                findings.append(
                    {
                        "rule": rule["id"],
                        "subject": subject,
                        "via": f"capability-{extra[0]}",
                        "detail": f"{where} adds {extra} beyond the allowlist "
                        f"{sorted(allow)}",
                    }
                )
    return findings


def check_det0008(rule: dict, snap: dict, lab_ns: set[str]) -> list[dict]:
    """A NetworkPolicy in the observe zone that grants ingress.

    Narrower than it looks, on purpose. Measured: four policies in this cluster
    SELECT the observe zone -- the sensor's own ingress, plus orders-api,
    postgres and web-frontend each admitting the sensor, which is PP-02 working
    exactly as designed. Only one of those is a policy *in* the observe zone, and
    that is the one the catalogue means by "fires exactly once". Widening this to
    "mentions the observe zone" would report three correct controls as findings.
    """
    pred = rule["predicate"]
    findings: list[dict] = []
    target_ns = pred.get("policyNamespace")

    if target_ns not in lab_ns:
        # A rule pointing outside the lab would report cluster plumbing. It is
        # reported as an empty finding set rather than raised, so that the caller
        # can turn it into a gate problem.
        #
        # This raised SystemExit in the first version, which killed the whole
        # mutation harness: one malformed rule took down the process that was
        # supposed to be proving the other rules work. A check that reports its own
        # misconfiguration as a problem is strictly more useful than one that
        # refuses to run.
        return findings

    for np in snap["networkPolicies"]:
        if np["namespace"] != target_ns:
            continue
        rules = np["spec"].get("ingress")
        if pred.get("requireIngressRule") and not rules:
            continue
        findings.append(
            {
                "rule": rule["id"],
                "subject": f"{np['namespace']}/{np['name']}",
                "via": "ingress-grant",
                "detail": f"policy in the observe zone carries {len(rules or [])} "
                f"ingress rule(s)",
            }
        )
    return findings


def check_det0009(rule: dict, snap: dict, lab_ns: set[str]) -> list[dict]:
    """A lab ServiceAccount holding a token with no binding at all.

    `default` is excluded, and that is a real exclusion rather than a
    convenience: every namespace has one, every pod gets a token for it, and it is
    never bound. Measured, 3 of the 6 unbound lab service accounts are `default`,
    so including it would triple the count with a truth that holds of every
    Kubernetes cluster ever built and therefore says nothing about this one.
    """
    pred = rule["predicate"]
    skip = set(pred.get("excludeServiceAccounts", []))
    bound: set[tuple[str, str]] = set()
    for b in list(snap["roleBindings"]) + list(snap["clusterRoleBindings"]):
        for s in b.get("subjects") or []:
            if s.get("kind") == "ServiceAccount":
                bound.add((s.get("namespace"), s.get("name")))

    findings: list[dict] = []
    for sa in snap["serviceAccounts"]:
        ns = sa["namespace"]
        if ns not in lab_ns or sa["name"] in skip:
            continue
        if (ns, sa["name"]) not in bound:
            findings.append(
                {
                    "rule": rule["id"],
                    "subject": f"{ns}/{sa['name']}",
                    "via": "unbound",
                    "detail": "issues a token and is bound to nothing; it authenticates "
                    "and appears in the audit log while granting nothing today",
                }
            )
    return findings


CHECKS = {
    "binding": check_det0001,
    "configmap": check_det0002,
    "securityContext": check_det0007,
    "networkpolicy": check_det0008,
    "serviceaccount": check_det0009,
}


# --------------------------------------------------------------------------- #
# gate
# --------------------------------------------------------------------------- #
def expected_pairs(rule: dict) -> set[tuple[str, str]]:
    return {(e["subject"], e["via"]) for e in rule.get("expect", [])}


def rule_namespaces(rule: dict) -> set[str]:
    """The namespaces a rule declares it applies to.

    Read from the rule, not from the snapshot, and that is the point.
    --------------------------------------------------------------
    The first version of this gate took the namespace set from the snapshot and
    never looked at `scope.subjectNamespaces` in the rules at all. So every rule
    carried a scope declaration that was decorative: a reader would reasonably
    believe that narrowing `subjectNamespaces` narrowed the check, and it would do
    nothing at all.

    A declaration in a config file that the code ignores is worse than no
    declaration, because it is a control that reads like one. Taking the set from
    the rule makes the declaration real, and it makes the "vacuous" mutation in
    test_posture.py catchable -- pointing a rule at kube-system now genuinely
    stops it finding anything, which is what the word implies.
    """
    scope = rule.get("scope") or {}
    declared = scope.get("subjectNamespaces")
    if declared == "labNamespaces":
        return set()  # resolved by the caller, which has the snapshot
    if not declared:
        return set()
    return set(declared)


def run_gate(rules: list[dict], snap: dict, verbose: bool = True) -> int:
    snap_ns = set(snap.get("namespaces") or [])
    problems: list[str] = []
    total = 0

    for rule in rules:
        check = CHECKS.get(rule["kind"])
        if check is None:
            problems.append(f"{rule['id']}: unknown kind {rule['kind']!r}")
            continue

        # Each rule's own declared scope, validated against the snapshot's.
        # `labNamespaces` is the sentinel that means "whatever the snapshot says is
        # the lab", so the resolution happens here rather than inside each check.
        declared = rule_namespaces(rule)
        if not declared:
            declared = snap_ns
        else:
            outside = declared - snap_ns
            if outside:
                problems.append(
                    f"{rule['id']}: scope.subjectNamespaces names {sorted(outside)}, "
                    f"which is not in the snapshot's lab namespaces {sorted(snap_ns)}. "
                    f"The rule would evaluate outside the lab, where most bindings are "
                    f"cluster plumbing, and the declaration would be reporting things "
                    f"nobody can act on."
                )
                declared = declared & snap_ns

        findings = check(rule, snap, declared)
        total += len(findings)
        expected = expected_pairs(rule)
        actual = {(f["subject"], f["via"]) for f in findings}

        extra = actual - expected
        missing = expected - actual
        duplicates = len(findings) - len(actual)

        if verbose:
            print()
            print(f"  {rule['id']}  {rule['title']}")
            print(f"    {len(findings)} finding(s), {len(expected)} expected")

        if not findings and expected:
            # The failure that matters most: a check that found nothing in a lab
            # built to trip it. Could be a broken check or a removed control, and
            # the message says both because the snapshot cannot tell them apart.
            problems.append(
                f"{rule['id']}: matched nothing, but {len(expected)} finding(s) are "
                f"expected. Either the check is broken or a control was removed; the "
                f"snapshot cannot distinguish those, and neither should a reader."
            )
        for subject, via in sorted(extra):
            problems.append(
                f"{rule['id']}: unexpected finding {subject} ({via}). Either the "
                f"cluster changed or the check is looser than it claims."
            )
        for subject, via in sorted(missing):
            problems.append(
                f"{rule['id']}: expected finding {subject} ({via}) is absent."
            )
        if duplicates:
            problems.append(
                f"{rule['id']}: reported {len(findings)} findings for "
                f"{len(actual)} distinct subject(s). A check that reports the same "
                f"problem twice per subject is harder to act on, not more thorough."
            )

    if verbose:
        print()
        print("=" * 70)
        if problems:
            print(f"FAIL  {len(problems)} problem(s) across {len(rules)} posture check(s)")
            for p in problems:
                print(f"  [FAIL] {p}")
            return 1
        print(
            f"PASS  {len(rules)} posture check(s), {total} finding(s): every finding is "
            f"an expected one, and every expected finding is present"
        )
        print(
            "      Note this is a posture gate, not a detection one. All these findings"
        )
        print(
            "      are intentional. What it proves is that the SET of them has not changed."
        )
    return len(problems)


# --------------------------------------------------------------------------- #
# yaml loading
#
# PyYAML if it is installed; otherwise a deliberately small reader for exactly the
# shape of posture-rules.yml. The fallback exists so the check runs in a fresh clone
# with nothing but the Python that the lab already requires, and it is strict --
# it raises on anything it does not understand rather than guessing, for the same
# reason detections/engine/sigmalite.py does.
# --------------------------------------------------------------------------- #
def load_rules(path: str = RULES_PATH) -> list[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        import yaml  # type: ignore
    except ImportError:
        return _load_rules_minimal(text)
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "rules" not in data:
        raise SystemExit(f"{path}: expected a mapping with a 'rules' key")
    return data["rules"]


def _scalar(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    if raw in ("true", "True"):
        return True
    if raw in ("false", "False"):
        return False
    if raw in ("null", "~", ""):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        return [_scalar(p) for p in inner.split(",")] if inner else []
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _load_rules_minimal(text: str) -> list[dict]:
    """Enough YAML for this file, and it refuses anything else.

    Deliberately small. A general YAML implementation is not something to
    half-write, and a parser that silently misreads a rule is worse than one that
    stops.
    """
    rules: list[dict] = []
    in_rules = False
    current: dict | None = None
    # Tracks the key we are inside, so nested maps (predicate:, scope:, expect:)
    # land in the right place without a real parser.
    stack: list[tuple[int, str]] = []
    in_expect = False

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        if raw_line.rstrip() == "rules:":
            in_rules = True
            continue
        if not in_rules:
            continue

        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        if line.startswith("- id:"):
            if current:
                rules.append(current)
            current = {"id": _scalar(line.split(":", 1)[1])}
            stack = [(indent, "")]
            in_expect = False
            continue

        if current is None:
            continue

        if in_expect:
            if line.startswith("- subject:"):
                stack.append((indent, "item"))
                current.setdefault("expect", []).append(
                    {"subject": _scalar(line.split(":", 1)[1])}
                )
                continue
            if line.startswith("via:") and current.get("expect"):
                current["expect"][-1]["via"] = _scalar(line.split(":", 1)[1])
                continue
            if not line.startswith("-"):
                in_expect = False

        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()

        if value == "":
            stack.append((indent, key))
            if key == "expect":
                in_expect = True
            continue

        target = current
        for s_indent, s_key in reversed(stack[:-1] if stack else []):
            if isinstance(target.get(s_key), dict):
                target = target[s_key]
        if key in ("name", "namespace") and isinstance(target, dict) and stack:
            last_key = stack[-1][1]
            if last_key in ("predicate", "scope"):
                target = current.setdefault(last_key, {})
        target[key] = _scalar(value)

    if current:
        rules.append(current)
    for r in rules:
        r.setdefault("expect", [])
    return rules


def main() -> int:
    parser = argparse.ArgumentParser(description="posture checks and their gate")
    parser.add_argument(
        "--from-file", metavar="PATH", help="evaluate a snapshot instead of the cluster"
    )
    parser.add_argument(
        "--snapshot", metavar="PATH", help="write a snapshot and exit (for --from-file use)"
    )
    parser.add_argument("--rules", default=RULES_PATH, help="path to posture-rules.yml")
    parser.add_argument("--quiet", action="store_true", help="verdict only")
    args = parser.parse_args()

    if args.snapshot:
        snap = build_snapshot()
        os.makedirs(os.path.dirname(args.snapshot), exist_ok=True)
        with open(args.snapshot, "w", encoding="utf-8") as handle:
            json.dump(snap, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote {args.snapshot}")
        return 0

    if args.from_file:
        with open(args.from_file, "r", encoding="utf-8") as handle:
            snap = json.load(handle)
    else:
        snap = build_snapshot()

    rules = load_rules(args.rules)
    if not args.quiet:
        print("=" * 70)
        print("posture checks against live cluster state")
        print("=" * 70)
        print(f"  rules      {len(rules)}")
        print(f"  namespaces {', '.join(snap.get('namespaces') or [])}")
        print()
        print("  All findings below are INTENTIONAL. This lab is deliberately")
        print("  vulnerable, so the gate is whether the set of findings is unchanged,")
        print("  not whether there are any.")
    return run_gate(rules, snap, verbose=not args.quiet)


if __name__ == "__main__":
    sys.exit(main())
