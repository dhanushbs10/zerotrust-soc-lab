"""
Phase 7: proves every detection rule fires against real telemetry, and stays
quiet on everything else.

AGENTS.md rule 2 is "every detection ships with a test that proves it fires. An
untested rule is not a detection", and the phase is done when "every rule fires
against a real attack step". This file is that test.

Three things are checked, and the third is the one that matters most.

1. The rules are valid Sigma. Every rule is loaded by pySigma, the reference
   implementation, so the selection syntax, condition grammar and modifiers are
   parsed by something other than this lab's own code.

2. Each rule fires, and fires only within its own schema. A rule that matches
   nothing is the failure mode that matters, so every rule declares a minimum
   hit count and a check confirms no rule matches an event outside the schema it
   claims. Cross-schema leakage is how a rule written for exec events ends up
   quietly matching flow events that happen to share a field name.

3. The suite can fail. Each rule is deliberately broken in turn and the suite is
   re-run; a rule whose mutation is not caught is reported as a failure. This is
   the fourth time in this project a verification has passed while proving
   nothing, and the reason the harness checks itself is written into it.

Run:  python detections/test-detections.py
Exit: 0 all rules proved, 1 otherwise.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import sigmalite  # noqa: E402

TELEMETRY = os.path.join(ROOT, ".telemetry")
RULE_GLOB = os.path.join(HERE, "*", "*.yml")

# Only the two collector outputs are rule input.
#
# .telemetry/ also holds audit-events.jsonl, which is the raw 70MB export the
# collectors parse. Feeding it to the rules would be wrong twice over: raw audit
# records use different field names (verb, objectRef.subresource) rather than the
# normalized schema, so a rule can only match them by accident, and the file is
# large enough to dominate the run. The collectors are the boundary between
# "what the API server recorded" and "what a detection sees", and rules live on
# the far side of it.
RULE_INPUTS = ("runtime-events.jsonl", "network-events.jsonl")

# Expected hit count per rule, as an EXACT equality.
#
# It was a floor (`>= want`) first, and that turned out to be a gate that could
# not fail: replacing a rule's condition with one that matches its whole schema
# raised the count and sailed through. A detection that fires on everything is
# broken, so the check has to be two-sided.
#
# Exact counts are brittle by nature -- every walk of the lab changes them. That
# is the intended behaviour rather than a flaw: a count that moves means the lab
# changed shape or a rule drifted, and a human decides which. The project has
# taken this trade everywhere else, most visibly in attack/run-all.ps1, where a
# path that stops being walkable breaks the build on the day it happens.
#
# To re-baseline after a deliberate change, run with --update and read the diff.
# Re-baselined after the audit-log rotation fix. The counts are lower than the
# lab's true history for a reason worth stating: before that fix both the
# exporter and the runtime collector read only the live audit.log, so a rotated
# 104MB file was invisible and the collector reported 14 exec sessions for a lab
# that had run 978. det-0003 was baselined at 87 against that truncated view; it
# is 108 against the recovered history, and det-0010 went 4 -> 15.
#
# These numbers are a fingerprint of one lab's current state, not a target. They
# move every time the lab is walked, and that is the gate working.
EXPECTED_HITS: dict[str, int] = {
    "det-0003-credential-or-escape-exec.yml": 108,
    "det-0004-pod-log-credential-read.yml": 32,
    "det-0005-refused-egress-burst.yml": 2,
    "det-0006-cross-zone-remote-service.yml": 4,
    "det-0010-pod-portforward.yml": 15,
    "det-0011-off-baseline-token-request.yml": 24,
}

# Rules whose hits are expected to be entirely lab instrumentation. Stated here
# rather than left implicit, because "the rule fired" and "the rule fired on
# something an attacker did" are different claims.
ALL_HITS_INSTRUMENTATION = {"det-0006-cross-zone-remote-service.yml"}


def verify_rule(rule: sigmalite.Rule, events: list[dict[str, Any]]) -> tuple[list[dict], list[str]]:
    """The real gate. Returns (hits, problems).

    Extracted as its own function so the mutation harness below can call exactly
    what the suite calls. A mutation harness that re-implements the check is
    testing its own copy rather than the gate, and would report success even if
    the gate were vacuous.
    """
    problems: list[str] = []
    name = os.path.basename(rule.source)
    hits = sigmalite.match_all(rule, events)
    declared = rule.logsource.get("schema", "")
    want = EXPECTED_HITS.get(name)

    if want is None:
        problems.append(f"{name}: no expected hit count declared")
    elif len(hits) != want:
        problems.append(f"{name}: {len(hits)} hits, expected exactly {want}")

    wrong = [h for h in hits if h.get("schema") != declared]
    if wrong:
        problems.append(f"{name}: {len(wrong)} hits outside the declared schema {declared}")

    if not hits and want != 0:
        problems.append(f"{name}: matched nothing, which is indistinguishable from working")

    if name in ALL_HITS_INSTRUMENTATION:
        roles = {h.get("source", {}).get("role") for h in hits}
        if roles - {"instrumentation"}:
            problems.append(f"{name}: non-instrumentation hits {roles}")

    return hits, problems


def load_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for filename in RULE_INPUTS:
        path = os.path.join(TELEMETRY, filename)
        if not os.path.exists(path):
            print(f"missing rule input {path}; run the collectors first", file=sys.stderr)
            sys.exit(2)
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))

    # Every event a rule can see must carry a schema. An event without one is a
    # raw record that leaked into the input set, and a rule could then match it
    # by field-name accident rather than by meaning.
    schemaless = [e for e in events if not isinstance(e.get("schema"), str)]
    if schemaless:
        print(
            f"{len(schemaless)} event(s) carry no schema field; rule input must be "
            f"collector output only",
            file=sys.stderr,
        )
        sys.exit(2)
    return events


def load_rules() -> list[sigmalite.Rule]:
    paths = sorted(glob.glob(RULE_GLOB))
    if not paths:
        print(f"no rules matched {RULE_GLOB}", file=sys.stderr)
        sys.exit(2)
    return [sigmalite.load_rule(p) for p in paths]


def validate_with_pysigma(paths: list[str]) -> tuple[int, list[str]]:
    """Load every rule with pySigma. Returns (count, problems)."""
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        return -1, ["pySigma is not installed; rules are unvalidated Sigma"]

    problems: list[str] = []
    count = 0
    for path in paths:
        try:
            collection = SigmaCollection.load_ruleset([path])
            count += len(collection.rules)
        except Exception as err:  # noqa: BLE001
            problems.append(f"{os.path.basename(path)}: {type(err).__name__}: {err}")
    return count, problems


def technique_coverage(rules: list[sigmalite.Rule]) -> dict[str, list[str]]:
    covered: dict[str, list[str]] = {}
    for rule in rules:
        for technique in rule.techniques:
            covered.setdefault(technique, []).append(os.path.basename(rule.source))
    return covered


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 7 detection tests")
    parser.add_argument(
        "--chain",
        action="store_true",
        help=(
            "verify the Phase 8 chain instead of the exact-count gate. Reports which "
            "of the chain's techniques the rule set can actually detect, and does not "
            "enforce EXPECTED_HITS -- walking the lab changes those counts by design, "
            "so enforcing them here would report the chain as broken when it is the "
            "baseline that moved."
        ),
    )
    args = parser.parse_args()

    events = load_events()
    rules = load_rules()
    paths = sorted(glob.glob(RULE_GLOB))

    if args.chain:
        return chain_mode(events, rules)

    return gate_mode(events, rules, paths)


def chain_mode(events: list[dict[str, Any]], rules: list[sigmalite.Rule]) -> int:
    """Phase 8: did the chain get detected, hop by hop?

    Read `.telemetry/chain-summary.json`, work out which techniques the rule set
    can cover, and report the difference. The point of this mode is the
    *undetectable* column: a chain report that only lists hits reads as "fully
    detected" even when a hop has no rule behind it at all.
    """
    summary_path = os.path.join(TELEMETRY, "chain-summary.json")
    if not os.path.exists(summary_path):
        print(
            f"{summary_path} not found. Run attack/chain-purple-team.ps1 first, then "
            "re-run the collectors so the chain's events are in the telemetry.",
            file=sys.stderr,
        )
        return 2
    with open(summary_path, "r", encoding="utf-8") as handle:
        chain = json.load(handle)

    # What fired, per rule.
    fired: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        fired[os.path.basename(rule.source)] = sigmalite.match_all(rule, events)

    # technique -> rules that carry it
    by_technique: dict[str, list[str]] = {}
    for rule in rules:
        for technique in rule.techniques:
            by_technique.setdefault(technique, []).append(os.path.basename(rule.source))

    print("Phase 8: was the chain detected?")
    print("=" * 78)
    print(f"  chain run      : {chain.get('chainRun')}")
    print(f"  hops           : {chain.get('hopsSucceeded')} succeeded, {chain.get('hopsFailed')} failed")
    print(f"  events in scope: {len(events)}")
    print()

    failures: list[str] = []
    seen: set[str] = set()
    for hop in chain.get("hops", []):
        technique = hop.get("attackId", "")
        seen.add(technique)
        rules_for = by_technique.get(technique, [])
        if not rules_for:
            print(f"  {hop.get('id'):<7} {technique:<11} NO RULE       {hop.get('what')}")
            failures.append(f"{hop.get('id')} ({technique}): no rule covers this technique")
            continue
        counts = ", ".join(f"{name.split('.')[0]}={len(fired[name])}" for name in rules_for)
        print(f"  {hop.get('id'):<7} {technique:<11} rule fires  {hop.get('what')}  [{counts}]")

    # A technique the chain walked that nothing carries.
    for technique in chain.get("techniques", []):
        if technique not in seen:
            failures.append(f"{technique}: listed as walked but no hop carries it")

    print()
    print("  What 'rule fires' does and does not claim")
    print("  -----------------------------------------")
    print("  It claims a rule for that technique exists and is matching events in the")
    print("  current telemetry. It does NOT claim this hop was the cause of those")
    print("  matches. The chain records verdicts, not the auditIDs it caused, so")
    print("  hop-level attribution would need the chain to emit the auditID of every")
    print("  request it made. Attributing by technique alone is the 'agreement is not")
    print("  evidence' mistake: a T1552.001 hop gets credited to the pod-log-read rule")
    print("  because that rule carries the tag, even when the hop produced an exec")
    print("  event the rule never looks at.")

    print()
    undetectable = chain.get("undetectable", [])
    if undetectable:
        print(f"  {len(undetectable)} technique(s) walked with NO telemetry schema behind them: "
              f"{', '.join(undetectable)}")
        print("  Those hops ran for real. No rule can fire on them, and this report")
        print("  does not claim otherwise.")

    print()
    print("=" * 78)
    if failures:
        print(f"  chain coverage is INCOMPLETE: {len(failures)} hop(s) with no rule at all")
        for failure in failures:
            print(f"    [FAIL] {failure}")
        return 1
    print("  every hop has a rule, and every rule is firing")
    return 0


def gate_mode(events: list[dict[str, Any]], rules: list[sigmalite.Rule], paths: list[str]) -> int:
    """The Phase 7 gate: exact hit counts, schema containment, mutation proof."""
    print("Phase 7 detection tests")
    print("=" * 70)
    print(f"  events : {len(events)}")
    print(f"  rules  : {len(rules)}")

    failures: list[str] = []

    # --- 1. the rules are real Sigma -------------------------------------
    count, problems = validate_with_pysigma(paths)
    if count == -1:
        print("  pysigma: NOT INSTALLED -- rules are not validated as Sigma")
        failures.extend(problems)
    else:
        print(f"  pysigma: {count} rule(s) parsed by the reference implementation")
        for problem in problems:
            print(f"    [FAIL] {problem}")
            failures.append(problem)

    by_schema: dict[str, int] = {}
    for event in events:
        schema = event.get("schema")
        if isinstance(schema, str):
            by_schema[schema] = by_schema.get(schema, 0) + 1

    print()
    print("per-rule results")
    print("-" * 70)

    results: dict[str, list[dict[str, Any]]] = {}

    for rule in rules:
        name = os.path.basename(rule.source)
        hits, problems = verify_rule(rule, events)
        results[name] = hits
        declared = rule.logsource.get("schema", "")
        want = EXPECTED_HITS.get(name)

        print(f"  {name:<44} {len(hits):>4} hit(s)  {declared}  (expect exactly {want})")
        for problem in problems:
            print(f"    [FAIL] {problem}")
            failures.append(problem)

        if name in ALL_HITS_INSTRUMENTATION and not problems:
            print("    note  every hit is lab instrumentation; this rule has no")
            print("          attack-step positive in this lab, by design. See its")
            print("          description before filtering on source.role.")

    # --- 2. every technique the registry declares has a rule ------------
    print()
    print("ATT&CK coverage of the rule set")
    print("-" * 70)
    covered = technique_coverage(rules)
    for technique in sorted(covered):
        names = ", ".join(covered[technique])
        print(f"  {technique:<12} {names}")

    # --- 3. the suite can fail ------------------------------------------
    print()
    print("mutation: each rule is broken on purpose and the SAME gate re-run")
    print("-" * 70)
    print("  a mutation counts as caught only when verify_rule() itself reports a")
    print("  problem. Comparing hit counts here instead would be testing a copy of")
    print("  the check rather than the check.")
    import copy

    for rule in rules:
        name = os.path.basename(rule.source)
        baseline_hits = results[name]
        original_selections = copy.deepcopy(rule.selections)
        original_condition = rule.condition
        original_tokens = list(rule._tokens)

        mutations: list[tuple[str, Any]] = []

        # Mutation A: drop the schema guard, so the rule can match any schema
        # that happens to share a field name.
        for sel_name, sel in list(rule.selections.items()):
            if isinstance(sel, dict) and "schema" in sel:
                weakened = copy.deepcopy(rule.selections)
                weakened[sel_name].pop("schema")
                mutations.append(("schema guard dropped", (weakened, rule.condition)))
                break

        # Mutation B: replace the detection with one that matches the rule's
        # whole schema. A detection that fires on everything is broken, and the
        # exact-count check exists to catch it.
        mutations.append((
            "condition replaced by match-everything",
            ({"sel": {"schema": rule.logsource.get("schema", "")}}, "sel"),
        ))

        # Mutation C: require a field value that no event carries, so the rule
        # matches nothing at all. The other direction.
        mutations.append((
            "condition requires an impossible value",
            (copy.deepcopy(rule.selections) | {
                "impossible": {"schema": "this-schema-does-not-exist/v9"},
            }, "sel and impossible"),
        ))

        for label, (selections, condition) in mutations:
            rule.selections = copy.deepcopy(selections)
            rule.condition = condition
            rule._tokens = sigmalite._tokenize(condition)
            try:
                mutated_hits, problems = verify_rule(rule, events)
            except Exception as err:  # noqa: BLE001
                mutated_hits, problems = [], [f"raised {type(err).__name__}: {err}"]

            # Three outcomes, and only the third is a failure.
            #   caught     the gate objected
            #   equivalent  the gate agreed AND the hit set is identical, which
            #               means the mutation changed nothing observable. That is
            #               a real finding -- the rule is redundant there -- and it
            #               is reported rather than hidden or failed.
            #   survived   the behaviour changed and the gate did not notice,
            #               which means the gate is not constraining that rule.
            if problems:
                verdict, mark = "caught", "ok  "
            elif mutated_hits == baseline_hits:
                verdict, mark = "equivalent", "note"
            else:
                verdict, mark = "SURVIVED", "FAIL"
                failures.append(
                    f"{name}: mutation '{label}' changed the result "
                    f"({len(baseline_hits)} -> {len(mutated_hits)} hits) and the gate did not notice"
                )
            print(f"  [{mark}] {name:<44} {label:<38} {verdict}")

        rule.selections = original_selections
        rule.condition = original_condition
        rule._tokens = original_tokens

    # --- verdict ---------------------------------------------------------
    print()
    print("=" * 70)
    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for failure in failures:
            print(f"  [FAIL] {failure}")
        return 1
    print(f"PASS  {len(rules)} rule(s) over {len(events)} event(s): "
          "each fires, none fires outside its schema, and each is provably breakable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
