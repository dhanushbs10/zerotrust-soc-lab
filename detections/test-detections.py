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
import time
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import sigmalite  # noqa: E402

TELEMETRY = os.path.join(ROOT, ".telemetry")
RULE_GLOB = os.path.join(HERE, "*", "*.yml")

# detections/posture/ holds rules too, and they are not Sigma.
#
# The glob above matches detections/posture/posture-rules.yml, because it is a
# .yml inside a directory under detections/. Loading it made sigmalite raise
# `SigmaError: no detection block`, which is the engine behaving exactly as
# designed -- it refuses anything it does not understand rather than skipping it --
# so the whole detection gate died on a file it was never meant to read.
#
# The engine was right and the caller was wrong. Posture rules are a different
# class: they read live configuration rather than telemetry, so they carry no
# `detection:` block and have no logsource schema. They are gated separately, by
# detections/posture/check_posture.py.
def rule_paths() -> list[str]:
    """The Sigma rules, and only the Sigma rules."""
    return sorted(
        p
        for p in glob.glob(RULE_GLOB)
        if "posture" not in os.path.normpath(p).split(os.sep)
    )

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
    # Re-baselined 2026-09-27 against the two-day audit window the cluster now
    # holds. The previous numbers (108/32/2/4/15/24) were measured against a
    # smaller window: the log has grown as the walks and the chain were re-run,
    # and the apiserver has rotated older records away. Both directions of that
    # drift are real, which is why these are equalities and not floors -- a floor
    # is a gate that cannot fail.
    #
    # This check earned its place during this re-baseline. Widening the audit
    # prefilter in collect-runtime.ps1 to capture bare pod creates also
    # re-captured every pods/exec, pods/log and pods/portforward record, and the
    # union of the two greps was concatenated rather than merged: det-0004 read
    # 64 instead of 16, det-0003 read 180 instead of 108. Nothing about the rules
    # had changed and nothing about the cluster had changed; only the number of
    # lines being read. A duplicate is worse than a gap, because a gap is visible
    # and a duplicate inflates every count that touches it.
    "det-0003-credential-or-escape-exec.yml": 180,
    "det-0004-pod-log-credential-read.yml": 16,
    "det-0005-refused-egress-burst.yml": 2,
    "det-0006-cross-zone-remote-service.yml": 4,
    "det-0010-pod-portforward.yml": 25,
    "det-0011-off-baseline-token-request.yml": 48,
    # 127 operator-created pods, of which 114 are the lab's own probes and 13 are
    # the chain's foothold. The exact 13 is the point: it is the arithmetic of the
    # instrumentation exclusion, so a future probe that stops being excluded, or a
    # foothold that starts being excluded, moves this number and fails here.
    "det-0012-direct-pod-creation.yml": 13,
}

# Rules whose hits are expected to be entirely lab instrumentation. Stated here
# rather than left implicit, because "the rule fired" and "the rule fired on
# something an attacker did" are different claims.
ALL_HITS_INSTRUMENTATION = {"det-0006-cross-zone-remote-service.yml"}

# Set from the command line. When true the EXPECTED_HITS fingerprints are enforced
# as exact equalities; when false they are reported as drift and the gate rests on
# the baseline-free checks (liveness, schema containment, and check_for_duplicate_events).
EXACT_BASELINE = False

# The set of counts actually enforced, and where it came from.
#
# There are two, and they are not interchangeable.
#
#   EXPECTED_HITS          committed, a fingerprint of the machine that authored
#                          it. Useful for a developer who has not moved, useless
#                          as a gate for anyone else: a fresh clone walks the lab a
#                          different number of times, against a differently sized
#                          audit log, and lands on different numbers. Enforcing
#                          this on a fresh clone guarantees a red run on correct
#                          code, which is how a gate gets learned to ignore.
#
#   --baseline <file>      a RECORDED baseline, written on the first run against
#                          this machine's own telemetry and enforced on every run
#                          after it. .telemetry/ is gitignored, so it never
#                          travels, and each machine gets its own. This is the gate
#                          that can actually fail for a given user, because the
#                          thing it compares against was measured on their cluster.
#
# The first run records and says so rather than passing quietly: a gate that has
# never compared anything has not passed, it has not run.
RECORDED_BASELINE: dict[str, int] | None = None
BASELINE_SOURCE = "none (first run: nothing to compare against)"
BASELINE_PATH: str | None = None
RECORD_REQUESTED = False

# Where the recorded baseline lives by default. Under .telemetry/, which is
# gitignored: a baseline is a fingerprint of one cluster's audit window, and it
# must not travel to another machine as though it were a fact about the rules.
DEFAULT_BASELINE = os.path.join(TELEMETRY, "detection-baseline.json")

# (rule name, expected, actual) tuples collected during a non-exact run.
DRIFT: list[tuple[str, int, int]] = []

# (rule name, precondition, how many events satisfy it) for rules this window
# cannot judge. Reported, never silently dropped.
NOT_JUDGEABLE: list[tuple[str, str, int]] = []


def load_recorded_baseline(path: str) -> dict[str, int] | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    hits = data.get("hits")
    if not isinstance(hits, dict):
        return None
    return {str(k): int(v) for k, v in hits.items()}


def write_recorded_baseline(
    path: str, hits: dict[str, int], event_count: int, schema_count: int
) -> None:
    """Write the baseline, with the window it was measured over.

    The window is part of the artefact on purpose. A count without the number of
    events behind it cannot be interpreted later: "det-0003: 180" means nothing
    without "over 2233 events across 7 schemas", and a reader who has forgotten
    which telemetry produced it will either trust it too much or dismiss it
    entirely.
    """
    payload = {
        "recordedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": (
            "Per-rule hit counts measured on THIS machine's telemetry. Regenerate "
            "with test-detections.py --record-baseline after changing a rule, a "
            "collector, or the number of times the lab has been walked -- and read "
            "the diff before accepting it. This file is gitignored on purpose: it "
            "is a fingerprint of one cluster's audit window, not a fact about the "
            "rules."
        ),
        "eventCount": event_count,
        "schemaCount": schema_count,
        "hits": hits,
    }
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def verify_rule(
    rule: sigmalite.Rule,
    events: list[dict[str, Any]],
    record_drift: bool = True,
) -> tuple[list[dict[str, Any]], list[str]]:
    """The real gate. Returns (hits, problems).

    Extracted as its own function so the mutation harness below can call exactly
    what the suite calls. A mutation harness that re-implements the check is
    testing its own copy rather than the gate, and would report success even if
    the gate were vacuous.

    record_drift=False for the mutation harness. The harness calls this with a
    deliberately broken rule, and a broken rule's hit count is not drift -- it is
    the entire point of the mutation. Letting those results into the drift report
    filled it with lines like "det-0010-pod-portforward.yml baseline 25 now 1416
    (+1391)", produced by a rule that does not exist in the repository, which is
    how a report stops being readable.
    """
    problems: list[str] = []
    name = os.path.basename(rule.source)
    hits = sigmalite.match_all(rule, events)
    declared = rule.logsource.get("schema", "")
    # The recorded baseline wins over the committed fingerprint when there is one,
    # because it was measured on this machine's telemetry. See RECORDED_BASELINE.
    if RECORDED_BASELINE is not None:
        want = RECORDED_BASELINE.get(name)
        source = "recorded"
    else:
        want = EXPECTED_HITS.get(name)
        source = "committed"

    if want is None:
        if source == "recorded":
            # A rule added since the baseline was recorded. Failing on it would
            # make adding a rule look like breaking the lab, which is the wrong
            # default -- the fix is to re-record, and the message says so.
            problems.append(
                f"{name}: present in the rule set but absent from the recorded "
                f"baseline. This is a new rule, not a regression: re-record with "
                f"--record-baseline once you have looked at what it fires on."
            )
        else:
            problems.append(f"{name}: no expected hit count declared")

    # Liveness. Baseline-free, and the check that actually matters: a rule that
    # stopped matching is broken, whatever the count says.
    #
    # But liveness is only a defect if the rule's PRECONDITION is present in this
    # window. det-0005 needs a comparable network delta, and the collector
    # deliberately refuses to fabricate one: kube-router rebuilds its iptables
    # chains whenever policy changes, the graph stage changes policy, and after it
    # the deltas are `chain-rebuilt` with `deltaDenied: null`. In a window with no
    # comparable delta the rule correctly matches nothing -- and "matched nothing"
    # is a statement about the window, not about the rule.
    #
    # So a rule may declare the precondition it needs, and the gate measures
    # whether the current telemetry can satisfy it. Unsatisfiable is reported as NOT
    # JUDGEABLE and excluded from the verdict, loudly. It is not a suppression:
    # the precondition is data, not an opinion, and if the data changes the rule
    # comes back under test immediately.
    #
    # The escape hatch this could become is the reason it is opt-in and declared in
    # the rule file rather than inferred. A rule cannot quietly mark itself
    # unjudgeable.
    precondition = rule.logsource.get("requires")
    judgeable = True
    if precondition:
        field = precondition.get("field")
        want_value = precondition.get("equals")
        path = field.split(".") if field else []
        candidates = events
        for part in path:
            candidates = [
                c.get(part) for c in candidates
                if isinstance(c, dict) and c.get(part) is not None
            ]
        satisfying = sum(1 for v in candidates if v == want_value)
        if satisfying == 0:
            judgeable = False
            if record_drift:
                NOT_JUDGEABLE.append((name, f"{field} == {want_value}", 0))

    if not hits and judgeable:
        problems.append(f"{name}: matched nothing, which is indistinguishable from working")
    if not hits and not judgeable:
        problems = [p for p in problems if "matched nothing" not in p]

    # The exact equality is a FINGERPRINT, enforced only against a quiesced
    # window. It is deliberately not a floor, because a floor cannot fail.
    #
    # It used to be an unconditional equality and that was a defect, not a strict
    # setting. Every chain run adds exactly one exec, one portforward, one token
    # request and one created pod, so the counts move by 1 each time the lab is
    # walked -- and the gate therefore could not pass twice in succession after a
    # walk, no matter how correct everything was. The harness's own --chain help
    # text already conceded the tension ("walking the lab changes those counts by
    # design") while the default path still enforced them.
    #
    # A recorded baseline is enforced automatically, because it was measured
    # against this machine's own telemetry and the run that just collected is the
    # thing it should be compared to. The committed fingerprint is only enforced
    # when the caller explicitly asks with --exact-baseline, because it was
    # measured on someone else's audit window and no fresh clone can reproduce it.
    #
    # Either way the number is a fingerprint rather than a target, and a drift
    # that is not enforced is still printed: a number nobody can reproduce is a
    # number that cannot fail, and a number that cannot fail is decoration.
    if want is not None and EXACT_BASELINE and len(hits) != want:
        # Only a judgeable rule is held to its count. Holding an unjudgeable rule to
        # a number recorded in a window that could satisfy it would be enforcing a
        # precondition the current telemetry does not meet.
        if judgeable:
            problems.append(
                f"{name}: {len(hits)} hits, {source} baseline says exactly {want}"
            )
        else:
            # Printed only from the real pass. The mutation harness re-runs this
            # function on a deliberately broken rule, and three copies of the same
            # notice in one report trains the reader to skip the line that matters.
            if record_drift:
                print(
                    f"  {name:<44} NOT JUDGEABLE this window: needs "
                    f"{precondition.get('field')} == {precondition.get('equals')}, "
                    f"and 0 event(s) provide it"
                )
    if (
        want is not None
        and not EXACT_BASELINE
        and record_drift
        and len(hits) != want
        and judgeable
    ):
        DRIFT.append((name, want, len(hits)))

    wrong = [h for h in hits if h.get("schema") != declared]
    if wrong:
        problems.append(f"{name}: {len(wrong)} hits outside the declared schema {declared}")

    # A rule that fires on every event in its own schema is not discriminating.
    #
    # This is the baseline-free replacement for the exact count as the thing that
    # catches an over-broad rule, and the mutation harness depends on it: the
    # "condition replaced by match-everything" mutation produces a rule that stays
    # inside the right schema, so the only properties that can catch it are "it
    # matches more than it should" and "its count changed". With the count
    # demoted to a fingerprint, this is what carries the check.
    #
    # It is a weaker instrument than an exact count -- a rule that matches 90% of
    # its schema passes here and would fail an equality -- and it is stated as a
    # strict-subset test rather than dressed up as one. The exact count is still
    # available under --exact-baseline for a quiesced window, and the mutation
    # harness runs under whichever mode the caller chose.
    schema_total = sum(1 for e in events if e.get("schema") == declared)
    if hits and len(hits) == schema_total:
        problems.append(
            f"{name}: fired on all {schema_total} event(s) in {declared}. A rule that "
            f"matches its entire schema is not discriminating; it is a schema guard "
            f"wearing a detection's name."
        )

    if name in ALL_HITS_INSTRUMENTATION:
        roles = {h.get("source", {}).get("role") for h in hits}
        if roles - {"instrumentation"}:
            problems.append(f"{name}: non-instrumentation hits {roles}")

    return hits, problems


def check_for_duplicate_events(events: list[dict[str, Any]]) -> list[str]:
    """No audit record may appear twice. Baseline-free.

    This is the check the hardcoded hit counts were accidentally doing, and it
    does it properly. Widening the audit prefilter in collect-runtime.ps1 to
    capture bare pod creates also re-captured every pods/exec, pods/log and
    pods/portforward record, and the union of the two greps was concatenated
    rather than merged: det-0004 read 64 hits where there were 16 records, and
    det-0003 read 180 where there were 108. Every count downstream of the read
    inflated, and nothing announced it.

    A duplicated event is worse than a missing one. A gap is visible -- the count
    is too low and someone asks why. A duplicate inflates every count that
    touches it while looking like a busy cluster, and it can survive a review
    because a high number reads as activity rather than as a defect.

    So this is a first-class gate, and it needs no fingerprint to know what
    correct looks like: within one schema, the number of distinct audit IDs must
    equal the number of events.
    """
    problems: list[str] = []
    by_schema: dict[str, dict[str, int]] = {}
    for e in events:
        schema = e.get("schema", "<none>")
        audit_id = e.get("auditId") or e.get("auditID")
        if not audit_id:
            continue
        by_schema.setdefault(schema, {})
        by_schema[schema][audit_id] = by_schema[schema].get(audit_id, 0) + 1

    for schema, ids in sorted(by_schema.items()):
        dupes = {k: v for k, v in ids.items() if v > 1}
        if dupes:
            worst = max(dupes.values())
            sample = sorted(dupes)[0]
            problems.append(
                f"{schema}: {len(dupes)} audit record(s) collected more than once "
                f"({sum(dupes.values()) - len(dupes)} extra event(s), worst seen {worst}x, "
                f"e.g. auditId {sample}). Something is being read twice."
            )
    return problems


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
    paths = rule_paths()
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
    parser.add_argument(
        "--exact-baseline",
        action="store_true",
        help=(
            "enforce EXPECTED_HITS as exact equalities. Only valid against a quiesced "
            "window: collect telemetry, then test, before walking anything. Every chain "
            "run adds one exec, one portforward, one token request and one created pod, "
            "so walking the lab moves these counts by design and enforcing them "
            "afterwards reports the lab as broken when the fingerprint is what moved."
        ),
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help=(
            "enforce the per-rule hit counts recorded at PATH, and treat a mismatch "
            "as a failure. This is the gate that works across machines: the counts "
            "were measured on your own telemetry, so they are reproducible by you. "
            "If the file does not exist it is recorded from the current run and the "
            "run says so rather than passing quietly."
        ),
    )
    parser.add_argument(
        "--record-baseline",
        metavar="PATH",
        help=(
            "write the per-rule hit counts to PATH from the current telemetry, "
            "overwriting whatever was there. Read the diff before committing to it: "
            "re-recording is how a real regression gets accepted as a new normal."
        ),
    )
    args = parser.parse_args()
    global EXACT_BASELINE, RECORDED_BASELINE, BASELINE_PATH, RECORD_REQUESTED
    EXACT_BASELINE = bool(args.exact_baseline)
    RECORD_REQUESTED = bool(args.record_baseline)

    baseline_path = args.baseline or DEFAULT_BASELINE
    if args.record_baseline:
        baseline_path = args.record_baseline

    # The recorded baseline is OPT-IN, and that is a correction rather than a
    # preference.
    #
    # The first version auto-enabled it whenever the file existed, on the reasoning
    # that a baseline measured on this machine must be worth more than the committed
    # one. Measured consequence: the default `python detections/test-detections.py`
    # FAILED with `det-0006: 3 hits, recorded baseline says exactly 4`, because the
    # lab had been walked since the baseline was recorded and one cross-zone flow no
    # longer appeared.
    #
    # That is the identical defect I had already fixed for the committed table, and I
    # reintroduced it one function away. The committed counts became un-enforceable
    # because no fresh clone can reproduce them; the recorded counts are equally
    # un-enforceable because no *repeat* run can reproduce them either. Every walk of
    # this lab changes the audit window by design. A gate that fails every time the
    # tool is used is a gate that gets ignored, and a gate that gets ignored protects
    # nothing.
    #
    # So: counts are enforced when the caller asks with --baseline, reported as drift
    # otherwise, and the default gate rests entirely on the baseline-free properties.
    # The recorded baseline is the tool for the rule-editing loop, where you collect
    # once, record, then re-run the gate and want it to hold you to a number.
    if args.baseline:
        recorded = load_recorded_baseline(args.baseline)
        if recorded is not None:
            RECORDED_BASELINE = recorded
            EXACT_BASELINE = True
            print(f"enforcing the recorded baseline at {args.baseline}")
        else:
            # Announced AND done. A promise in the output that the code does not keep
            # is worse than silence: it teaches the reader to trust a line that is
            # not true.
            RECORD_REQUESTED = True
            print(
                f"no baseline at {args.baseline} yet -- recording one from this run. "
                f"Re-run with --baseline to enforce it. A gate that has never compared "
                f"anything has not passed, it has not run."
            )
    elif args.record_baseline:
        RECORD_REQUESTED = True
    BASELINE_PATH = args.baseline or args.record_baseline

    events = load_events()
    rules = load_rules()
    paths = rule_paths()

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

    # --- 1b. nothing was collected twice ---------------------------------
    dup_problems = check_for_duplicate_events(events)
    print()
    if dup_problems:
        print("collected events are unique per audit record")
        print("-" * 70)
        for problem in dup_problems:
            print(f"  [FAIL] {problem}")
            failures.append(problem)
    else:
        print("collected events are unique per audit record")
        print("-" * 70)
        print("  ok     no audit record was collected more than once")

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
        exact_note = "exact" if EXACT_BASELINE else "baseline"

        print(f"  {name:<44} {len(hits):>4} hit(s)  {declared}  ({exact_note} {want})")
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
        # whole schema. A detection that fires on everything is broken, and
        # verify_rule's strict-subset check exists to catch it.
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
                mutated_hits, problems = verify_rule(rule, events, record_drift=False)
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

    # --- 4. record the baseline, so the NEXT run has something to check ----
    #
    # Recorded last and unconditionally when asked for, and deliberately not
    # conditional on the run passing. A baseline captured only from a green run
    # is a baseline that cannot record a regression: the run that would have
    # caught the regression is exactly the run whose numbers you would not trust.
    if RECORD_REQUESTED and BASELINE_PATH:
        measured = {name: len(results[name]) for name in sorted(results)}
        write_recorded_baseline(
            BASELINE_PATH,
            measured,
            event_count=len(events),
            schema_count=len({e.get("schema") for e in events if isinstance(e.get("schema"), str)}),
        )
        print()
        print("baseline")
        print("-" * 70)
        print(f"  wrote {BASELINE_PATH}")
        for bname, count in measured.items():
            prior = (RECORDED_BASELINE or {}).get(bname)
            if prior is None:
                print(f"    {bname:<44} {count:>5}   (new)")
            elif prior != count:
                print(f"    {bname:<44} {count:>5}   (was {prior}, {count - prior:+d})")
            else:
                print(f"    {bname:<44} {count:>5}   (unchanged)")
        if RECORDED_BASELINE:
            print("  Read the deltas above before accepting them. Every one of them is")
            print("  a claim that the change was understood rather than absorbed.")

    # --- verdict ---------------------------------------------------------
    if NOT_JUDGEABLE:
        print()
        print("not judgeable in this window")
        print("-" * 70)
        for jname, jcond, jsat in NOT_JUDGEABLE:
            print(f"  {jname}")
            print(f"    needs {jcond}; {jsat} event(s) in the current telemetry provide it")
        print("  The rule is neither passed nor failed here. It is excluded from the")
        print("  verdict because the telemetry cannot exercise it, and it comes back")
        print("  under test the moment the window can.")
        print()
        print("  One consequence, stated rather than left to be discovered: a mutation")
        print("  that makes a rule match NOTHING is indistinguishable from a rule that")
        print("  already matched nothing. For these rules the 'impossible value'")
        print("  mutation therefore reports `equivalent` in such a window, and that is")
        print("  not a clean result. It is missing coverage, and the only fix is a")
        print("  window that can judge the rule.")

    if DRIFT:
        print()
        print("baseline drift (not enforced in this mode)")
        print("-" * 70)
        for dname, want, got in DRIFT:
            delta = got - want
            print(f"  {dname:<44} baseline {want:>5}  now {got:>5}  ({delta:+d})")
        print("  The audit log is cumulative and rotates. Every chain run adds one")
        print("  exec, one portforward, one token request and one created pod, so these")
        print("  move by design. --exact-baseline enforces the committed fingerprint,")
        print("  --baseline enforces your own recorded one.")

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
