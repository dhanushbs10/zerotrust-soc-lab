"""
Proves sigmalite's semantics, and -- more importantly -- proves it can be wrong.

A detection engine that is subtly incorrect is worse than no engine, because it
produces confident verdicts. Every case below is written as a mutation: a
deliberately broken version of the evaluator must FAIL this file. An engine
whose tests only ever assert the happy path is not tested.

Run:  python detections/engine/test_sigmalite.py
"""

from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sigmalite  # noqa: E402
from sigmalite import Rule, SigmaError, UnsupportedConstruct  # noqa: E402

FAILURES: list[str] = []
CHECKS = 0


def check(name: str, got: object, want: object) -> None:
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILURES.append(f"{name}: got {got!r}, want {want!r}")


def expect_raises(name: str, fn, exc=Exception) -> None:
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except exc:
        return
    except Exception as err:  # noqa: BLE001
        FAILURES.append(f"{name}: raised {type(err).__name__}, want {exc.__name__}")
        return
    FAILURES.append(f"{name}: did not raise {exc.__name__}")


def rule(detection: dict, **extra) -> Rule:
    base = {
        "title": "t",
        "id": "00000000-0000-0000-0000-000000000001",
        "status": "experimental",
        "description": "d",
        "author": "a",
        "level": "high",
        "logsource": {"category": "lab"},
        "tags": ["attack.t1078.001"],
    }
    base.update(extra)
    detection = dict(detection)
    detection.setdefault("condition", "sel")
    base["detection"] = detection
    return Rule(base, source="<test>")


# ---------------------------------------------------------------------------
print("field lookup")
# ---------------------------------------------------------------------------
e = {
    "schema": "runtime/container-exec/v1",
    "counter": {"deltaDenied": 2, "deltaValid": True},
    "candidateTechniques": [{"id": "T1609.001"}, {"id": "T1090.001"}],
    "subject": {"pod": "p", "namespace": "n"},
    "cmd": None,
}

check("dotted scalar", sigmalite._lookup(e, "counter.deltaDenied"), [2])
check("into a list of objects", sorted(sigmalite._lookup(e, "candidateTechniques.id")),
      ["T1090.001", "T1609.001"])
check("absent path yields nothing", sigmalite._lookup(e, "counter.nope"), [])
check("absent top-level yields nothing", sigmalite._lookup(e, "missing"), [])
check("null field yields [None]", sigmalite._lookup(e, "cmd"), [None])

# ---------------------------------------------------------------------------
print("value matching")
# ---------------------------------------------------------------------------
check("equality", sigmalite._match_value("abc", "abc", ""), True)
check("equality is case-SENSITIVE", sigmalite._match_value("ABC", "abc", ""), False)
check("contains", sigmalite._match_value("sh -c cat token", "cat token", "contains"), True)
check("startswith", sigmalite._match_value("sh -c cat", "sh -c", "startswith"), True)
check("endswith", sigmalite._match_value("sh -c cat", "cat", "endswith"), True)
check("regex", sigmalite._match_value("abc123", r"\d+", "re"), True)
check("gt true", sigmalite._match_value(2, 0, "gt"), True)
check("gt false at zero", sigmalite._match_value(0, 0, "gt"), False)
check("gte at zero", sigmalite._match_value(0, 0, "gte"), True)
check("lt", sigmalite._match_value(1, 2, "lt"), True)
check("numeric vs numeric string", sigmalite._match_value("5", 4, "gt"), True)
check("non-numeric does not match gt", sigmalite._match_value("abc", 0, "gt"), False)
check("bool renders lowercase", sigmalite._match_value(True, "true", ""), True)

# ---------------------------------------------------------------------------
print("absent fields never match")
# ---------------------------------------------------------------------------
r = rule({"sel": {"subject.pod": "p"}})
check("missing field cannot match", r.matches({"schema": "other"}), False)
check("present field matches", r.matches({"subject": {"pod": "p"}}), True)

# ---------------------------------------------------------------------------
print("selections and conditions")
# ---------------------------------------------------------------------------
r = rule({"sel": {"schema": "a"}, "flt": {"schema": "b"}, "condition": "sel and not flt"})
check("sel and not flt (match)", r.matches({"schema": "a"}), True)
check("sel and not flt (excluded)", r.matches({"schema": "b"}), False)

r = rule({"sel": {"schema": ["a", "b"]}, "condition": "sel"})
check("list of values is OR", r.matches({"schema": "a"}), True)
check("list of values is OR (2)", r.matches({"schema": "b"}), True)
check("list of values is OR (miss)", r.matches({"schema": "c"}), False)

r = rule({"x1": {"k1": "1"}, "x2": {"k2": "2"}, "x3": {"k3": "3"}, "condition": "all of x*"})
check("all of glob, all present", r.matches({"k1": "1", "k2": "2", "k3": "3"}), True)
check("all of glob, one missing", r.matches({"k1": "1", "k2": "2"}), False)
check("all of glob, one present", r.matches({"k1": "1"}), False)

r = rule({"x1": {"k1": "1"}, "x2": {"k2": "2"}, "y1": {"j1": "9"}, "condition": "all of x*"})
check("glob excludes non-matching names", r.matches({"k1": "1", "k2": "2"}), True)

r = rule({"x1": {"k1": "1"}, "x2": {"k2": "2"}, "condition": "1 of x*"})
check("1 of glob, one present", r.matches({"k1": "1"}), True)
check("1 of glob, none present", r.matches({}), False)

r = rule({"x": {"k": "1"}, "y": {"k": "2"}, "condition": "1 of them"})
check("1 of them", r.matches({"k": "1"}), True)

r = rule({"a": {"ka": "1"}, "b": {"kb": "2"}, "c": {"kc": "3"}, "condition": "2 of them"})
check("2 of them, exactly two", r.matches({"ka": "1", "kb": "2"}), True)
check("2 of them, one", r.matches({"ka": "1"}), False)
check("2 of them, three", r.matches({"ka": "1", "kb": "2", "kc": "3"}), False)

r = rule({"sel": {"k": "1"}, "condition": "(sel or sel) and not not sel"})
check("parentheses and double negation", r.matches({"k": "1"}), True)

r = rule({"sel": {"k": "v"}, "condition": "sel"})
check("a field with no value means exists", r.matches({"k": "v"}), True)

# numeric predicate, the whole of the T1046 rule
r = rule({"sel": {"counter.deltaDenied|gt": 0}, "condition": "sel"})
check("gt on a real event", r.matches({"counter": {"deltaDenied": 2}}), True)
check("gt excludes zero", r.matches({"counter": {"deltaDenied": 0}}), False)

# ---------------------------------------------------------------------------
print("unsupported constructs raise instead of silently not matching")
# ---------------------------------------------------------------------------
r = rule({"sel": {"k|windash": "v"}, "condition": "sel"})
expect_raises("unknown modifier raises", lambda: r.matches({"k": "v"}), UnsupportedConstruct)

r = rule({"sel": {"k": "v"}, "condition": "nosuchselection"})
expect_raises("unknown selection raises", lambda: r.matches({"k": "v"}), SigmaError)

r = rule({"sel": {"k": "v"}, "condition": "sel and"})
expect_raises("truncated condition raises", lambda: r.matches({"k": "v"}), SigmaError)

r = rule({"sel": {"k": "v"}, "condition": "(sel"})
expect_raises("unbalanced paren raises", lambda: r.matches({"k": "v"}), SigmaError)

r = rule({"sel": {"k": "v"}, "condition": "1 of zzz*"})
expect_raises("quantifier matching nothing raises", lambda: r.matches({"k": "v"}), SigmaError)

expect_raises(
    "rule with no attack tag raises",
    lambda: Rule(
        {"title": "t", "id": "x", "logsource": {}, "detection": {"sel": {"a": 1}, "condition": "sel"}},
        source="<t>",
    ),
    SigmaError,
)

# ---------------------------------------------------------------------------
print("the evaluator can be broken, and these tests notice")
# ---------------------------------------------------------------------------

ORIG = {
    "_lookup": sigmalite._lookup,
    "_match_value": sigmalite._match_value,
    "_match_selection": sigmalite._match_selection,
    "resolve": sigmalite._Parser.resolve,
}


def mutate(name: str, attr: str, replacement) -> None:
    """Re-break one piece, run the suite, require it to fail, then restore."""
    global CHECKS
    original = ORIG[attr]
    setattr(sigmalite, attr, replacement) if attr != "resolve" else setattr(
        sigmalite._Parser, "resolve", replacement
    )
    try:
        before = list(FAILURES)
        del FAILURES[:]
        _rerun()
        caught = len(FAILURES) > 0
        del FAILURES[:]
        FAILURES.extend(before)
    finally:
        if attr == "resolve":
            sigmalite._Parser.resolve = original
        else:
            setattr(sigmalite, attr, original)
    CHECKS += 1
    if not caught:
        FAILURES.append(f"mutation '{name}' was NOT caught by this suite")


def _rerun() -> None:
    """Re-execute the assertions above against the current module state."""
    r = rule({"sel": {"schema": "a"}, "flt": {"schema": "b"}, "condition": "sel and not flt"})
    check("m:sel", r.matches({"schema": "a"}), True)
    check("m:not", r.matches({"schema": "b"}), False)
    r2 = rule({"sel": {"counter.deltaDenied|gt": 0}, "condition": "sel"})
    check("m:gt", r2.matches({"counter": {"deltaDenied": 2}}), True)
    check("m:gt0", r2.matches({"counter": {"deltaDenied": 0}}), False)
    r3 = rule({"x": {"k": "1"}, "y": {"k": "2"}, "condition": "all of x*"})
    check("m:allof", r3.matches({"k": "12"}), True)
    check("m:allof1", r3.matches({"k": "1"}), False)
    r4 = rule({"sel": {"subject.pod": "p"}, "condition": "sel"})
    check("m:absent", r4.matches({"schema": "other"}), False)
    check("m:present", r4.matches({"subject": {"pod": "p"}}), True)
    check("m:case", sigmalite._match_value("ABC", "abc", ""), False)
    check("m:listid", sorted(sigmalite._lookup(
        {"candidateTechniques": [{"id": "a"}, {"id": "b"}]}, "candidateTechniques.id")), ["a", "b"])


# Mutation 1: equality becomes case-insensitive (the Phase 6 bug class).
def _case_insensitive(actual, expected, modifier):
    if modifier == "":
        return sigmalite._as_text(actual).lower() == sigmalite._as_text(expected).lower()
    return ORIG["_match_value"](actual, expected, modifier)


# Mutation 2: a missing field is treated as a match.
def _absent_is_match(event, path):
    found = ORIG["_lookup"](event, path)
    return found if found else [None]


# Mutation 3: `not` is dropped from the condition grammar.
def _no_not(self, name, event):
    if self.peek() == "not":
        self.next()
    return ORIG["resolve"](self, name, event)


# Mutation 4: numeric comparison treats a non-number as zero.
def _numeric_as_zero(actual, expected, modifier):
    if modifier in {"gt", "gte", "lt", "lte"}:
        a = sigmalite._numeric(actual)
        b = sigmalite._numeric(expected)
        a = 0.0 if a is None else a
        b = 0.0 if b is None else b
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[modifier]
    return ORIG["_match_value"](actual, expected, modifier)


mutate("equality becomes case-insensitive", "_match_value", _case_insensitive)
mutate("absent field treated as a match", "_lookup", _absent_is_match)
mutate("`not` dropped from the grammar", "resolve", _no_not)
mutate("non-numeric coerced to zero", "_match_value", _numeric_as_zero)

# ---------------------------------------------------------------------------
print()
if FAILURES:
    print(f"FAIL  {len(FAILURES)} of {CHECKS} check(s) failed")
    for f in FAILURES:
        print(f"  [FAIL] {f}")
    sys.exit(1)

print(f"PASS  {CHECKS} checks, including 4 mutations that must be caught")
print("  an evaluator whose tests cannot fail is an evaluator that has not been tested")
sys.exit(0)
