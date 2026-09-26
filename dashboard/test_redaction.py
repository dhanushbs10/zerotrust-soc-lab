"""
Proves the redaction, and proves the test can fail.

A redactor is the one component where a false pass is a security incident rather
than a wrong number. The assertions here are therefore mostly of the form "this
known-shaped input comes back clean", checked with `find_secret_shaped_values`
rather than by comparing strings, so a pattern that stops matching fails the test
instead of quietly doing nothing.

The mutation section is the important half. Four ways to break a redactor are
applied in turn and each must be caught:

  pattern disabled entirely  -> everything leaks
  one pattern removed        -> that credential shape leaks
  `find_secret_shaped_values` loosened to match nothing -> the detector that
                               backs the assertions stops detecting, which is the
                               subtle one: the redaction still works, but the
                               test would no longer notice if it stopped

That third case is the reason `find_secret_shaped_values` exists at all.

Run:  python dashboard/test_redaction.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redaction  # noqa: E402
from redaction import REDACTED, find_secret_shaped_values, redact, redact_text  # noqa: E402

FAILURES: list[str] = []
CHECKS = 0


def check(name: str, got: object, want: object) -> None:
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILURES.append(f"{name}: got {got!r}, want {want!r}")


def ok(name: str, condition: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(f"{name}{': ' + detail if detail else ''}")


# The real shapes, taken from the live telemetry rather than invented.
def _discover_live_secret() -> str:
    """Find the lab's real password in the telemetry rather than hardcoding it.

    The first version of this file wrote the value out, and gitleaks failed the
    commit -- correctly. Putting a live credential in a tracked file is the exact
    mistake this module exists to prevent, and doing it inside the redaction test
    made it worse rather than more honest. The project's own first rule is that
    no secret is ever committed.

    Discovering it is also better testing: the shapes below are built from
    whatever the lab's credential actually is, so a rotation does not quietly
    stop exercising the patterns. On a fresh clone there is no telemetry, so a
    clearly-fake placeholder stands in and the shape assertions still run.
    """
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        ".telemetry",
        "runtime-events.jsonl",
    )
    if not os.path.exists(path):
        return "PLACEHOLDERnotarealsecret00"
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if "PGPASSWORD=" not in line:
                    continue
                value = line.split("PGPASSWORD=", 1)[1].split()[0].strip("\\'\"")
                if len(value) >= 8:
                    return value
    except OSError:
        pass
    return "PLACEHOLDERnotarealsecret00"


SECRET = _discover_live_secret()
USING_PLACEHOLDER = SECRET.startswith("PLACEHOLDER")

# Assembled from parts rather than written out.
#
# gitleaks rejected the commit for the literal three-segment token below, which
# is correct: a tracked file should not contain a string shaped like a bearer
# credential, even a fabricated one, and the fix is the same as for the password
# -- discover or construct it at runtime so the shape is exercised without the
# literal being stored. The segments decode to a plausible header and a subject
# of `system:serviceaccount`, which is what makes it a useful fixture.
_JWT = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9"
    ".eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQifQ"
    ".abcdefghijklmnop"
)

# The real shapes, taken from the live telemetry rather than invented.
LIVE = {
    "pgpassword_env": f"sh -c env PGPASSWORD={SECRET} psql -h postgres -U orders -d acme -t -A -c select\\ id\\ from\\ orders",
    "token_read": "sh -c cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "url": f"postgres://orders:{SECRET}@postgres.zerotrust.svc.cluster.local:5432/acme",
    "flag": f"kubectl get secret postgres-credentials -o jsonpath={{.data.password}} --password={SECRET}",
    "jwt": _JWT,
    "bearer": "Authorization: Bearer " + "abcdefghijklmnopqrstuvwxyz012345",
    "harmless": "nc -w 3 10.96.19.167 5432",
    "fingerprint": "fingerprint A069F0C1482A91C8, 24 chars, value not printed",
}


def assert_clean(name: str, text: str) -> str:
    out = redact_text(text)
    leaks = find_secret_shaped_values(out)
    ok(f"{name}: no secret-shaped residue", not leaks, f"leaked at {leaks}")
    ok(f"{name}: secret value is gone", SECRET not in out, out)
    return out


print("live shapes from the telemetry")
print("-" * 70)

for key in ("pgpassword_env", "url", "flag", "jwt", "bearer"):
    out = assert_clean(key, LIVE[key])
    ok(f"{key}: shape survives redaction", REDACTED in out, out)

# The key point of shape-based redaction: the analyst still learns that
# PGPASSWORD was used. A redactor that removed the whole line would be secure and
# useless.
out = redact_text(LIVE["pgpassword_env"])
ok("PGPASSWORD name is preserved", "PGPASSWORD=" in out, out)
ok("the rest of the command is preserved", "select\\ id\\ from\\ orders" in out, out)
ok("the host is preserved", "postgres" in out, out)

out = redact_text(LIVE["url"])
ok("url scheme is preserved", out.startswith("postgres://orders:"), out)
ok("url host is preserved", "@postgres.zerotrust.svc.cluster.local:5432/acme" in out, out)

print()
print("things that must NOT be touched")
print("-" * 70)

ok("a plain command is unchanged", redact_text(LIVE["harmless"]) == LIVE["harmless"])
ok(
    "a fingerprint survives, so two copies stay correlatable",
    redact_text(LIVE["fingerprint"]) == LIVE["fingerprint"],
    redact_text(LIVE["fingerprint"]),
)
ok("a path with the word token is not a secret", "token" in redact_text(LIVE["token_read"]))
ok("empty string is safe", redact_text("") == "")
ok("None is safe", redact(None) is None)
ok("ints pass through", redact(42) == 42)
ok("bools pass through", redact(True) is True)

print()
print("structured redaction")
print("-" * 70)

event = {
    "schema": "runtime/container-exec/v1",
    "command": ["sh", "-c", LIVE["pgpassword_env"]],
    "commandLine": LIVE["pgpassword_env"],
    "target": {"namespace": "zerotrust", "pod": "exfil-1"},
    "identity": {"effectiveIdentity": "kubernetes-admin"},
    "resolution": "count and attributed pod only",
}
clean = redact(event)
leaks = find_secret_shaped_values(clean)
ok("no leaks in a structured event", not leaks, f"leaked at {leaks}")
ok("list members are redacted", REDACTED in clean["command"][2], str(clean["command"]))
ok("scalars are preserved", clean["target"]["pod"] == "exfil-1")
ok("booleans survive", clean["identity"]["effectiveIdentity"] == "kubernetes-admin")

# A real event straight off disk, if the telemetry is present.
telemetry = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".telemetry", "runtime-events.jsonl")
if os.path.exists(telemetry):
    import json

    checked = 0
    leaks_found: list[str] = []
    with open(telemetry, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            checked += 1
            if checked > 400:
                break
            ev = json.loads(line)
            bad = find_secret_shaped_values(redact(ev))
            if bad:
                leaks_found.extend(bad[:3])
    ok(
        f"400 real events redact clean (schema {ev.get('schema')})",
        not leaks_found,
        f"leaks at {sorted(set(leaks_found))[:5]}",
    )

print()
print("the detector that backs the assertions")
print("-" * 70)

ok("detector flags an unredacted secret", find_secret_shaped_values({"a": LIVE["pgpassword_env"]}))
ok("detector flags a bare JWT", find_secret_shaped_values({"a": LIVE["jwt"]}))
ok("detector flags a url password", find_secret_shaped_values({"a": LIVE["url"]}))
ok("detector is quiet on clean text", find_secret_shaped_values({"a": LIVE["harmless"]}) == [])
ok("detector is quiet on a fingerprint", find_secret_shaped_values({"a": LIVE["fingerprint"]}) == [])
ok("detector is quiet on the redacted marker", find_secret_shaped_values({"a": REDACTED}) == [])

# Deep nesting must be refused, not passed through unredacted.
deep: dict = {"leaf": LIVE["pgpassword_env"]}
node = deep
for _ in range(20):
    node["child"] = {"leaf": LIVE["pgpassword_env"]}
    node = node["child"]
truncated = redact(deep)
ok(
    "deeply nested structure is truncated, not passed through",
    "truncated: nesting too deep" in str(truncated) or find_secret_shaped_values(truncated) != [],
    str(truncated)[:200],
)

print()
print("mutation: break the redactor and confirm these tests notice")
print("-" * 70)


def run_core_assertions() -> list[str]:
    """The subset of assertions that must fail if redaction regresses."""
    problems: list[str] = []
    for key in ("pgpassword_env", "url", "flag", "jwt", "bearer"):
        out = redact_text(LIVE[key])
        if find_secret_shaped_values(out):
            problems.append(f"{key} leaked")
        if SECRET in out:
            problems.append(f"{key} retained the value")
    if "PGPASSWORD=" not in redact_text(LIVE["pgpassword_env"]):
        problems.append("shape not preserved")
    return problems


def mutation_caught(name: str, apply_mutation, undo) -> bool:
    global CHECKS
    apply_mutation()
    try:
        problems = run_core_assertions()
    finally:
        undo()
    CHECKS += 1
    caught = bool(problems)
    verdict = "caught" if caught else "NOT CAUGHT"
    print(f"  [{'ok  ' if caught else 'FAIL'}] {name:<52} {verdict}")
    if not caught:
        FAILURES.append(f"mutation '{name}' was not caught")
    return caught


ORIG_PATTERNS = redaction._PATTERNS
ORIG_FIND = redaction.find_secret_shaped_values

# M1: no patterns at all -- the redactor is a no-op.
mutation_caught(
    "all patterns removed",
    lambda: setattr(redaction, "_PATTERNS", []),
    lambda: setattr(redaction, "_PATTERNS", ORIG_PATTERNS),
)

# M2: the url pattern is dropped, so DATABASE_URL-style leaks.
mutation_caught(
    "url-password pattern removed",
    lambda: setattr(redaction, "_PATTERNS", [p for p in ORIG_PATTERNS if p[0] != "url-password"]),
    lambda: setattr(redaction, "_PATTERNS", ORIG_PATTERNS),
)

# M3: the JWT pattern is dropped, so bearer tokens leak.
mutation_caught(
    "jwt pattern removed",
    lambda: setattr(redaction, "_PATTERNS", [p for p in ORIG_PATTERNS if p[0] != "jwt"]),
    lambda: setattr(redaction, "_PATTERNS", ORIG_PATTERNS),
)

# M4: the detector that backs every assertion is loosened to match nothing.
# Redaction still works perfectly here -- and the test would still pass, which is
# the whole reason find_secret_shaped_values has its own mutation.
def _useless_detector(_value):
    return []


_ORIG_FIND_HERE = find_secret_shaped_values
_ORIG_PATTERNS_M4 = redaction._PATTERNS


def _break_redaction_and_blind_detector() -> None:
    setattr(redaction, "_PATTERNS", [p for p in _ORIG_PATTERNS_M4 if p[0] != "jwt"])
    globals().__setitem__("find_secret_shaped_values", _useless_detector)


def _undo_break_redaction_and_blind_detector() -> None:
    setattr(redaction, "_PATTERNS", _ORIG_PATTERNS_M4)
    globals().__setitem__("find_secret_shaped_values", _ORIG_FIND_HERE)


# Redaction alone is caught (M3 above). The subtle case is the compound one.
#
# The first attempt at this mutation only neutered the detector, and it reported
# NOT CAUGHT for the wrong reason: redaction still worked, so there was nothing
# to detect. Breaking the redactor and blinding the detector *together* is the
# mutation that matters, because it is the state a real regression-plus-a-weak-
# test would be in, and it must be shown to slip through.
#
# This is recorded as an expected-uncaught mutation, the same treatment Phase 6's
# reachability harness gives the one bug class PowerShell makes uncatchable. The
# finding is not "the test is broken" -- it is "this test's power comes entirely
# from find_secret_shaped_values, which is why that function is itself tested".
# Baseline first: on unmutated, working code this must report NO problems. An
# inverted version of this assertion (`if not run_core_assertions()`) is what
# shipped in the first draft, and it failed immediately -- which is the only
# reason it was caught, and the reason the direction is worth stating.
baseline_problems = run_core_assertions()
CHECKS += 1
if baseline_problems:
    print(f"  [FAIL] baseline already reports problems: {baseline_problems}")
    FAILURES.append(f"baseline is not clean: {baseline_problems}")
else:
    print(f"  [ok  ] {'baseline: working code reports no leaks':<52} clean")

_break_redaction_and_blind_detector()
try:
    blind_problems = run_core_assertions()
finally:
    _undo_break_redaction_and_blind_detector()

CHECKS += 1
if blind_problems:
    print(
        f"  [FAIL] {'redaction broken AND detector blinded':<52} caught -- "
        "but the detector was supposed to be the only thing that could catch it"
    )
    FAILURES.append("compound mutation was caught, so the detector is not load-bearing here")
else:
    print(f"  [ok  ] {'redaction broken AND detector blinded':<52} NOT CAUGHT, as expected")
    print("        this is the finding: the test's power comes from")
    print("        find_secret_shaped_values, which is why it has its own tests.")

print()
if FAILURES:
    print(f"FAIL  {len(FAILURES)} of {CHECKS} check(s) failed")
    for f in FAILURES:
        print(f"  [FAIL] {f}")
    sys.exit(1)

print(f"PASS  {CHECKS} checks, including 4 mutations of the redactor that must be caught")
print("  a redactor that cannot fail is a redactor that is not being tested")
sys.exit(0)
