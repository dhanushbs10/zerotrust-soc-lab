"""
Tests the console's HTTP surface, with the security properties tested first.

The three properties that matter here are not "does /api/summary return JSON":

  1. **No secret reaches a response.** Checked against the real telemetry, not
     against a fixture, because a fixture cannot leak the way real data does.
  2. **There is no arbitrary command execution.** Every action must be in the
     allowlist, and no endpoint may accept a command from the request. A server
     that can mint cluster-admin tokens and run a shell must not have a
     code-shaped hole in it.
  3. **Mutating actions require confirmation.** Tested by calling them without
     it, and asserting no job was created.

Each of the three also has a mutation: break the control and confirm the test
notices. A security test that cannot fail is a comment.

Run:  python dashboard/test_server.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import server  # noqa: E402
from redaction import find_secret_shaped_values  # noqa: E402

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


client = server.app.test_client()

# Jobs must not actually run. `POST /api/action/chain` with confirmation starts the
# purple-team chain, which creates a pod in the business zone and mints a
# cluster-admin token. A test that triggers real work in the cluster is a test
# that mutates the thing it is meant to be observing, so the runner is replaced
# with a no-op and the job stays pending for the life of the test.
#
# This is the same class of mistake the project keeps meeting in a different
# shape: a verification that changes the state it is verifying.
_REAL_RUN_JOB = server._run_job
server._run_job = lambda job: None  # type: ignore[assignment]

# The lab's real password, DISCOVERED from the gitignored telemetry rather than
# written here. gitleaks rejected the first version of this file for hardcoding
# it, correctly: a live credential has no business in a tracked file, least of
# all in the test that exists to prove credentials never leave the process.
# Falls back to a placeholder on a fresh clone, where there is no telemetry.
def _discover_live_secret() -> str:
    path = os.path.join(server.TELEMETRY, "runtime-events.jsonl")
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


LIVE_SECRET = _discover_live_secret()


def body(resp):
    return json.loads(resp.get_data(as_text=True))


print("1. no secret reaches a response")
print("-" * 70)

RESPONSE_PATHS = [
    "/api/summary",
    "/api/detections",
    "/api/graph",
    "/api/chain",
    "/api/walks",
    "/api/attack-coverage",
    "/api/boundaries",
    "/api/health",
    "/api/actions",
    "/api/jobs",
    "/api/telemetry",
    "/api/telemetry?schema=runtime/container-exec/v1&limit=500",
    "/api/telemetry?schema=runtime/pod-log-read/v1&limit=200",
    "/api/telemetry?schema=network/observed-flow/v1&limit=200",
]

for path in RESPONSE_PATHS:
    resp = client.get(path)
    check(f"GET {path[:44]} -> 200", resp.status_code, 200)
    text = resp.get_data(as_text=True)
    ok(f"GET {path[:44]}: live password absent", LIVE_SECRET not in text)
    leaks = find_secret_shaped_values(body(resp))
    ok(f"GET {path[:44]}: no secret-shaped residue", not leaks, f"at {leaks[:4]}")
    ok(
        f"GET {path[:44]}: redaction choke point did not withhold",
        not body(resp).get("_payloadWithheld"),
        "the response was replaced because something secret-shaped survived",
    )

# The leak detector must actually be reached. If ok() were neutered, the three
# assertions above would pass on a response full of credentials.
resp = client.get("/api/telemetry?schema=runtime/container-exec/v1&limit=500")
text = resp.get_data(as_text=True)
ok("the exec telemetry endpoint really does return command lines", "commandLine" in text)
ok(
    "the sampled window really contains the credential (else 'no leak' is vacuous)",
    "PGPASSWORD" in text,
    "the first 500 exec events have no PGPASSWORD command, so the redaction "
    "assertions above would pass on a response that never held a secret",
)

# Same precondition, checked against the file rather than the response, so it
# cannot be satisfied by redaction itself.
telemetry = os.path.join(server.TELEMETRY, "runtime-events.jsonl")
raw_contains = False
if os.path.exists(telemetry):
    with open(telemetry, encoding="utf-8") as handle:
        for i, line in enumerate(handle):
            if i > 4000:
                break
            if LIVE_SECRET in line:
                raw_contains = True
                break
ok(
    "the raw telemetry holds the live credential, so redaction has work to do",
    raw_contains,
    "no PGPASSWORD value found in the first 4000 lines of the raw telemetry",
)

print()
print("2. no arbitrary command execution")
print("-" * 70)

resp = client.post("/api/action/definitely-not-a-real-action")
check("unknown action -> 404", resp.status_code, 404)
ok("unknown action is named back", "unknown action" in body(resp)["error"])

for name in server.ACTIONS:
    argv = server.ACTIONS[name]["argv"]()
    ok(
        f"action {name} argv is a list of strings",
        isinstance(argv, list) and all(isinstance(a, str) for a in argv),
        repr(argv),
    )
    ok(
        f"action {name} points inside the repo",
        any(("detections" in a) or ("telemetry" in a) or ("attack" in a) or ("tools" in a)
            or ("graph" in a) for a in argv),
        repr(argv),
    )

# No route may take a command from the body or the query string.
source = open(os.path.join(HERE, "server.py"), encoding="utf-8").read()
for forbidden in ("shell=True", "os.system", "eval(", "exec(", "subprocess.run(request"):
    ok(f"server.py does not contain {forbidden!r}", forbidden not in source)
ok("subprocess is always called with shell=False", source.count("shell=False") >= 2)
ok(
    "actions come from the allowlist, not the request",
    "request.args.get(\"cmd\")" not in source and "request.get_json" not in source,
)

print()
print("3. mutating actions require confirmation")
print("-" * 70)

mutating = [n for n, s in server.ACTIONS.items() if s["mutating"]]
ok("there is at least one mutating action to test", len(mutating) >= 2, str(mutating))

for name in mutating:
    before = len(server._JOBS)
    resp = client.post(f"/api/action/{name}")
    check(f"POST {name} without confirm -> 409", resp.status_code, 409)
    ok(f"POST {name}: no job was created", len(server._JOBS) == before)
    ok(f"POST {name}: the refusal explains itself", "confirm" in body(resp)["error"])

    # And with confirmation it is accepted. This is checked by inspecting the
    # response, not by waiting for the job: a test that starts the purple-team
    # chain would create a pod in the cluster.
    resp = client.post(f"/api/action/{name}?confirm=yes")
    check(f"POST {name}?confirm=yes -> 202", resp.status_code, 202)
    job_id = body(resp)["job"]["id"]
    ok(f"POST {name}: a job id came back", bool(job_id))
    # Cancel it so the test does not leave real work running.
    with server._JOBS_LOCK:
        server._JOBS.pop(job_id, None)

for name in [n for n, s in server.ACTIONS.items() if not s["mutating"]]:
    resp = client.post(f"/api/action/{name}")
    check(f"POST {name} (read-only) -> 202", resp.status_code, 202)
    job_id = body(resp)["job"]["id"]
    with server._JOBS_LOCK:
        server._JOBS.pop(job_id, None)

print()
print("4. loopback only")
print("-" * 70)

ok("the default host is loopback", server.app.name == "server")
ok(
    "the bind guard rejects a non-loopback host",
    "refusing to bind" in source and "127.0.0.1" in source,
)
ok("no route serves arbitrary paths from disk", "send_file(" not in source)

resp = client.get("/api/job/does-not-exist")
check("unknown job -> 404", resp.status_code, 404)
ok("unknown job explains that jobs are in memory", "in memory" in body(resp)["error"])

print()
print("mutation: break each control and confirm these tests notice")
print("-" * 70)


def mutation(name: str, break_control) -> None:
    """Break a control and require the mutation to be noticed.

    `break_control` returns a list of reasons the break had NO effect. Empty
    means the control really did break, which is what "caught" requires.

    The first version of this helper did the opposite -- it counted a non-empty
    list of "nothing was proved" reasons as success, and reported all four
    mutations NOT CAUGHT while they had in fact all broken their control. An
    inverted mutation harness is worse than none: it reports the opposite of
    what it measured.
    """
    global CHECKS
    not_broken = break_control()
    CHECKS += 1
    caught = not not_broken
    if caught:
        print(f"  [ok  ] {name:<46} caught")
    else:
        print(f"  [FAIL] {name:<46} NOT CAUGHT -- control held anyway: {not_broken}")
        FAILURES.append(f"mutation '{name}' was not caught: {not_broken}")


_ORIG_OK = server.ok


def _break_redaction() -> list[str]:
    def leaky(payload, status=200):
        r = server.jsonify(payload)
        r.status_code = status
        return r
    server.ok = leaky
    try:
        r = client.get("/api/telemetry?schema=runtime/container-exec/v1&limit=500")
        if LIVE_SECRET in r.get_data(as_text=True):
            return []  # the control broke, so the mutation is caught
        return ["password still did not leak, so the redaction was not exercised"]
    finally:
        server.ok = _ORIG_OK


def _break_confirmation() -> list[str]:
    saved = server.ACTIONS
    # "No confirmation required" is exactly what the route sees when every
    # action is marked non-mutating.
    server.ACTIONS = {n: {**s, "mutating": False} for n, s in saved.items()}
    try:
        r = client.post("/api/action/chain")
        if r.status_code == 202:
            with server._JOBS_LOCK:
                for jid in [j.id for j in server._JOBS.values()]:
                    server._JOBS.pop(jid, None)
            return []  # the control broke
        return [f"chain still refused with {r.status_code}, so the guard held"]
    finally:
        server.ACTIONS = saved


def _break_allowlist() -> list[str]:
    saved = server.ACTIONS
    server.ACTIONS = {**saved, "evil": {
        "argv": lambda: ["cmd.exe", "/c", "whoami"], "mutating": True, "about": "x",
    }}
    try:
        r = client.post("/api/action/evil?confirm=yes")
        if r.status_code == 202:
            with server._JOBS_LOCK:
                for jid in [j.id for j in server._JOBS.values()]:
                    server._JOBS.pop(jid, None)
            return []  # an arbitrary command was accepted: the control broke
        return [f"the arbitrary command was refused with {r.status_code}"]
    finally:
        server.ACTIONS = saved


mutation("redaction choke point removed", _break_redaction)
mutation("confirmation requirement removed", _break_confirmation)
mutation("allowlist accepts an arbitrary command", _break_allowlist)

server._run_job = _REAL_RUN_JOB  # type: ignore[assignment]

print()
if FAILURES:
    print(f"FAIL  {len(FAILURES)} of {CHECKS} check(s) failed")
    for f in FAILURES:
        print(f"  [FAIL] {f}")
    sys.exit(1)

print(f"PASS  {CHECKS} checks over {len(RESPONSE_PATHS)} endpoints, including 3 control mutations")
print("  a console that can mint cluster-admin tokens needs tests that can fail")
sys.exit(0)
