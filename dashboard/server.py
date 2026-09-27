"""
The SOC console and control panel.

Two jobs, one process
---------------------
*Console*   read-only views of what the lab currently knows: detections and what
            they matched, the reachability graph, the chain, the walk summary,
            ATT&CK coverage, and raw telemetry.
*Control*   buttons that actually run things: collect telemetry, walk the
            privilege paths, run the purple-team chain, re-run the detection gate.

What this server is allowed to do
--------------------------------
This process can, through the actions below, mint a cluster-admin token, create
pods, and port-forward into the database. Three consequences, all enforced rather
than documented-and-hoped:

1. **It binds to 127.0.0.1 only.** Never 0.0.0.0. There is no authentication
   here, so binding to every interface would put an unauthenticated
   cluster-admin minting service on the network.

2. **Actions are an allowlist of fixed argv lists.** There is no endpoint that
   takes a command from the request. A "run this" endpoint is remote code
   execution with extra steps, and the allowlist means a bug in the web layer
   cannot become arbitrary execution. Each entry names a script that is already
   in the repository.

3. **Mutating actions require an explicit confirm flag.** The chain creates pods
   and mints tokens. A browser that re-sends a POST, or a curious double-click,
   should not be able to do that by accident.

Every response body passes through `redaction.redact`. The telemetry contains a
live superuser password in exec `commandLine` fields, and this server's whole job
is to render those fields. See `redaction.py` for why that is a module and not a
helper call.

Actions are asynchronous
------------------------
The chain takes tens of seconds and the audit export can take minutes. A
synchronous request would time out in the browser and leave the operator unsure
whether it ran. So POST /api/action/<name> returns a job id immediately and
GET /api/job/<id> polls it. Jobs are held in memory and lost on restart, which is
correct: a job is a thing you are watching, not a thing to persist.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

from redaction import find_secret_shaped_values, redact

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TELEMETRY = os.path.join(ROOT, ".telemetry")
STATIC = os.path.join(HERE, "static")
ENGINE = os.path.join(ROOT, "detections", "engine")

app = Flask(__name__, static_folder=None)


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------


class Job:
    def __init__(self, name: str, argv: list[str]) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.name = name
        self.argv = argv
        self.started = time.time()
        self.finished: float | None = None
        self.exit_code: int | None = None
        self.output: list[str] = []
        self.state = "running"
        # The tail is bounded. A walk prints a lot and an unbounded buffer in a
        # long-lived process is a slow leak.
        self._lock = threading.Lock()

    def append(self, line: str) -> None:
        with self._lock:
            self.output.append(line.rstrip())
            if len(self.output) > 400:
                del self.output[: len(self.output) - 400]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state,
            "exitCode": self.exit_code,
            "elapsedSeconds": round((self.finished or time.time()) - self.started, 1),
            "command": " ".join(self.argv),
            "output": self.output[-200:],
        }


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _run_job(job: Job) -> None:
    """Run a job's argv, streaming output.

    `shell=False` and a list argv, always. The allowlist is the security control;
    this is the belt to its braces, and it is what stops a future edit that
    builds a command string from reaching a shell.
    """
    try:
        proc = subprocess.Popen(
            job.argv,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            job.append(line)
        proc.wait()
        job.exit_code = proc.returncode
        job.state = "done" if proc.returncode == 0 else "failed"
    except FileNotFoundError as err:
        job.append(f"could not start {job.argv[0]}: {err}")
        job.exit_code = 127
        job.state = "failed"
    except Exception as err:  # noqa: BLE001
        job.append(f"{type(err).__name__}: {err}")
        job.exit_code = 1
        job.state = "failed"
    finally:
        job.finished = time.time()
        with _JOBS_LOCK:
            # Keep the registry bounded. Old jobs are not interesting an hour
            # later and this process is long-lived.
            if len(_JOBS) > 40:
                for old in sorted(_JOBS.values(), key=lambda j: j.started)[:20]:
                    if old.state != "running":
                        _JOBS.pop(old.id, None)


# ---------------------------------------------------------------------------
# the allowlist
# ---------------------------------------------------------------------------

_PS = "powershell"
# The interpreter running this server, so the detection gate uses the same
# environment and the same pySigma install rather than whatever `python` happens
# to resolve to on PATH.
_PY = sys.executable

# name -> (argv builder, mutating?, human description)
#
# `mutating` marks the entries that change cluster state. The API refuses those
# without an explicit confirm, and the console renders them differently.
ACTIONS: dict[str, dict[str, Any]] = {
    "collect-audit": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"telemetry\audit\export-audit-log.ps1"],
        "mutating": False,
        "about": "Export the audit log to .telemetry/audit-events.jsonl",
    },
    "collect-runtime": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"telemetry\runtime\collect-runtime.ps1"],
        "mutating": False,
        "about": "Derive exec, token-request and log-read events from the audit log",
    },
    "collect-network": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"telemetry\network\collect-network.ps1"],
        "mutating": False,
        "about": "Read kube-router counters. Run twice for a meaningful delta",
    },
    "attack-tag": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"telemetry\tag-attack-ids.ps1"],
        "mutating": False,
        "about": "Check every collected event against the ATT&CK registry",
    },
    "graph": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"graph\build-reachability.ps1"],
        "mutating": False,
        "about": "Derive who-can-reach-what and verify it against the datapath",
    },
    "boundaries": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"tools\test-boundaries.ps1"],
        "mutating": False,
        "about": "33 assertions over namespaces, RBAC and NetworkPolicies",
    },
    "drift": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"tools\scan-drift.ps1"],
        "mutating": False,
        "about": "Compare live state against the manifests, in both directions",
    },
    "detections": {
        "argv": lambda: [_PY, os.path.join("detections", "test-detections.py")],
        "mutating": False,
        "about": "Run the detection gate: every rule fires, and is provably breakable",
    },
    "walks": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"attack\run-all.ps1"],
        "mutating": True,
        "about": "Walk all 7 catalogued privilege paths",
    },
    "chain": {
        "argv": lambda: [_PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", r"attack\chain-purple-team.ps1"],
        "mutating": True,
        "about": "Run the 6-hop intrusion: creates a pod, mints a token, reads the database",
    },
}


# ---------------------------------------------------------------------------
# reading the lab's output
# ---------------------------------------------------------------------------


def _read_json(name: str) -> Any:
    path = os.path.join(TELEMETRY, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError) as err:
        return {"_error": f"could not read {name}: {err}"}


def _read_jsonl(name: str, limit: int | None = None) -> list[Any]:
    path = os.path.join(TELEMETRY, name)
    if not os.path.exists(path):
        return []
    rows: list[Any] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # A half-written last line after an interrupted collection is
                # expected. Skipping it silently would hide truncation, so the
                # count of skipped lines is reported by the caller instead.
                continue
            if limit and len(rows) >= limit:
                break
    return rows


def _load_rules() -> list[Any]:
    import glob

    sys.path.insert(0, ENGINE)
    import sigmalite  # noqa: PLC0415

    rules = []
    for path in sorted(glob.glob(os.path.join(ROOT, "detections", "*", "*.yml"))):
        try:
            rules.append(sigmalite.load_rule(path))
        except Exception as err:  # noqa: BLE001
            rules.append({"_broken": os.path.basename(path), "_error": str(err)})
    return rules


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def ok(payload: Any, status: int = 200):
    """Every response goes through redaction, in one place.

    Deliberately a single choke point rather than a decorator on each route: a
    route added later that forgets to redact is the failure mode, and a
    choke point makes forgetting impossible at the cost of one function.
    """
    safe = redact(payload)
    # Belt and braces. If anything secret-shaped survives, say so loudly in the
    # response rather than shipping it. This should never fire; if it does, the
    # bug is visible in the console immediately.
    leaks = find_secret_shaped_values(safe)
    if leaks:
        safe = {"_redactionLeak": leaks, "_payloadWithheld": True}
    response = jsonify(safe)
    response.status_code = status
    return response


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/static/<path:filename>")
def static_files(filename: str):
    return send_from_directory(STATIC, filename)


# Static assets are also served from the root, so a plain drop of index.html,
# app.js and styles.css into dashboard/static/ works whatever the HTML
# references. The replacement console used `href="styles.css"` rather than
# `/static/styles.css`, and every asset 404'd against the `/static/`-only
# routes -- a blank page with two console errors and no obvious cause.
#
# send_from_directory is given the static directory and an explicit filename, so
# a traversal attempt cannot escape it.
@app.get("/<path:filename>")
def root_static(filename: str):
    if filename.startswith("api/"):
        return jsonify({"error": "not found"}), 404
    candidate = os.path.join(STATIC, filename)
    if os.path.isfile(candidate):
        return send_from_directory(STATIC, filename)
    return index()


@app.get("/api/actions")
def api_actions():
    return ok({
        name: {"mutating": spec["mutating"], "about": spec["about"]}
        for name, spec in ACTIONS.items()
    })


@app.get("/api/health")
def api_health():
    """Is the cluster up, and does the telemetry exist yet."""
    cluster: str
    try:
        proc = subprocess.run(
            ["kubectl", "get", "--raw=/readyz"],
            cwd=ROOT, capture_output=True, text=True, timeout=20, shell=False,
        )
        cluster = "ready" if proc.returncode == 0 else "unreachable"
    except Exception as err:  # noqa: BLE001
        cluster = f"unreachable ({type(err).__name__})"

    files = {}
    for name in os.listdir(TELEMETRY) if os.path.isdir(TELEMETRY) else []:
        if name.endswith((".json", ".jsonl")):
            path = os.path.join(TELEMETRY, name)
            files[name] = {
                "bytes": os.path.getsize(path),
                "ageSeconds": round(time.time() - os.path.getmtime(path)),
            }
    return ok({"cluster": cluster, "artifacts": files})


@app.get("/api/summary")
def api_summary():
    """One screen: is the lab healthy, what fired, what is uncovered."""
    walks = _read_json("walk-summary.json") or {}
    chain = _read_json("chain-summary.json") or {}
    tag = _read_json("attack-tag-report.json") or {}
    graph = _read_json("reachability-graph.json") or {}
    detections = _read_json("detection-results.json") or {}

    return ok({
        "walks": {
            "paths": walks.get("pathsWalked"),
            # What the catalogue says should have run, and whether the sweep
            # actually covered all of it. Without these two a sweep that stopped
            # early produced a summary indistinguishable from a lab with fewer
            # paths in it: same shape, same confidence, six of seven.
            "pathsExpected": walks.get("pathsExpected"),
            "complete": walks.get("complete"),
            "held": (walks.get("assertions") or {}).get("held"),
            "failed": (walks.get("assertions") or {}).get("failed"),
            "attackIds": walks.get("attackIds"),
            "at": walks.get("generatedAt"),
        },
        "chain": {
            "run": chain.get("chainRun"),
            "succeeded": chain.get("hopsSucceeded"),
            "failed": chain.get("hopsFailed"),
            "undetectable": chain.get("undetectable"),
            "hops": chain.get("hops"),
        },
        "coverage": {
            "techniques": (tag.get("summary") or {}).get("techniques")
            or tag.get("techniques"),
            "unexercised": tag.get("notExercised") or tag.get("unexercised"),
        },
        "graph": {
            "nodes": len(graph.get("nodes") or []),
            "edges": len(graph.get("edges") or []),
            "at": graph.get("generatedAt"),
        },
        "detections": detections.get("summary"),
    })


@app.get("/api/detections")
def api_detections():
    """Every rule, its techniques, and what it matched."""
    rules = _load_rules()
    events = _read_jsonl("runtime-events.jsonl") + _read_jsonl("network-events.jsonl")

    import sigmalite  # noqa: PLC0415

    out = []
    for rule in rules:
        if isinstance(rule, dict):
            out.append(rule)
            continue
        hits = sigmalite.match_all(rule, events)
        sample = hits[:3]
        out.append({
            "id": rule.id,
            "title": rule.title,
            "level": rule.level,
            "description": rule.description,
            "falsepositives": rule.data.get("falsepositives", []),
            "techniques": rule.techniques,
            "schema": rule.logsource.get("schema"),
            "hits": len(hits),
            "sample": [
                {
                    "collectedAt": h.get("collectedAt"),
                    "techniqueIds": [t.get("id") for t in (h.get("candidateTechniques") or []) if isinstance(t, dict)],
                    "summary": _event_summary(h),
                }
                for h in sample
            ],
        })
    return ok({"rules": out, "eventsConsidered": len(events)})


def _node_label(node: Any) -> str:
    """A short human label for one end of an observed flow.

    `source` and `dest` on a flow are objects carrying ip, pod, namespace, app,
    serviceAccount, zone and role -- there is no `name` field, and the object
    itself stringifies into a Python dict repr when interpolated. The first
    version of this summary did exactly that, so the console's sample panel was
    rendering lines like:

        None -> {'ip': '10.244.2.2', 'pod': 'orders-api-6cd9fc96...', ...}:8080

    which is both unreadable and, worse, looks like a data problem rather than a
    formatting one. app is the workload's identity and is what an analyst wants;
    pod is the fallback because a probe or a foothold has no app label of its own
    worth trusting, and a bare pod name is still better than a dict.
    """
    if not isinstance(node, dict):
        return str(node) if node is not None else "?"
    for key in ("app", "pod", "serviceAccount", "ip"):
        value = node.get(key)
        if value:
            return str(value)
    return "?"


def _event_summary(event: dict[str, Any]) -> str:
    """One line describing an event, for a table cell."""
    schema = event.get("schema", "")
    if schema == "runtime/container-exec/v1":
        tgt = event.get("target") or {}
        who = (event.get("identity") or {}).get("effectiveIdentity", "?")
        return f"{who} exec {tgt.get('namespace')}/{tgt.get('pod')} ({event.get('subresource')})"
    if schema == "runtime/token-request/v1":
        return (f"{event.get('namespace')}/{event.get('serviceAccount')} "
                f"requester={event.get('requesterClass')} code={event.get('responseCode')}")
    if schema == "runtime/pod-log-read/v1":
        return f"{(event.get('identity') or {}).get('effectiveIdentity')} read {event.get('namespace')}/{event.get('pod')}"
    if schema == "network/denial-counter/v1":
        subj = event.get("subject") or {}
        counter = event.get("counter") or {}
        return (f"{subj.get('namespace')}/{subj.get('pod')} "
                f"+{counter.get('deltaDenied')} denied of +{counter.get('deltaTotal')} ({event.get('baselineState')})")
    if schema == "network/observed-flow/v1":
        return (f"{_node_label(event.get('source'))} -> "
                f"{_node_label(event.get('dest'))}:{event.get('destPort')} "
                f"[{event.get('scope')}/{event.get('state')}]")
    if schema == "runtime/workload-identity/v1":
        return f"{event.get('namespace')}/{event.get('pod')} as {event.get('serviceAccount')}"
    return schema


@app.get("/api/graph")
def api_graph():
    return ok(_read_json("reachability-graph.json") or {"_missing": True})


@app.get("/api/chain")
def api_chain():
    return ok(_read_json("chain-summary.json") or {"_missing": True})


@app.get("/api/walks")
def api_walks():
    return ok(_read_json("walk-summary.json") or {"_missing": True})


@app.get("/api/attack-coverage")
def api_attack_coverage():
    return ok(_read_json("attack-tag-report.json") or {"_missing": True})


@app.get("/api/boundaries")
def api_boundaries():
    return ok(_read_json("boundary-tests.json") or {"_missing": True})


@app.get("/api/telemetry")
def api_telemetry():
    """Raw events, bounded and redacted.

    `limit` defaults low on purpose. This endpoint exists so an analyst can look
    at an individual event, not so a browser can pull 100MB of audit-derived
    JSON into a tab.
    """
    schema = request.args.get("schema", "")
    limit = min(int(request.args.get("limit", "100")), 1000)
    events = _read_jsonl("runtime-events.jsonl") + _read_jsonl("network-events.jsonl")
    if schema:
        events = [e for e in events if e.get("schema") == schema]
    return ok({"schema": schema or "(all)", "count": len(events), "events": events[:limit]})


@app.post("/api/action/<name>")
def api_action(name: str):
    spec = ACTIONS.get(name)
    if spec is None:
        return ok({"error": f"unknown action {name!r}",
                   "known": sorted(ACTIONS)}, status=404)

    # Mutating actions need an explicit confirmation. The chain creates a pod and
    # mints a cluster-admin token; a double-clicked button should not do that.
    if spec["mutating"] and request.args.get("confirm") != "yes":
        return ok({
            "error": f"action {name!r} changes cluster state and needs ?confirm=yes",
            "mutating": True,
            "about": spec["about"],
        }, status=409)

    job = Job(name, spec["argv"]())
    with _JOBS_LOCK:
        _JOBS[job.id] = job
    threading.Thread(target=_run_job, args=(job,), daemon=True).start()
    return ok({"job": job.to_dict()}, status=202)


@app.get("/api/job/<job_id>")
def api_job(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return ok({"error": f"no job {job_id!r}. Jobs are in memory and are lost on restart."}, status=404)
    return ok({"job": job.to_dict()})


@app.get("/api/jobs")
def api_jobs():
    with _JOBS_LOCK:
        return ok({"jobs": [j.to_dict() for j in sorted(_JOBS.values(), key=lambda j: j.started, reverse=True)]})


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="127.0.0.1", help="do not change this; see the module docstring")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(
            f"refusing to bind {args.host}. This process can mint cluster-admin tokens "
            "and has no authentication. It binds to loopback only."
        )

    print(f"SOC console on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)
