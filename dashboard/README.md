# SOC console and control panel

A local web surface for the lab: read what it currently knows, and drive it.

```
pip install -r dashboard/requirements.txt
python dashboard/server.py            # http://127.0.0.1:8099
```

There is no build step and no Node toolchain. `static/` is plain HTML, CSS and
one JavaScript file, served as-is.

## Two halves

**Console** (read-only)

| View | Shows |
|---|---|
| Overview | the four headline numbers, what is *uncovered*, ATT&CK coverage, artifact freshness |
| Detections | every rule, its techniques, its hit count, and sample matched events |
| Reachability | the 6 open paths of 25 modelled, with what decided each one |
| Chain | the 6 hops, and which have a rule behind them |
| Event stream | collected events, filterable by schema, credential values redacted |

**Control** (mutating)

Ten buttons that run the lab's own scripts: collect audit/runtime/network
telemetry, walk the privilege paths, run the chain, rebuild the graph, re-run the
detection gate, check drift and boundaries. Output streams into the page and the
read views refresh when the job finishes.

## Three security properties, enforced and tested

This process can mint a cluster-admin token, create pods, and port-forward into
the database. That is not a hypothetical — it is what the `chain` button does.

**1. It binds to loopback and refuses anything else.** There is no
authentication, so binding to every interface would put an unauthenticated
cluster-admin minting service on the network. `--host` exists but the only
accepted values are `127.0.0.1`, `localhost` and `::1`; anything else exits.

**2. Actions are a fixed allowlist.** `ACTIONS` in `server.py` is a dict of name
→ argv builder. There is no endpoint that takes a command from the request, and
`test_server.py` asserts that `shell=True`, `os.system`, `eval(` and `exec(` do
not appear in the source at all. A "run this command" endpoint is remote code
execution with extra steps.

**3. Mutating actions require `?confirm=yes`.** `walks` and `chain` are marked
`mutating`; without the flag the API returns 409 and creates no job. The browser
also shows a `confirm()` dialog, so the flag is the control and the dialog is
the human-facing half of it.

## Redaction, and why it is a module

The telemetry contains a **live superuser password** in exec `commandLine`
fields:

```
sh -c env PGPASSWORD=<redacted> psql -h postgres -U orders ...
```

SP-01's walk exists to prove that credential works, and it is in a gitignored
file, which is the right place for it. A console renders `commandLine` onto a
page — so without redaction, opening the dashboard publishes a working database
credential to whoever is looking, and into browser history and any screenshot of
an incident.

`redaction.py` sits between the file and the response. It matches **shapes**,
never values: `KEY=value` for credential-ish keys, URL passwords, JWTs,
`Authorization` headers, `--password`. A redactor with the value baked in would
stop working the moment the credential is rotated, which is the one moment
redaction matters most — the same reason `DET-0002` does not carry the leaked
value.

Redaction lives in the server rather than the collector because **the
collector's output is the evidence**, and evidence should stay intact.

Two things are deliberately *not* redacted:

- **Fingerprints.** `A069F0C1482A91C8` is SP-01's stable non-reversible label,
  and it is the one piece of evidence that tells an analyst the ConfigMap copy
  and the Secret copy are the same credential.
- **The key names.** An analyst needs to see that `PGPASSWORD` was used. The
  output reads `PGPASSWORD=<redacted>`, not a deleted line.

`server.ok()` is the single choke point every response goes through, and it
re-checks its own output with `find_secret_shaped_values`. If anything
secret-shaped survives, the payload is replaced with `_payloadWithheld` and the
console shows it — so a redaction bug is visible immediately rather than shipped.

## Tests

```
python dashboard/test_redaction.py    # 44 checks, 4 mutations
python dashboard/test_server.py       # 115 checks over 14 endpoints, 3 control mutations
```

The security properties are tested before the convenient ones, and each has a
mutation that must be caught.

**`test_redaction.py`** asserts known-shaped inputs come back clean, checked with
`find_secret_shaped_values` rather than by string comparison — so a pattern that
stops matching fails the test instead of quietly doing nothing.

**`test_server.py`** checks all 14 read endpoints against the *real* telemetry,
not a fixture, and asserts the sampled window actually contains the credential —
otherwise "no leak" passes vacuously on a response that never held a secret.

## Bugs found while building this

Four, all found by running the thing rather than reading it.

1. **The URL redaction rule named the wrong capture group.** The replacement used
   `\g<pw>` where it meant `\g<scheme>`, so it rewrote the prefix *to the
   password* and kept the value. Every other shape was clean, so the test passed
   on the four rules around it.

2. **The leak detector was blind to `PGPASSWORD=`.** Written as
   `\b(pass|secret|token)\b`, it cannot match inside `PGPASSWORD` — there is no
   word boundary between `PG` and `PASSWORD`. Redaction caught the shape; the
   detector asserting redaction worked could not see it. The detector has to be
   at least as broad as the thing it detects.

3. **The mutation harness was inverted.** Each body returned reasons the break had
   *no* effect, and the helper counted a non-empty list as "caught". All four
   mutations reported `NOT CAUGHT` while having in fact all broken their control.
   A mutation harness that reports the opposite of what it measured is worse than
   none.

4. **The stream rendered literal `<b>` tags.** `summarise()` builds HTML with the
   values escaped, and the caller escaped the result again. Values come from
   telemetry and are untrusted, so the escaping belongs next to the
   interpolation — not in an outer layer the author of `summarise()` cannot see.

## What the console refuses to claim

- **Rule coverage is not hop attribution.** The chain view says *rule fires*,
  meaning a rule for that technique exists and is matching. It does not claim
  that hop caused the match. hop 2 reads a ConfigMap and is credited to a rule
  that only inspects pod-log-read events; that is the agreement-is-not-evidence
  mistake, and the same defect that made Phase 6 report 25/25 open paths
  including 19 that were dropped.
- **Coverage gaps are shown, not rounded away.** `T1078.001` is walked by the
  chain and has no rule, so the chain tile is amber and the Overview names it.
- **Staleness is surfaced.** The artifacts table flags anything over an hour
  old, because a rotated or truncated audit log looks exactly like a quiet
  cluster — which is how this lab lost 91k records earlier today.

## API

| Method | Path | |
|---|---|---|
| GET | `/api/health` | cluster reachability, artifact sizes and ages |
| GET | `/api/summary` | the four headline numbers, chain gaps |
| GET | `/api/detections` | every rule, techniques, hits, sample events |
| GET | `/api/graph` | the reachability graph |
| GET | `/api/chain` | chain summary and hop verdicts |
| GET | `/api/walks` | privilege-path sweep summary |
| GET | `/api/attack-coverage` | the Phase 5 registry report |
| GET | `/api/boundaries` | boundary test results |
| GET | `/api/telemetry?schema=&limit=` | raw events, redacted, bounded |
| GET | `/api/actions` | the allowlist, with mutating flags |
| POST | `/api/action/<name>` | start a job; `?confirm=yes` if mutating |
| GET | `/api/job/<id>` | poll a job |
| GET | `/api/jobs` | all jobs |

Jobs are held in memory and lost on restart. That is correct: a job is a thing
you are watching, not a thing to persist.

## Not done

- **No authentication.** Loopback binding is the entire control. Do not expose
  this, and do not put it behind a reverse proxy that listens on a real
  interface.
- **No live streaming.** The event stream is poll-on-navigation, not a websocket.
  It is enough to watch an attack's aftermath, not its middle.
- **No posture detections.** `DET-0001`, `0002`, `0007`, `0008` and `0009` are
  configuration checks against live cluster state, not rules over collected
  events. They are not written; the catalogue specifies what each should assert.
