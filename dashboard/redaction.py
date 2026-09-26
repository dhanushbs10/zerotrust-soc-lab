"""
Credential redaction for anything the dashboard serves.

Why this module exists
----------------------
The lab's telemetry contains a live credential, and that is the entire point of
SP-01. Measured in `.telemetry/runtime-events.jsonl`, an exec event's
`commandLine` reads:

    sh -c env PGPASSWORD=<the real password> psql -h postgres -U orders ...

That value is the real, current, superuser password for the orders database.
SP-01's walk went to some trouble to prove it, and it is in a gitignored file,
which is the correct place for it.

It is deliberately *not* reproduced here. The first version of this docstring
quoted the actual password as an illustration and gitleaks failed the commit --
which is the correct outcome and a fair reflection of how easy it is to leak a
credential while writing prose about not leaking credentials.

A SOC console renders `commandLine` onto a page. Without redaction, opening the
dashboard publishes a working database credential to whoever is looking at the
screen, and writes it into browser history, devtools, and any screenshot taken
of an incident. Redaction belongs between the file and the response, not in the
collector, because the collector's output is the evidence and the evidence
should stay intact.

Shape, not value
----------------
Nothing here knows the password. Every pattern matches a *shape* -- `KEY=value`,
a bearer token, a JWT, a password in a URL -- for the same reason DET-0002 does
not carry the leaked value: a detector that knows the secret in order to find the
secret is not a detector. A redactor with the value baked in would also stop
working the moment the credential is rotated, which is the one moment redaction
matters most.

What is deliberately not redacted
--------------------------------
Fingerprints. SP-01 records a stable non-reversible label
(`A069F0C1482A91C8`) precisely so two copies of one credential can be correlated
without printing either. That label is safe and it is useful on a console, so it
survives. Redacting it would destroy the one piece of evidence that tells an
analyst the ConfigMap copy and the Secret copy are the same credential.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["redact_text", "redact", "REDACTED", "find_secret_shaped_values"]

REDACTED = "<redacted>"

# Each pattern is (name, compiled regex, replacement). The replacement uses \1
# for the key so the *shape* of the line survives and stays readable: an analyst
# needs to see that PGPASSWORD was used, not its value.
#
# Order matters. The URL rule runs before the generic KEY=value rule because
# `postgres://orders:hunter2@host/db` contains a `:` and `@` that the generic
# rule would mangle differently.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # scheme://user:password@host
    #
    # The replacement names <scheme>, not <pw>. Naming the password group here
    # rewrites the prefix to the password and keeps the value, which is how the
    # first version of this rule leaked a whole URL credential while the test
    # around it still passed on every other shape.
    (
        "url-password",
        re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)(?P<pw>[^\s@]+)(?P<at>@)"),
        r"\g<scheme>" + REDACTED + r"\g<at>",
    ),
    # PGPASSWORD=..., MY_PASSWORD=..., DB_PASSWORD: ..., token=..., api_key=...
    # The key is any identifier ending in a credential-ish word. Deliberately
    # broad on the left and greedy-but-bounded on the right, so a value with
    # shell punctuation does not swallow the rest of the command.
    (
        "key-equals",
        re.compile(
            r"(?P<key>\b[A-Za-z_][A-Za-z0-9_.-]*"
            r"(?:PASS(WORD)?|SECRET|TOKEN|APIKEY|API_KEY|CREDENTIAL|AUTH)"
            r"(?![A-Za-z0-9_])"
            r"\s*[=:]\s*)"
            r"(?P<val>\"[^\"]*\"|'[^']*'|[^\s;&|]+)",
            re.IGNORECASE,
        ),
        r"\g<key>" + REDACTED,
    ),
    # Bare JWT: three base64url segments. Header always starts eyJ.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"), REDACTED),
    # Authorization header values.
    (
        "authorization",
        re.compile(r"(?i)(?P<key>\bAuthorization\s*:\s*)(?P<val>Bearer|Basic)\s+\S+"),
        r"\g<key>\g<val> " + REDACTED,
    ),
    # `-password <value>` and `--password=<value>`, which kubectl and friends use.
    (
        "flag-password",
        re.compile(r"(?P<key>(?:-{1,2}password|--token)(?:\s+|=))(?P<val>[^\s]+)"),
        r"\g<key>" + REDACTED,
    ),
]

# Applied to a whole event, not just to strings we know are commands.
_STRING_KEYS_NEEDING_WALK = (
    "commandLine",
    "command",
    "requestURI",
    "raw",
    "detail",
    "verdict",
    "note",
    "why",
    "reason",
    "decisionReason",
    "note_text",
)


def redact_text(text: str) -> str:
    """Redact credential-shaped substrings, preserving surrounding structure."""
    if not text:
        return text
    out = text
    for _name, pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact a JSON-shaped structure.

    Depth-limited so a malformed or cyclic structure cannot hang the server. The
    limit is generous for telemetry (events nest about six deep) and a value that
    hits it is returned as a marker rather than silently passed through, because
    an unredacted deep structure is exactly the failure this module exists to
    prevent.
    """
    if _depth > 12:
        return "<truncated: nesting too deep to redact safely>"

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v, _depth + 1) for v in value)
    return value


def find_secret_shaped_values(value: Any) -> list[str]:
    """Return any value that *looks* like a credential and survived redaction.

    This is the detector that backs the detector. The redaction tests assert
    that known-shaped inputs come back clean, but a pattern that fails to match
    a novel shape would pass those tests silently. This walks a structure and
    reports anything still credential-shaped, so a test can assert the absence
    of leaks rather than the presence of redactions.

    Returns a list of short descriptions, never the value itself.
    """
    suspicious: list[str] = []

    def looks_like_secret(text: str) -> bool:
        if not isinstance(text, str) or len(text) < 8:
            return False
        if REDACTED in text:
            return False
        # The key pattern must allow a prefix, exactly as the redactor's does.
        # Written as `\b(pass(word)?|secret|token)\b` it cannot see `PGPASSWORD=`
        # at all, because there is no word boundary between "PG" and "PASSWORD"
        # -- so the detector was blind to the one credential shape this lab
        # actually produces, while redaction caught it. The detector has to be at
        # least as broad as the thing it is detecting.
        if re.search(
            r"(?i)\b[A-Za-z_][A-Za-z0-9_.-]*"
            r"(?:PASS(WORD)?|SECRET|TOKEN|APIKEY|API_KEY|CREDENTIAL|AUTH)"
            r"(?![A-Za-z0-9_])\s*[=:]\s*\S",
            text,
        ):
            return True
        if re.search(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.", text):
            return True
        if re.search(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:[^\s@]+@", text):
            return True
        return False

    def walk(node: Any, path: str, depth: int) -> None:
        if depth > 12:
            return
        if isinstance(node, str):
            if looks_like_secret(node):
                suspicious.append(path)
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}", depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]", depth + 1)

    walk(value, "$", 0)
    return suspicious
