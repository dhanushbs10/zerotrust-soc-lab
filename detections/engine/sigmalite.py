"""
sigmalite -- a deliberately small evaluator for the Sigma rule subset this lab uses.

Why this exists
---------------
The rules in `detections/` are standard Sigma and are validated as such: every
rule is loaded by pySigma (`SigmaCollection.load_ruleset`), which parses the
selection syntax, the condition grammar and the modifiers for real. What pySigma
does *not* provide is a backend that can match events sitting in a local JSONL
file, and standing up a SIEM to evaluate six rules would be a large dependency
for a lab whose whole point is to be inspectable.

So the split is:

  pySigma        proves the rules are valid Sigma. This is the real guarantee,
                 and it comes from the reference implementation.
  sigmalite      runs them against the lab's own event files.

What this module is not
-----------------------
It is not a Sigma implementation and must not be described as one. It supports
exactly the constructs listed in SUPPORTED below, and it raises on anything
else rather than guessing. A rule that uses a construct this evaluator does not
understand is a test failure, not a rule that quietly matches nothing --
silence is the one outcome a detection tool must never produce by accident.

The three behaviours worth knowing about
----------------------------------------
1. Field lookup walks dotted paths and flattens arrays, so `counter.deltaDenied`
   and `candidateTechniques.id` both work. A path that is absent yields no
   values, which never matches -- an absent field is not a match.

2. A selection that references a field the event does not have cannot match.
   This is why every rule here pairs its positive condition with an explicit
   guard on `schema`: without it a rule written for exec events would happily
   match a flow event that happened to share a field name.

3. Numeric comparison is supported (`<`, `>`, `<=`, `>=`, `=`) because
   `deltaDenied > 0` is the entire predicate for the T1046 rule. Values are
   coerced to float, and a non-numeric value does not match rather than raising,
   so one malformed counter cannot abort a run over the other 1400 events.

SUPPORTED
---------
selection keys      field, 'field|contains', '|startswith', '|endswith', '|re',
                    '|all', '|gt', '|gte', '|lt', '|lte'
selection values    scalar, or list of scalars (OR), or list of lists (AND of ORs)
condition grammar   identifiers, 'and', 'or', 'not', parentheses,
                    '1 of <glob>', 'all of <glob>', 'any of <glob>',
                    and the special identifier 'them'
"""

from __future__ import annotations

import re
from typing import Any, Iterable

__all__ = [
    "SigmaError",
    "UnsupportedConstruct",
    "Rule",
    "load_rule",
    "matches",
    "match_all",
    "SUPPORTED_MODIFIERS",
]


class SigmaError(Exception):
    """The rule is malformed."""


class UnsupportedConstruct(SigmaError):
    """The rule uses something this evaluator deliberately does not implement.

    Raised rather than ignored. An unrecognised construct that is skipped
    produces a rule that matches nothing, and a rule that matches nothing looks
    exactly like a rule that is working.
    """


SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "all",
    "gt",
    "gte",
    "lt",
    "lte",
    "base64",
}

# Modifiers that take their value as a regex rather than a literal.
_REGEX_MODIFIERS = {"re"}


# ---------------------------------------------------------------------------
# field access
# ---------------------------------------------------------------------------


def _lookup(event: Any, path: str) -> list[Any]:
    """Return every value at `path` inside `event`.

    A dotted path walks nested objects. Where a list is met, the walk continues
    into each element and the results are concatenated, so a path can address a
    field inside a list of objects.

    Returns [] when the path is absent. Absence is not a match, and it must not
    raise: half the schemas in this lab simply do not carry half the fields.
    """
    parts = path.split(".")
    current: list[Any] = [event]

    for part in parts:
        nxt: list[Any] = []
        for node in current:
            if isinstance(node, dict) and part in node:
                value = node[part]
                if isinstance(value, list):
                    nxt.extend(value)
                else:
                    nxt.append(value)
            elif isinstance(node, list):
                # A list reached mid-path: keep descending into its elements so
                # `candidateTechniques.id` resolves, but only if the element is
                # itself a container.
                for item in node:
                    if isinstance(item, dict) and part in item:
                        value = item[part]
                        if isinstance(value, list):
                            nxt.extend(value)
                        else:
                            nxt.append(value)
        current = nxt
        if not current:
            return []

    return current


def _as_text(value: Any) -> str:
    """Render a value for string comparison.

    Booleans are lower-cased so a rule can write `true`, which is how they
    appear in the event files. Everything else uses str(), which is what a
    Sigma rule written against JSON Lines expects.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _numeric(value: Any) -> float | None:
    """Coerce to float, or None when it is not a number.

    None rather than an exception: one counter that failed to parse must not
    abort a run over every other event.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# selection evaluation
# ---------------------------------------------------------------------------


def _match_value(actual: Any, expected: Any, modifier: str) -> bool:
    if modifier in _REGEX_MODIFIERS:
        try:
            return re.search(str(expected), _as_text(actual)) is not None
        except re.error as exc:
            raise SigmaError(f"invalid regex {expected!r}: {exc}") from exc

    if modifier == "gt":
        a, b = _numeric(actual), _numeric(expected)
        return a is not None and b is not None and a > b
    if modifier == "gte":
        a, b = _numeric(actual), _numeric(expected)
        return a is not None and b is not None and a >= b
    if modifier == "lt":
        a, b = _numeric(actual), _numeric(expected)
        return a is not None and b is not None and a < b
    if modifier == "lte":
        a, b = _numeric(actual), _numeric(expected)
        return a is not None and b is not None and a <= b

    text = _as_text(actual)
    if modifier == "contains":
        return str(expected) in text
    if modifier == "startswith":
        return text.startswith(str(expected))
    if modifier == "endswith":
        return text.endswith(str(expected))
    # No modifier: equality. Sigma's default is case-insensitive, but this lab
    # has already been bitten by case-insensitive comparison once -- the
    # policyTypes confusion in Phase 6 -- so equality here is case-SENSITIVE and
    # a rule that needs case-insensitivity must say `|contains`.
    return text == _as_text(expected)


def _match_leaf(field_spec: str, value: Any, event: Any) -> bool:
    """Evaluate one `field: value` pair from a selection.

    `field_spec` is the map key, which is either a bare field name or
    `field|modifier`. `value` is a scalar, a list of scalars (OR), or a
    `{modifier: value}` map that overrides the modifier written in the key.
    """
    if isinstance(value, dict):
        if len(value) != 1:
            raise UnsupportedConstruct(
                f"a field value may carry exactly one modifier, got {list(value)}"
            )
        mod_key, value = next(iter(value.items()))
        modifier: str | None = mod_key
    else:
        modifier = None

    if "|" in field_spec:
        field, inline_mod = field_spec.split("|", 1)
        if inline_mod not in SUPPORTED_MODIFIERS:
            raise UnsupportedConstruct(
                f"modifier '|{inline_mod}' is not implemented by sigmalite; "
                f"supported: {sorted(SUPPORTED_MODIFIERS)}"
            )
        # A modifier in the value map wins over one in the key, which is how
        # Sigma resolves the two spellings of the same thing.
        if modifier is None:
            modifier = inline_mod
    else:
        field = field_spec

    actuals = _lookup(event, field)
    if not actuals:
        # Absent field never matches. Documented because it is the behaviour
        # that makes a schema guard in a rule necessary rather than decorative.
        return False

    expected_values = value if isinstance(value, list) else [value]

    # A list of lists is an AND of ORs, which is how Sigma expresses "all of
    # these, each of which may be any of these".
    if expected_values and all(isinstance(v, list) for v in expected_values):
        return _match_groups(actuals, expected_values, modifier)

    if modifier == "all":
        # Every listed value must be present among the event's values for this
        # field. With no modifier that is plain set membership, so it is written
        # as an equality test rather than a substring one.
        return all(any(_match_value(a, v, None) for a in actuals) for v in expected_values)

    return any(_match_value(a, v, modifier or "") for a in actuals for v in expected_values)


def _match_groups(actuals: list[Any], groups: list[Any], modifier: str | None) -> bool:
    """AND across groups, OR within each group."""
    for group in groups:
        if isinstance(group, list):
            if not any(_match_value(a, v, modifier or "") for a in actuals for v in group):
                return False
        else:
            if not any(_match_value(a, group, modifier or "") for a in actuals):
                return False
    return True


def _match_selection(selection: Any, event: Any) -> bool:
    """A selection is a map of field-pairs; every pair must match (AND)."""
    if not isinstance(selection, dict):
        raise UnsupportedConstruct(f"selection must be a mapping, got {type(selection).__name__}")
    if not selection:
        return True
    for field_spec, value in selection.items():
        if not _match_leaf(field_spec, value, event):
            return False
    return True


# ---------------------------------------------------------------------------
# condition grammar
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*?\-.]+|\band\b|\bor\b|\bnot\b|\bof\b\b)")


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            if text[pos].isspace():
                pos += 1
                continue
            raise SigmaError(f"cannot tokenize condition at offset {pos}: {text[pos:pos + 20]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    """Recursive descent over: expr := term (('or') term)* ; term := factor (('and') factor)*"""

    def __init__(self, tokens: list[str], selections: dict[str, Any]):
        self.tokens = tokens
        self.i = 0
        self.selections = selections

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaError("condition ended unexpectedly")
        self.i += 1
        return tok

    def parse(self, event: Any) -> bool:
        result = self.parse_or(event)
        if self.peek() is not None:
            raise SigmaError(f"trailing tokens in condition: {self.tokens[self.i:]}")
        return result

    def parse_or(self, event: Any) -> bool:
        result = self.parse_and(event)
        while self.peek() == "or":
            self.next()
            # No short-circuit: both sides are evaluated so a rule that throws on
            # one branch still reports the error rather than hiding it.
            right = self.parse_and(event)
            result = result or right
        return result

    def parse_and(self, event: Any) -> bool:
        result = self.parse_factor(event)
        while self.peek() == "and":
            self.next()
            right = self.parse_factor(event)
            result = result and right
        return result

    def parse_factor(self, event: Any) -> bool:
        tok = self.next()
        if tok == "not":
            return not self.parse_factor(event)
        if tok == "(":
            inner = self.parse_or(event)
            if self.next() != ")":
                raise SigmaError("unbalanced parenthesis in condition")
            return inner
        if tok.isdigit():
            n = int(tok)
            if self.next() != "of":
                raise SigmaError(f"expected 'of' after {tok!r}")
            return self.parse_quantifier(event, exact=n)
        if tok == "all":
            if self.next() != "of":
                raise SigmaError("expected 'of' after 'all'")
            return self.parse_quantifier(event, exact=None)
        if tok == "any":
            if self.next() != "of":
                raise SigmaError("expected 'of' after 'any'")
            return self.parse_quantifier(event, minimum=1)
        return self.resolve(tok, event)

    def parse_quantifier(
        self, event: Any, exact: int | None = None, minimum: int | None = None
    ) -> bool:
        """Resolve `N of <glob>`, `all of <glob>` and `any of <glob>`.

        `exact=None` together with no minimum is `all of`, which requires every
        named selection to match. Getting that wrong is silent rather than
        loud: `all of x*` with only `x1` present would report a match, so a rule
        relying on it would fire on incomplete evidence.
        """
        target = self.next()
        if target == "them":
            names = list(self.selections.keys())
        else:
            names = [n for n in self.selections if fnmatch(n, target)]
        if not names:
            raise SigmaError(f"quantifier matched no selection: {target!r}")
        hits = sum(1 for n in names if self.resolve(n, event))
        if exact is None and minimum is None:
            return hits == len(names)
        if exact is not None:
            return hits == exact
        return hits >= (minimum or 1)

    def resolve(self, name: str, event: Any) -> bool:
        if name not in self.selections:
            raise SigmaError(f"condition references unknown selection {name!r}")
        return _match_selection(self.selections[name], event)


def fnmatch(name: str, pattern: str) -> bool:
    """`*` and `?` glob, case-insensitive to match Sigma's selection names."""
    rx = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.fullmatch(rx, name, re.IGNORECASE) is not None


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class Rule:
    def __init__(self, data: dict[str, Any], source: str = "<dict>"):
        self.source = source
        self.data = data
        self.id: str = data.get("id", "")
        self.title: str = data.get("title", "")
        self.level: str = data.get("level", "")
        self.description: str = data.get("description", "")
        self.references: list[str] = data.get("references", []) or []
        self.tags: list[str] = data.get("tags", []) or []
        self.logsource: dict[str, Any] = data.get("logsource", {}) or {}

        detection = data.get("detection")
        if not isinstance(detection, dict):
            raise SigmaError(f"{source}: no detection block")
        self.selections = {k: v for k, v in detection.items() if k != "condition"}
        condition = detection.get("condition")
        if not isinstance(condition, str):
            raise SigmaError(f"{source}: detection.condition must be a string")
        self.condition = condition
        self._tokens = _tokenize(condition)

        # Sigma spells sub-techniques in lower case (`attack.t1609.001`) while
        # ATT&CK and every other part of this lab spell them upper case
        # (`T1609.001`). Normalising here means a rule's technique can be
        # compared with a chain's, an event's candidateTechniques, and the
        # registry's table without every call site remembering to.
        #
        # This was a real bug: the Phase 8 chain report said "NO RULE" for all
        # six hops while the rules were loaded and firing, because the dict
        # lookup was case-sensitive and the two sides disagreed on the case of
        # the letter T.
        techniques = [t for t in self.tags if isinstance(t, str) and t.lower().startswith("attack.t")]
        self.techniques = [t.split(".", 1)[1].upper() for t in techniques]

        if not self.techniques:
            raise SigmaError(
                f"{source}: rule carries no attack.* tag, so it has no ATT&CK technique. "
                "AGENTS.md rule 3 requires one on every detection."
            )

    def matches(self, event: Any) -> bool:
        return _Parser(self._tokens, self.selections).parse(event)

    def __repr__(self) -> str:
        return f"<Rule {self.id} {self.title!r} {self.techniques}>"


def load_rule(path: str) -> Rule:
    import yaml  # imported here so the module is importable without PyYAML

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise SigmaError(f"{path}: top level must be a mapping")
    return Rule(data, source=path)


def matches(rule: Rule, event: Any) -> bool:
    return rule.matches(event)


def match_all(rule: Rule, events: Iterable[Any]) -> list[Any]:
    return [e for e in events if rule.matches(e)]
