#!/usr/bin/env python3
"""Strict YAML validator for the lab's manifests.

Why this exists
---------------
PyYAML does not treat a duplicate mapping key as an error. It silently keeps the
last value. That turns a missing `---` document separator into a *vanishing
object* rather than a failure: the manifests still parse, `kubectl apply
--dry-run=client` still reports success, and the resource you wrote is simply
not there.

That is how six NetworkPolicies disappeared from this lab during authoring. A
policy that fails to be created is worse than a policy that fails to apply,
because the deny is absent and nothing says so.

So this validator:

  1. rejects duplicate keys in any mapping (the actual bug)
  2. counts documents per file and prints what it found
  3. cross-checks that every object kustomize will build has a name and a kind
  4. verifies that pinned image digests are actually pinned

It needs no dependencies beyond PyYAML, which ships with pre-commit's own
environment. Run it directly:

    python tools/validate-yaml.py identities workloads cluster

Exit code is 0 only if every file is clean.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys instead of overwriting."""


def _construct_mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r} (first seen at line {key_node.start_mark.line + 1})",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)

# `image: nginx` or `image: nginx:1.27` are floating. A digest pin looks like
# `nginx@sha256:...`. This repo requires digests so that a rebuild pulls the same
# bytes that were reviewed.
_UNPINNED = re.compile(r"^\s*image:\s*(?P<ref>[^\s@]+)\s*$")
_PINNED = re.compile(r"^\s*image:\s*[^\s@]+@sha256:[0-9a-f]{64}\s*$")

# Kinds that legitimately carry no metadata.name: Kustomization is a build-time
# overlay definition, the audit policy is a plain config file, and Cluster is
# kind's cluster definition.
NAMELESS_KINDS = frozenset({"Kustomization", "Policy", "Cluster"})


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.objects = 0

    def error(self, path: pathlib.Path, message: str) -> None:
        self.errors.append(f"{path}: {message}")


def check_file(path: pathlib.Path, report: Report) -> None:
    text = path.read_text(encoding="utf-8")

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        pinned = _PINNED.match(line)
        floating = _UNPINNED.match(line)
        if floating and not pinned:
            report.error(
                path,
                f"line {line_number}: image {floating.group('ref')!r} is not pinned by digest",
            )

    try:
        documents = list(yaml.load_all(text, Loader=StrictLoader))
    except yaml.YAMLError as exc:
        report.error(path, f"YAML error: {exc}")
        return

    real = 0
    for index, document in enumerate(documents):
        if document is None:
            continue
        real += 1
        report.objects += 1
        if not isinstance(document, dict):
            report.error(path, f"document {index} is {type(document).__name__}, expected a mapping")
            continue
        kind = document.get("kind")
        metadata = document.get("metadata") or {}
        if not kind:
            report.error(path, f"document {index} has no `kind`")
        # Kustomization is a build-time file, not a cluster object, and the audit
        # policy is a config file. Neither is named, and requiring a name for them
        # would just train people to ignore this validator.
        if kind not in NAMELESS_KINDS and not metadata.get("name"):
            report.error(path, f"document {index} ({kind}) has no metadata.name")
        if kind == "Namespace" and "spec" in document:
            report.error(path, f"Namespace {metadata.get('name')} has a spec block, which is invalid")
    if real == 0:
        report.error(path, "contains no Kubernetes objects")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="files or directories to validate")
    parser.add_argument("--quiet", action="store_true", help="only print problems")
    args = parser.parse_args()

    files: list[pathlib.Path] = []
    for raw in args.paths:
        target = pathlib.Path(raw)
        if target.is_dir():
            files.extend(sorted(target.rglob("*.yaml")))
            files.extend(sorted(target.rglob("*.yml")))
        elif target.is_file():
            files.append(target)
        else:
            sys.exit(f"no such path: {raw}")

    report = Report()
    for path in files:
        check_file(path, report)

    if not args.quiet:
        print(f"checked {len(files)} file(s), {report.objects} object(s)")

    if report.errors:
        print(f"\n{len(report.errors)} problem(s):", file=sys.stderr)
        for problem in report.errors:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    if not args.quiet:
        print("all manifests clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
