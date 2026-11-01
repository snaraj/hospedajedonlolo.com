#!/usr/bin/env python3
"""Fail-closed schema gate for the `.github/dependabot.yml` subset this repo uses.

This module is intentionally standard-library only (no PyYAML): the same
constraint `scripts/ci/chart-ingress-pin.sh` works under, for the same
reason -- CI runs no unpinned interpreter package. Rather than hand-parse
`spec.ingress` alone (that script's approach), this module implements a
small, generic, indentation-based recursive-descent reader for the narrow
block-style YAML subset Dependabot configs need, then validates the result
against this repository's contract in a separate semantic pass so every
rejection can name the exact offending line.

Deliberate, conservative restrictions (fail-closed: anything this reader
cannot unambiguously parse is rejected, never guessed at):

- Two-space indentation steps only, block style only. Flow collections
  (`[...]`, `{...}`), tabs, comments (`#`), block scalars (`|`, `>`),
  anchors/aliases (`&`, `*`), and tags (`!`) are all refused outright --
  none of them appear in this repository's real config, and silently
  half-supporting any of them would trade a clear rejection for a guess.
  The `#` rule is WIDER than YAML's comment rule, deliberately: any line
  containing a `#` anywhere is refused, including one inside a quoted scalar
  (`- "lib#1"` denies, though real YAML reads it as the string `lib#1`).
  Deciding which `#` opens a comment needs the quote tracking this reader
  does not do, so it refuses the whole class. The denial message names
  comments because that is the realistic cause, not because the check can
  tell the two apart -- it cannot, and an operator who wrote a `#`-bearing
  pattern will be told something slightly wrong about a line that is
  nonetheless genuinely refused.
- The top-level key set is exactly `{version, updates}`; nothing here reads
  or validates `registries:` or `enable-beta-ecosystems:`. Adding either is
  a conscious, reviewed extension of this file, same as the "Sanctioned
  evolution" pattern AGENTS.md documents for other growth points.
- The per-`updates[]` key set is exactly what this repository actually
  uses: `package-ecosystem`, `directory`, `schedule`, `open-pull-requests-
  limit`, `groups`. Dependabot's full schema has more (`ignore`, `labels`,
  `reviewers`, ...); an unrecognized key is refused rather than passed
  through unvalidated, so adopting a new one is a deliberate edit here.
- `schedule.interval` accepts only `daily`, `weekly`, `monthly` -- this
  repo uses `weekly` everywhere today; Dependabot's `quarterly`,
  `semiannually`, `yearly`, and cron-string forms take a different shape
  and are out of scope until a real need arrives.
- `schedule.timezone` is checked for IANA-style shape (`Area/Location`,
  `Etc/GMT+12`, bare `UTC`, ...) by pattern only, not against the system
  timezone database, so this gate's result cannot depend on which tzdata
  happens to be installed on the runner.

CLI:

    python3 -I -B scripts/ci/dependabot_contract.py .github/dependabot.yml

Exit 0 when the file satisfies the contract; exit 2, with a `DENY:` line
naming the offending line on stderr, when it does not. A malformed
invocation (missing/extra argument) is also exit 2 -- that is argparse's
own usage-error status, not a choice this module makes -- distinguishable
from a contract denial only by the `usage:` vs `DENY:` line on stderr, so
1 is not reserved for anything; it would only appear from an unhandled
crash, which every known input in this module's own test suite forecloses.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Documented `package-ecosystem` values, cross-checked against two
# independent sources (both re-read 2026-08-20): the github/docs
# supported-package-managers table (docs.github.com/en/code-security/
# dependabot/dependabot-version-updates/configuration-options-for-the-
# dependabot.yml-file) and SchemaStore's `dependabot-2.0.json` enum, which
# agree on all 33 values. Includes every ecosystem this repository's real
# config uses today (github-actions, gomod) plus the rest of the
# documented set, so a future addition of an official ecosystem never needs
# this allowlist touched -- only a genuinely unknown string is refused.
# Corrected 2026-08-20 (PR #84 adversarial review): an initial single-
# source fetch mistakenly carried `hex` where the documented value for
# Hex/Elixir is `mix` -- both sources agree `mix` is correct and `hex` is
# not a `package-ecosystem` value at all.
ECOSYSTEMS = frozenset(
    {
        "bazel",
        "bundler",
        "bun",
        "cargo",
        "composer",
        "conda",
        "deno",
        "devcontainers",
        "docker",
        "docker-compose",
        "dotnet-sdk",
        "elm",
        "github-actions",
        "gitsubmodule",
        "gomod",
        "gradle",
        "helm",
        "julia",
        "maven",
        "mix",
        "nix",
        "npm",
        "nuget",
        "opentofu",
        "pip",
        "pre-commit",
        "pub",
        "rust-toolchain",
        "sbt",
        "swift",
        "terraform",
        "uv",
        "vcpkg",
    }
)

TOP_LEVEL_KEYS = frozenset({"version", "updates"})
UPDATE_KEYS = frozenset({"package-ecosystem", "directory", "schedule", "open-pull-requests-limit", "groups"})
REQUIRED_UPDATE_KEYS = frozenset({"package-ecosystem", "directory", "schedule"})
SCHEDULE_KEYS = frozenset({"interval", "day", "time", "timezone"})
ALLOWED_INTERVALS = frozenset({"daily", "weekly", "monthly"})
ALLOWED_DAYS = frozenset({"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"})
TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")
GROUP_ENTRY_KEYS = frozenset({"patterns", "exclude-patterns", "dependency-type", "update-types", "applies-to"})
DEPENDENCY_TYPES = frozenset({"development", "production"})
UPDATE_TYPES = frozenset({"major", "minor", "patch"})
APPLIES_TO = frozenset({"version-updates", "security-updates"})

_KEY_RE = re.compile(r"^([A-Za-z0-9_.-]+):(?:\s+(.*))?$")


class DependabotContractError(ValueError):
    """`.github/dependabot.yml` (or a candidate copy) fails the contract."""


# --- Parse tree -------------------------------------------------------------
#
# Every node carries the 1-indexed source line it started on, so every
# semantic rejection downstream can name an exact line without re-deriving
# it. NullNode stands for a mapping key written with no inline value and no
# indented child block (`key:` followed by nothing) -- distinct from a
# missing key, and always refused wherever a real value is required.


@dataclass
class ScalarNode:
    value: str
    line: int


@dataclass
class NullNode:
    line: int


@dataclass
class SequenceNode:
    items: list[Node]
    line: int


@dataclass
class MappingNode:
    entries: dict[str, Node] = field(default_factory=dict)
    key_lines: dict[str, int] = field(default_factory=dict)
    line: int = 0


# Everything this reader builds is one of the four, and every one of them
# carries its own source line. Saying so is what lets a refusal name the line:
# `object` has no `.line`, so `_require_mapping` and its two siblings were
# reaching for an attribute their declared parameter type does not have. The
# containers really only ever hold these four -- `_consume_mapping_entries`
# stores a ScalarNode, a NullNode, or whatever `_parse_block` returned, and
# nothing else -- so this is the type the parser already had.
Node = ScalarNode | NullNode | SequenceNode | MappingNode


# --- Lexical helpers ----------------------------------------------------------


def _check_forbidden_bytes(text: str) -> None:
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise DependabotContractError(f"line {lineno}: tab characters are not supported; use spaces only")
        if "#" in raw:
            raise DependabotContractError(
                f"line {lineno}: comments are not supported by this conservative parser"
            )


def _indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def _looks_like_flow(value: str) -> bool:
    v = value.strip()
    return v.startswith("[") or v.startswith("{")


_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?[0-9]?$")


def _parse_scalar_token(raw: str, lineno: int) -> ScalarNode:
    v = raw.strip()
    if v[:1] in ("&", "*", "!"):
        raise DependabotContractError(f"line {lineno}: anchors, aliases, and tags are not supported")
    if _BLOCK_SCALAR_RE.match(v):
        raise DependabotContractError(f"line {lineno}: block scalar indicators are not supported")
    if v[:1] in ('"', "'"):
        quote = v[0]
        if len(v) < 2 or v[-1] != quote:
            raise DependabotContractError(f"line {lineno}: unterminated quoted scalar")
        v = v[1:-1]
        if quote in v:
            raise DependabotContractError(
                f"line {lineno}: quoted scalars may not contain an embedded, unescaped quote character"
            )
    elif any(ch in v for ch in "\"'"):
        raise DependabotContractError(f"line {lineno}: unexpected quote character in an unquoted scalar")
    if v == "":
        raise DependabotContractError(f"line {lineno}: empty scalar value")
    return ScalarNode(v, lineno)


def _split_key_value(content: str) -> tuple[str, str | None] | None:
    """Split a `key:` or `key: value` line body. None means no match at all."""
    match = _KEY_RE.match(content)
    if not match:
        return None
    key = match.group(1)
    value = match.group(2)
    if value is not None:
        value = value.strip()
        if value == "":
            value = None
    return key, value


# --- Recursive-descent block reader ------------------------------------------
#
# Every nesting level in this grammar -- a mapping value that is itself a
# mapping or sequence, a sequence item's inline mapping key, a group's body
# -- is indented exactly two columns deeper than its parent. That single
# rule is enough to read this repository's real file end to end; anything
# that does not fit it is refused rather than guessed at.


def _parse_block(lines: list[tuple[int, str]], idx: int, indent: int) -> tuple[Node, int]:
    if idx >= len(lines):
        raise DependabotContractError("unexpected end of file; more content was expected")
    lineno, raw = lines[idx]
    if _indent(raw) != indent:
        raise DependabotContractError(f"line {lineno}: expected indentation of exactly {indent} spaces")
    content = raw[indent:]
    if content == "-" or content.startswith("- "):
        return _parse_sequence(lines, idx, indent)
    return _parse_mapping(lines, idx, indent)


def _consume_mapping_entries(
    lines: list[tuple[int, str]],
    idx: int,
    indent: int,
    entries: dict[str, Node],
    key_lines: dict[str, int],
) -> int:
    def add(key: str, node: Node, lineno: int) -> None:
        if key in entries:
            raise DependabotContractError(
                f"line {lineno}: duplicate key '{key}' (first seen at line {key_lines[key]})"
            )
        entries[key] = node
        key_lines[key] = lineno

    while idx < len(lines):
        lineno, raw = lines[idx]
        if _indent(raw) != indent:
            break
        content = raw[indent:]
        if content == "-" or content.startswith("- "):
            raise DependabotContractError(f"line {lineno}: unexpected sequence item; a mapping was expected here")
        parsed = _split_key_value(content)
        if parsed is None:
            raise DependabotContractError(f"line {lineno}: unparseable content; expected a 'key: value' mapping entry")
        key, value = parsed
        idx += 1
        if value is not None:
            if _looks_like_flow(value):
                raise DependabotContractError(
                    f"line {lineno}: flow-style values ('[...]' or '{{...}}') are not supported"
                )
            add(key, _parse_scalar_token(value, lineno), lineno)
        elif idx < len(lines) and _indent(lines[idx][1]) == indent + 2:
            child, idx = _parse_block(lines, idx, indent + 2)
            add(key, child, lineno)
        else:
            add(key, NullNode(lineno), lineno)
    return idx


def _parse_mapping(lines: list[tuple[int, str]], idx: int, indent: int) -> tuple[MappingNode, int]:
    node_line = lines[idx][0]
    entries: dict[str, Node] = {}
    key_lines: dict[str, int] = {}
    idx = _consume_mapping_entries(lines, idx, indent, entries, key_lines)
    if not entries:
        raise DependabotContractError(f"line {node_line}: empty mapping")
    return MappingNode(entries, key_lines, node_line), idx


def _parse_sequence(lines: list[tuple[int, str]], idx: int, indent: int) -> tuple[SequenceNode, int]:
    node_line = lines[idx][0]
    items: list[Node] = []
    while idx < len(lines):
        lineno, raw = lines[idx]
        if _indent(raw) != indent:
            break
        content = raw[indent:]
        if not (content == "-" or content.startswith("- ")):
            break
        remainder = content[2:] if content.startswith("- ") else ""
        if remainder.strip() == "":
            raise DependabotContractError(f"line {lineno}: empty sequence item is not supported")
        parsed = _split_key_value(remainder)
        if parsed is not None:
            key, value = parsed
            entries: dict[str, Node] = {}
            key_lines: dict[str, int] = {key: lineno}
            idx += 1
            if value is not None:
                if _looks_like_flow(value):
                    raise DependabotContractError(
                        f"line {lineno}: flow-style values ('[...]' or '{{...}}') are not supported"
                    )
                entries[key] = _parse_scalar_token(value, lineno)
            elif idx < len(lines) and _indent(lines[idx][1]) == indent + 4:
                child, idx = _parse_block(lines, idx, indent + 4)
                entries[key] = child
            else:
                entries[key] = NullNode(lineno)
            idx = _consume_mapping_entries(lines, idx, indent + 2, entries, key_lines)
            items.append(MappingNode(entries, key_lines, lineno))
        else:
            if _looks_like_flow(remainder):
                raise DependabotContractError(
                    f"line {lineno}: flow-style values ('[...]' or '{{...}}') are not supported"
                )
            items.append(_parse_scalar_token(remainder, lineno))
            idx += 1
    return SequenceNode(items, node_line), idx


def parse_document(text: str) -> MappingNode:
    _check_forbidden_bytes(text)
    raw_lines = text.splitlines()
    lines = [(i + 1, line) for i, line in enumerate(raw_lines) if line.strip() != ""]
    if not lines:
        raise DependabotContractError("line 1: file is empty")
    node, idx = _parse_block(lines, 0, 0)
    if idx != len(lines):
        raise DependabotContractError(
            f"line {lines[idx][0]}: unexpected content at top level (indentation never returns to 0)"
        )
    if not isinstance(node, MappingNode):
        raise DependabotContractError(f"line {node.line}: the top-level document must be a mapping")
    return node


# --- Semantic contract --------------------------------------------------------


def _require_mapping(node: Node, where: str) -> MappingNode:
    if not isinstance(node, MappingNode):
        raise DependabotContractError(f"line {node.line}: {where} must be a mapping")
    return node


def _require_scalar(node: Node, where: str) -> ScalarNode:
    if not isinstance(node, ScalarNode):
        raise DependabotContractError(f"line {node.line}: {where} must be a plain value, not a nested structure")
    return node


def _require_nonempty_sequence(node: Node, where: str) -> SequenceNode:
    if not isinstance(node, SequenceNode) or not node.items:
        raise DependabotContractError(f"line {node.line}: {where} must be a non-empty list")
    return node


def _reject_unknown_keys(mapping: MappingNode, allowed: frozenset[str], where: str) -> None:
    for key, lineno in mapping.key_lines.items():
        if key not in allowed:
            raise DependabotContractError(f"line {lineno}: unknown key '{key}' in {where}")


def _validate_string_list(node: Node, where: str, *, allowed: frozenset[str] | None = None) -> None:
    seq = _require_nonempty_sequence(node, where)
    for item in seq.items:
        scalar = _require_scalar(item, f"each {where} item")
        if allowed is not None and scalar.value not in allowed:
            raise DependabotContractError(f"line {scalar.line}: {where} item must be one of {sorted(allowed)}")


def _validate_schedule(node: Node) -> None:
    schedule = _require_mapping(node, "'schedule'")
    _reject_unknown_keys(schedule, SCHEDULE_KEYS, "a 'schedule' mapping")
    if "interval" not in schedule.entries:
        raise DependabotContractError(f"line {schedule.line}: schedule is missing required key 'interval'")
    interval = _require_scalar(schedule.entries["interval"], "'schedule.interval'")
    if interval.value not in ALLOWED_INTERVALS:
        raise DependabotContractError(
            f"line {interval.line}: schedule.interval must be one of {sorted(ALLOWED_INTERVALS)}"
        )
    if "day" in schedule.entries:
        day = _require_scalar(schedule.entries["day"], "'schedule.day'")
        if day.value not in ALLOWED_DAYS:
            raise DependabotContractError(f"line {day.line}: schedule.day must be a lowercase weekday name")
    if "time" in schedule.entries:
        time_value = _require_scalar(schedule.entries["time"], "'schedule.time'")
        if not TIME_RE.match(time_value.value):
            raise DependabotContractError(f"line {time_value.line}: schedule.time must be 24-hour 'HH:MM'")
    if "timezone" in schedule.entries:
        timezone = _require_scalar(schedule.entries["timezone"], "'schedule.timezone'")
        if not TIMEZONE_RE.match(timezone.value):
            raise DependabotContractError(
                f"line {timezone.line}: schedule.timezone must look like an IANA zone identifier"
            )


def _validate_groups(node: Node) -> None:
    groups = _require_mapping(node, "'groups'")
    for name, group_node in groups.entries.items():
        group = _require_mapping(group_node, f"groups.{name}")
        _reject_unknown_keys(group, GROUP_ENTRY_KEYS, f"groups.{name}")
        # No "must declare at least one key" check here: `group.entries` is
        # non-empty by construction whenever `group` exists at all, so a
        # redundant check would be exactly the vacuous-assertion class
        # AGENTS.md's adversarial review protocol flags -- no input could ever
        # turn it red.
        #
        # The guarantor is `_consume_mapping_entries`, not the "empty mapping"
        # raise this comment used to cite. `_parse_block` has already required
        # `idx < len(lines)`, exact indentation, and a non-sequence line before
        # it calls `_parse_mapping`, so the first pass of the consume loop can
        # neither break nor bail: it either adds an entry or rejects the line
        # as unparseable. That `empty mapping` guard is therefore itself
        # unreachable -- a structural backstop, kept, but the wrong thing to
        # send a maintainer to as the safety net.
        if "patterns" in group.entries:
            _validate_string_list(group.entries["patterns"], f"groups.{name}.patterns")
        if "exclude-patterns" in group.entries:
            _validate_string_list(group.entries["exclude-patterns"], f"groups.{name}.exclude-patterns")
        if "dependency-type" in group.entries:
            dependency_type = _require_scalar(group.entries["dependency-type"], f"groups.{name}.dependency-type")
            if dependency_type.value not in DEPENDENCY_TYPES:
                raise DependabotContractError(
                    f"line {dependency_type.line}: groups.{name}.dependency-type must be one of {sorted(DEPENDENCY_TYPES)}"
                )
        if "update-types" in group.entries:
            _validate_string_list(group.entries["update-types"], f"groups.{name}.update-types", allowed=UPDATE_TYPES)
        if "applies-to" in group.entries:
            applies_to = _require_scalar(group.entries["applies-to"], f"groups.{name}.applies-to")
            if applies_to.value not in APPLIES_TO:
                raise DependabotContractError(
                    f"line {applies_to.line}: groups.{name}.applies-to must be one of {sorted(APPLIES_TO)}"
                )


def _validate_update_entry(node: Node) -> None:
    entry = _require_mapping(node, "each updates[] entry")
    _reject_unknown_keys(entry, UPDATE_KEYS, "an updates[] entry")
    for key in sorted(REQUIRED_UPDATE_KEYS):
        if key not in entry.entries:
            raise DependabotContractError(f"line {entry.line}: updates[] entry is missing required key '{key}'")
    ecosystem = _require_scalar(entry.entries["package-ecosystem"], "'package-ecosystem'")
    if ecosystem.value not in ECOSYSTEMS:
        raise DependabotContractError(f"line {ecosystem.line}: unknown package-ecosystem '{ecosystem.value}'")
    directory = _require_scalar(entry.entries["directory"], "'directory'")
    if not directory.value.startswith("/"):
        raise DependabotContractError(f"line {directory.line}: directory must start with '/'")
    _validate_schedule(entry.entries["schedule"])
    if "open-pull-requests-limit" in entry.entries:
        limit = _require_scalar(entry.entries["open-pull-requests-limit"], "'open-pull-requests-limit'")
        if not re.fullmatch(r"[0-9]+", limit.value):
            raise DependabotContractError(f"line {limit.line}: open-pull-requests-limit must be a non-negative integer")
    if "groups" in entry.entries:
        _validate_groups(entry.entries["groups"])


def validate_document(node: MappingNode) -> None:
    _reject_unknown_keys(node, TOP_LEVEL_KEYS, "the top-level mapping")
    if "version" not in node.entries:
        raise DependabotContractError(f"line {node.line}: missing required top-level key 'version'")
    version = _require_scalar(node.entries["version"], "'version'")
    if version.value != "2":
        raise DependabotContractError(f"line {version.line}: version must be exactly 2")
    if "updates" not in node.entries:
        raise DependabotContractError(f"line {node.line}: missing required top-level key 'updates'")
    updates = _require_nonempty_sequence(node.entries["updates"], "'updates'")
    for item in updates.items:
        _validate_update_entry(item)


def validate_text(text: str) -> None:
    validate_document(parse_document(text))


def validate_file(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError is a ValueError, not an OSError -- read_text
        # raises it directly when the bytes on disk are not valid UTF-8, and
        # without this arm it propagated uncaught: a crash and a bare
        # non-zero exit instead of the DENY line every other rejection in
        # this module produces. Non-UTF-8 bytes are exactly the kind of
        # input the module docstring promises to reject, never guess at.
        raise DependabotContractError(f"cannot read {path}: {exc}") from exc
    validate_text(text)


# --- CLI -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed schema gate for a dependabot.yml subset.")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_file(args.path)
    except DependabotContractError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 2
    print(f"OK: {args.path} satisfies the dependabot.yml contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
