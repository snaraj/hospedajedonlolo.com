#!/usr/bin/env python3
"""Fail-closed release identity and GitHub event policy.

This module is intentionally standard-library only.  CI and its hostile tests
use the same functions, so event, version, and immutable-artifact decisions
cannot drift into prose-only conventions.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_WORKFLOW = "PR gate"
EXPECTED_WORKFLOW_PATH = ".github/workflows/pr-gate.yml"
EXPECTED_CODEQL_WORKFLOW = "CodeQL"
EXPECTED_CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
EXPECTED_PUBLISHER_PATH = ".github/workflows/release-publisher.yml"
EXPECTED_REPOSITORY = "snaraj/hospedajedonlolo.com"
EXPECTED_IMAGE = "ghcr.io/snaraj/hospedajedonlolo-com"
EXPECTED_CHART = "ghcr.io/snaraj/charts/hospedajedonlolo-com"
GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_BOT_ID = 41898282
# The in-toto Statement ENVELOPE version cosign actually emits for every
# `cosign attest` predicate type -- alias or explicit URI alike. This is
# independent of, and must not be confused with, the SLSA predicate's own
# "v1" versioning carried by SLSA_PREDICATE_TYPE below: cosign v3.1.3's
# GenerateStatement always sets Type: in_toto.StatementInTotoV01, whether it
# routes through the typed slsaprovenance1 alias or the verbatim custom/URI
# path used here.
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
# An Actions run ID is a positive decimal integer with no leading zero, sign,
# separator, or surrounding space -- the same shape the publisher already
# demands of its dispatched main and CodeQL run IDs
# (`[[ "${MAIN_RUN_ID}" =~ ^[1-9][0-9]*$ ]]`).
ACTIONS_RUN_ID_RE = re.compile(r"[1-9][0-9]*")
# BuildKit writes the builder identity as the run URL with the ATTEMPT
# appended: `.../actions/runs/<id>/attempts/<n>`, measured on this
# repository's own published provenance sampled from v0.1.2 through v0.1.32,
# every one of them `/attempts/1`. The bare run URL is accepted too, because
# the run is the identity a caller can prove and the attempt is a sub-index
# of that same run -- a re-run of one publisher run stays bound to it. What
# is NOT accepted is anything else after the run: the suffix is matched by
# pattern, never skipped over, so `/attempts/0`, `/attempts/`,
# `/attempts/1/anything`, `/jobs/5`, or a bare trailing slash all deny.
BUILDER_ATTEMPT_SUFFIX = r"(?:/attempts/[1-9][0-9]*)?"
# The fail-closed value the COMMITTED chart carries. It is a syntactically
# valid digest -- it satisfies values.schema.json and the gate's render
# assertion -- that no registry can ever resolve, so a chart installed with it
# fails at pull time instead of silently pulling a floating tag. The committed
# tree keeps it forever (issue #111 acceptance 4); only the PUBLISHED artifact
# carries the resolved digest, substituted on the runner by the publisher after
# the vulnerability gate, signature, and provenance attestation have accepted
# it.
CHART_DIGEST_SENTINEL = "sha256:" + "0" * 64
# The exact committed line the substitution replaces. Quoting and trailing
# whitespace are tolerated because YAML permits them; ANY other spelling of the
# value fails closed rather than being rewritten by guess.
CHART_DIGEST_LINE_RE = re.compile(
    r"(?m)^  digest:[ \t]+[\"']?" + CHART_DIGEST_SENTINEL + r"[\"']?[ \t]*$"
)
GITHUB_API_VERSION = "2026-03-10"
EXPECTED_MAIN_RULESET = "Protect-Main"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
REQUIRED_STATUS_CHECKS = (
    "analyze (go, manual)",
    "analyze (javascript-typescript, none)",
    "application",
    "chart",
    "container",
    "dependency-review",
    "security",
)
EXPECTED_MAIN_RULE_TYPES = frozenset(
    {
        "creation",
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
        "required_signatures",
        "code_scanning",
        "code_quality",
        "code_coverage",
    }
)
# The complete, closed set of pull-request rule parameters GitHub exposes for
# Protect-Main.  The compare against this dict is exact equality in both
# directions, so a field GitHub adds is as fatal as a field it drops: the
# publisher refuses to release onto a settings surface nobody re-anchored.
# That is what happened on 2026-08-20 (issue #91), when GitHub began returning
# require_extra_approval_for_unattributed_changes and every release from 0.1.20
# on denied with "pull-request rule parameters are not exact" until this pin
# grew to know it.  It is pinned True -- the live value AND the stricter
# direction: a commit whose author is not the pushing/attributed actor needs an
# extra approval.  Agent commits here are authored and committed as the owner's
# noreply identity and SSH-signed (AGENTS.md, "Commit identity mechanics"), so
# they are attributed and no flow changes.  Re-anchoring means extending this
# set deliberately, never relaxing the compare.
EXPECTED_PULL_REQUEST_PARAMETERS = {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews_on_push": False,
    "required_reviewers": [],
    "require_code_owner_review": False,
    "require_extra_approval_for_unattributed_changes": True,
    "require_last_push_approval": False,
    "required_review_thread_resolution": True,
    "allowed_merge_methods": ["squash", "rebase"],
}
EXPECTED_CODE_SCANNING_TOOLS = [
    {
        "tool": "CodeQL",
        "security_alerts_threshold": "high_or_higher",
        "alerts_threshold": "errors",
    }
]
RELEASE_MANIFEST_SCHEMA = "https://hospedajedonlolo.com/schemas/release-manifest/v1"
RELEASE_MANIFEST_WORKFLOW = ".github/workflows/release-publisher.yml"
RELEASE_MANIFEST_PLATFORMS = ["linux/amd64", "linux/arm64"]
TRIVY_VERSION = "0.72.0"
TRIVY_SEVERITIES = ["HIGH", "CRITICAL"]
# The closed inventory of the protected-main gate run, exact in both
# directions: a job missing its expected conclusion denies, and so does a job
# reporting a conclusion it is not supposed to reach. Two entries are
# `skipped` BY DESIGN, and both are pull-request-only conditions in
# pr-gate.yml -- dependency-review (no base/head pair exists on a push) and
# container (the merged tree is byte-identical to the tree its required PR
# check already built, and the released bytes are built, scanned, signed and
# attested by release-publisher.yml regardless). Those two pins are
# load-bearing the other way round too: a `container` job reporting `success`
# on a main push means the workflow condition is gone, so the inventory
# refuses it rather than releasing off a surface nobody re-anchored.
# This repository publishes no coverage badge and runs no other job in the
# gate: anything beyond these five is a foreign job this inventory refuses.
EXPECTED_MAIN_JOBS = {
    "application": "success",
    "chart": "success",
    "container": "skipped",
    "dependency-review": "skipped",
    "security": "success",
}
EXPECTED_CODEQL_JOBS = {
    "analyze (go, manual)": "success",
    "analyze (javascript-typescript, none)": "success",
    "analyze (python, none)": "success",
}
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
INTOTO_LAYER_MEDIA_TYPE = "application/vnd.in-toto+json"
SBOM_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SBOM_PREDICATE_TYPE = "https://spdx.dev/Document"


class ContractError(ValueError):
    """A release input cannot satisfy the immutable publication contract."""


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = SEMVER_RE.fullmatch(raw.strip())
        if not match:
            raise ContractError(f"invalid semantic version: {raw!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tag(self) -> str:
        return f"v{self}"


@dataclass(frozen=True)
class ReleaseIntent:
    source_sha: str
    version: Version

    @property
    def tag(self) -> str:
        return self.version.tag


@dataclass(frozen=True)
class TransitionWindow:
    base_sha: str
    intent: ReleaseIntent


def require_sha(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not SHA_RE.fullmatch(raw):
        raise ContractError(f"{field} must be one lowercase 40-hex commit SHA")
    return raw


def require_next_patch(base: Version, head: Version) -> None:
    expected = Version(base.major, base.minor, base.patch + 1)
    if head != expected:
        raise ContractError(f"head version {head} must be exact next patch {expected}")


def _top_level_scalar(text: str, key: str) -> str:
    values: list[str] = []
    for line in text.splitlines():
        if line == line.lstrip() and line.startswith(f"{key}:"):
            values.append(line.split(":", 1)[1].strip().strip("\"'"))
    if len(values) != 1 or not values[0]:
        raise ContractError(f"expected exactly one non-empty top-level {key!r} scalar")
    return values[0]


def _direct_child_scalar(text: str, parent: str, key: str) -> str:
    parents = [index for index, line in enumerate(text.splitlines()) if line.rstrip() == f"{parent}:"]
    if len(parents) != 1:
        raise ContractError(f"expected exactly one top-level {parent!r} mapping")
    lines = text.splitlines()
    values: list[str] = []
    for line in lines[parents[0] + 1 :]:
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            break
        if line.startswith(f"  {key}:"):
            values.append(line.split(":", 1)[1].strip().strip("\"'"))
    if len(values) != 1 or not values[0]:
        raise ContractError(f"expected exactly one non-empty {parent}.{key} scalar")
    return values[0]


CHANGELOG_CORRECTIONS_PATH = "scripts/ci/changelog-correction-allowlist.txt"
_CHANGELOG_BRACKET_HEADING_RE = re.compile(r"^## \[[^\]]*\].*$")
_CHANGELOG_RELEASED_HEADING_RE = re.compile(
    r"^## \[(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\]"
    r" - (?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})$"
)
_CHANGELOG_AGGREGATE_HEADING_RE = re.compile(
    r"^## \[(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\] and earlier$"
)
_CHANGELOG_UNRELEASED_HEADING = "## [Unreleased]"


@dataclass(frozen=True)
class ChangelogSection:
    """One released block: its heading facts and every byte beneath it."""

    version: Version
    date: dt.date
    heading: str
    body: str


def parse_changelog(text: str) -> list[ChangelogSection]:
    """Return every released section, in file order, or refuse the file's shape.

    A section runs from its own `## [X.Y.Z] - YYYY-MM-DD` heading to the next
    one, so the undated `## [X.Y.Z] and earlier` tail this repository imported
    is body text of the last dated section rather than a special case: the
    append-only comparison retains it byte-for-byte like any other released
    prose.

    Every OTHER `## [...]` heading is refused by shape, and that half is what
    makes the parse trustworthy rather than merely convenient. Without it,
    respelling a released heading -- an en dash for the hyphen, a stray space --
    would delete a release from this parse while leaving text on the page that
    still reads like history.
    """
    lines = text.split("\n")
    heading_indexes: list[int] = []
    released_indexes: list[int] = []
    for index, line in enumerate(lines):
        if not _CHANGELOG_BRACKET_HEADING_RE.fullmatch(line):
            continue
        heading_indexes.append(index)
        if _CHANGELOG_RELEASED_HEADING_RE.fullmatch(line):
            released_indexes.append(index)
        elif line != _CHANGELOG_UNRELEASED_HEADING and not (
            _CHANGELOG_AGGREGATE_HEADING_RE.fullmatch(line)
        ):
            raise ContractError(
                f"changelog heading {line!r} is neither {_CHANGELOG_UNRELEASED_HEADING!r}, a "
                "released `## [X.Y.Z] - YYYY-MM-DD` heading, nor the imported "
                "`## [X.Y.Z] and earlier` tail"
            )
    for index in heading_indexes:
        if _CHANGELOG_AGGREGATE_HEADING_RE.fullmatch(lines[index]) and index != heading_indexes[-1]:
            raise ContractError(
                "the `## [X.Y.Z] and earlier` aggregate heading may appear only as the last "
                "bracketed heading in the changelog"
            )
    sections: list[ChangelogSection] = []
    for position, start in enumerate(released_indexes):
        end = released_indexes[position + 1] if position + 1 < len(released_indexes) else len(lines)
        match = _CHANGELOG_RELEASED_HEADING_RE.fullmatch(lines[start])
        if match is None:  # pragma: no cover - released_indexes only holds matches
            raise ContractError("changelog released heading stopped matching mid-parse")
        try:
            date = dt.date.fromisoformat(match.group("date"))
        except ValueError as exc:
            raise ContractError(
                f"changelog release date {match.group('date')!r} is not a real ISO date"
            ) from exc
        sections.append(
            ChangelogSection(
                version=Version.parse(match.group("version")),
                date=date,
                heading=lines[start],
                body="\n".join(lines[start + 1 : end]),
            )
        )
    return sections


def require_changelog_history(text: str) -> list[ChangelogSection]:
    """Refuse a changelog whose released ladder is not a real release order.

    Shape only -- this half reads ONE snapshot and therefore cannot see a
    deletion. It denies a duplicated version, a reordered pair, an unparseable
    date, and a date that moves FORWARD as the file moves DOWN: states no
    sequence of releases can produce.
    """
    sections = parse_changelog(text)
    if not sections:
        raise ContractError("changelog carries no released `## [X.Y.Z] - YYYY-MM-DD` heading")
    for earlier, later in zip(sections, sections[1:]):
        if earlier.version == later.version:
            raise ContractError(f"changelog names version {earlier.version} more than once")
        if earlier.version < later.version:
            raise ContractError(
                f"changelog version {later.version} is listed below {earlier.version}; "
                "released headings must descend"
            )
        if earlier.date < later.date:
            raise ContractError(
                f"changelog date {later.date.isoformat()} for {later.version} is later than "
                f"{earlier.date.isoformat()} for {earlier.version} above it"
            )
    return sections


def parse_changelog_corrections(text: str) -> dict[Version, tuple[dt.date, dt.date, str]]:
    """Parse `<version> | <old date> | <new date> | <reason>` correction lines.

    THE LIFT, AND EXACTLY HOW NARROW IT IS. The append-only guard below is
    absolute about identity and order: no released version may be removed,
    reordered, duplicated, or have one byte of its entries rewritten, and no
    line in this file can permit any of that. The single thing a line here
    authorizes is a released heading's DATE moving from one stated value to
    another stated value, for one stated reason -- the correction issue #12
    needed, and the only historical edit this repository has had cause to make.

    An entry is spent the moment it lands: it names the exact old date, so once
    the base carries the corrected heading there is nothing left for it to
    authorize. That is why a spent entry is inert rather than an error -- unlike
    the workflow allowlist, whose subjects can be reoccupied by a later step of
    the same name, a consumed entry here is addressed to bytes that no longer
    exist anywhere in the ladder.
    """
    corrections: dict[Version, tuple[dt.date, dt.date, str]] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4 or not all(parts):
            raise ContractError(
                f"{CHANGELOG_CORRECTIONS_PATH}:{number}: expected exactly four non-empty "
                "`|`-separated fields -- `<version> | <old date> | <new date> | <reason>`"
            )
        raw_version, raw_old, raw_new, _reason = parts
        version = Version.parse(raw_version)
        try:
            old, new = dt.date.fromisoformat(raw_old), dt.date.fromisoformat(raw_new)
        except ValueError as exc:
            raise ContractError(
                f"{CHANGELOG_CORRECTIONS_PATH}:{number}: both dates must be real ISO dates"
            ) from exc
        if old == new:
            raise ContractError(
                f"{CHANGELOG_CORRECTIONS_PATH}:{number}: the two dates are identical, so this "
                "line authorizes nothing"
            )
        if version in corrections:
            raise ContractError(
                f"{CHANGELOG_CORRECTIONS_PATH}:{number}: version {version} is corrected twice"
            )
        corrections[version] = (old, new, parts[3])
    return corrections


def require_appended_changelog(
    base_text: str,
    head_text: str,
    corrections: Mapping[Version, tuple[dt.date, dt.date, str]] | None = None,
) -> None:
    """Prove the head changelog only ADDED to the base changelog (issue #105).

    The shape rules above constrain one file; only this base-to-head comparison
    proves append-only, which is the property `CHANGELOG.md` needs as the
    human-readable half of the release ledger. Every released section the base
    carried must survive in the head, in the same order, with its entries
    byte-identical; the only admissible difference is whole new sections added
    ABOVE all of them. A deleted middle or tail heading, a reordered pair, a
    rewritten historical entry, and a silently re-dated release all stop here.

    The failure this closes was mechanical, not hostile: an edit meant to insert
    a version block above a heading replaced the span down to and including it,
    orphaning one shipped release's entries under the next version's name -- with
    every release control still reporting success.
    """
    base_sections = require_changelog_history(base_text)
    head_sections = require_changelog_history(head_text)
    base_versions = {section.version for section in base_sections}
    # The added prefix is found by IDENTITY, not by arithmetic: counting would
    # read a range that adds one release and deletes another as an unchanged
    # ladder and then report the mismatch as a reorder, sending the next reader
    # to the wrong place. Everything from the first head section the base
    # already released onward is the RETAINED region, and it must be exactly
    # the base's own.
    added = 0
    while added < len(head_sections) and head_sections[added].version not in base_versions:
        added += 1
    retained = head_sections[added:]
    if len(retained) != len(base_sections):
        head_versions = {section.version for section in head_sections}
        missing = [str(section.version) for section in base_sections
                   if section.version not in head_versions]
        verb, count = (
            ("lost", len(base_sections) - len(retained))
            if len(retained) < len(base_sections)
            else ("inserted", len(retained) - len(base_sections))
        )
        raise ContractError(
            f"changelog {verb} {count} released heading(s) below its newest release: the base "
            f"carried {len(base_sections)} and the head retains {len(retained)}"
            + (f"; gone from the head: {', '.join(missing)}" if missing else "")
            + ". Released history is append-only, and a new release is added ABOVE every "
            "retained one"
        )
    corrections = dict(corrections or {})
    for base_section, head_section in zip(base_sections, retained):
        if base_section.version != head_section.version:
            raise ContractError(
                f"changelog released order changed: the base has {base_section.version} where the "
                f"head has {head_section.version}. Released history is append-only"
            )
        if base_section.body != head_section.body:
            raise ContractError(
                f"changelog entries under {base_section.version} were rewritten; a released block "
                "is retained byte-for-byte, never edited"
            )
        if base_section.date == head_section.date:
            continue
        authorized = corrections.get(base_section.version)
        if authorized is None or authorized[:2] != (base_section.date, head_section.date):
            raise ContractError(
                f"changelog re-dated {base_section.version} from {base_section.date.isoformat()} "
                f"to {head_section.date.isoformat()} with no matching line in "
                f"{CHANGELOG_CORRECTIONS_PATH}. Correcting a released date is a stated, reviewed "
                f"edit -- add `{base_section.version} | {base_section.date.isoformat()} | "
                f"{head_section.date.isoformat()} | <the record the new date comes from>` -- and "
                "nothing lifts a deletion, a reorder, or a rewritten entry"
            )


def _changelog_corrections(
    repository: Path, head_sha: str
) -> dict[Version, tuple[dt.date, dt.date, str]]:
    """Read the correction lift from the HEAD revision, fail-closed when absent.

    From the head because the authorization must ride in the same reviewed diff
    as the correction it authorizes; an absent file is no corrections at all,
    which denies rather than permits.
    """
    text = _git_file_optional(repository, head_sha, CHANGELOG_CORRECTIONS_PATH)
    return parse_changelog_corrections(text or "")


def validate_snapshot(files: Mapping[str, str]) -> ReleaseIntent:
    required = {"VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md"}
    missing = sorted(required.difference(files))
    if missing:
        raise ContractError(f"release snapshot is missing: {', '.join(missing)}")

    version = Version.parse(files["VERSION"])
    chart = files["chart/Chart.yaml"]
    values = files["chart/values.yaml"]
    if Version.parse(_top_level_scalar(chart, "version")) != version:
        raise ContractError("chart version does not equal VERSION")
    if Version.parse(_top_level_scalar(chart, "appVersion")) != version:
        raise ContractError("chart appVersion does not equal VERSION")
    if _direct_child_scalar(values, "image", "tag") != version.tag:
        raise ContractError("human image tag does not equal v<VERSION>")

    escaped = re.escape(str(version))
    headings = re.findall(rf"^## \[{escaped}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$", files["CHANGELOG.md"], re.MULTILINE)
    if len(headings) != 1:
        raise ContractError("changelog must contain exactly one dated current-version heading")
    try:
        dt.date.fromisoformat(headings[0])
    except ValueError as exc:
        raise ContractError("changelog release date is not a real ISO date") from exc
    top = re.compile(rf"^## \[Unreleased\]\s*\n+## \[{escaped}\] - {re.escape(headings[0])}$", re.MULTILINE)
    if not top.search(files["CHANGELOG.md"]):
        raise ContractError("current release must immediately follow an empty Unreleased heading")
    # Everything ABOVE was about the current version's heading alone, which left
    # every heading below it unguarded (issue #105). The ladder below it is now
    # constrained too, on every snapshot this contract reads.
    sections = require_changelog_history(files["CHANGELOG.md"])
    if sections[0].version != version:
        raise ContractError(
            f"changelog's topmost released heading is {sections[0].version}, not the "
            f"released version {version}"
        )
    return ReleaseIntent(source_sha="", version=version)


def require_publishable_digest(raw: object, field: str) -> str:
    """Return a digest that is well formed AND is not the fail-closed sentinel.

    Both halves are load-bearing and neither implies the other. The format
    check refuses a truncated, upper-case, or prefix-less value that would
    render an unpullable reference; the sentinel check refuses the one value
    that IS well formed and still unpullable, which is exactly the bug the
    embed exists to close. A substitution that wrote the sentinel back over
    itself would satisfy every syntactic check and publish the same broken
    chart.
    """
    digest = _require_digest(raw, field)
    if digest == CHART_DIGEST_SENTINEL:
        raise ContractError(f"{field} is the all-zeros fail-closed sentinel, not a resolved digest")
    return digest


def assert_chart_image_digest(values: str, digest: str) -> None:
    """Fail unless chart values carry exactly the expected resolved digest.

    Read-only, and deliberately usable against a PACKAGED chart: the publisher
    re-reads what `helm package` actually produced rather than trusting that
    the working-tree edit reached the archive.
    """
    expected = require_publishable_digest(digest, "expected image digest")
    if CHART_DIGEST_SENTINEL in values:
        raise ContractError("chart values still carry the all-zeros fail-closed digest sentinel")
    observed = _direct_child_scalar(values, "image", "digest")
    if observed != expected:
        raise ContractError(f"chart image digest {observed!r} is not the resolved digest {expected!r}")


def embed_chart_image_digest(values: str, digest: str) -> str:
    """Return chart values with the sentinel replaced by the resolved digest.

    The source text must still carry the sentinel: a values file that already
    names some other digest is either committed source drift (acceptance 4 says
    the committed tree keeps the sentinel) or a second substitution over an
    already-substituted tree, and neither may be silently rewritten. Exactly one
    line may match, and the result is re-asserted before it is returned, so no
    caller can receive a half-substituted document.
    """
    expected = require_publishable_digest(digest, "embedded image digest")
    observed = _direct_child_scalar(values, "image", "digest")
    if observed != CHART_DIGEST_SENTINEL:
        raise ContractError(
            f"chart image digest is {observed!r}; the committed chart must carry the "
            "all-zeros fail-closed sentinel before substitution"
        )
    embedded, substitutions = CHART_DIGEST_LINE_RE.subn(lambda _match: f"  digest: {expected}", values)
    if substitutions != 1:
        raise ContractError(
            f"chart values must carry exactly one substitutable image digest line, found {substitutions}"
        )
    assert_chart_image_digest(embedded, expected)
    return embedded


def _git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def _git_file(repository: Path, revision: str, path: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError(f"{path} is absent at {revision}")
    return completed.stdout


def _git_file_optional(repository: Path, revision: str, path: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repository), "show", f"{revision}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _version_at(repository: Path, revision: str) -> Version | None:
    raw = _git_file_optional(repository, revision, "VERSION")
    return Version.parse(raw) if raw is not None else None


def _linear_commits(repository: Path, base_sha: str, head_sha: str) -> list[str]:
    """Return every commit in one contiguous, merge-free base..head range."""
    _git(repository, "merge-base", "--is-ancestor", base_sha, head_sha)
    raw = _git(repository, "rev-list", "--first-parent", "--reverse", f"{base_sha}..{head_sha}")
    commits = raw.splitlines() if raw else []
    if not commits or commits[-1] != head_sha:
        raise ContractError("release range is empty or does not end at the exact head")
    previous = base_sha
    for commit in commits:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", commit).split()
        if len(fields) != 2 or fields[0] != commit or fields[1] != previous:
            raise ContractError("release range must be one contiguous linear commit chain")
        previous = commit
    return commits


def _first_parent_history(repository: Path, head_sha: str) -> list[str]:
    """Return the complete ordered mainline ending at one exact head.

    The imported pre-policy history contains ordinary GitHub merge commits, so
    the immutable historical ledger follows their first-parent mainline. New
    release ranges remain merge-free through ``_linear_commits`` above.
    """
    raw = _git(repository, "rev-list", "--first-parent", "--reverse", head_sha)
    commits = raw.splitlines() if raw else []
    if not commits or commits[-1] != head_sha:
        raise ContractError("release history is empty or does not end at the exact head")
    previous: str | None = None
    for commit in commits:
        fields = _git(repository, "rev-list", "--parents", "-n", "1", commit).split()
        if fields[0] != commit:
            raise ContractError("release history commit identity is not exact")
        if previous is None:
            if len(fields) != 1:
                raise ContractError("release history root must have no parent")
        elif len(fields) < 2 or fields[1] != previous:
            raise ContractError("release history first-parent chain is not contiguous")
        previous = commit
    return commits


def _monotonic_transitions(
    repository: Path, base_sha: str, commits: list[str]
) -> list[tuple[str, str, Version]]:
    """Classify every exact patch boundary and reject transient states."""
    current = _version_at(repository, base_sha)
    if current is None:
        raise ContractError("release transition base must contain VERSION")
    previous = base_sha
    transitions: list[tuple[str, str, Version]] = []
    for commit in commits:
        observed = _version_at(repository, commit)
        if observed == current:
            previous = commit
            continue
        expected = Version(current.major, current.minor, current.patch + 1)
        if observed != expected:
            rendered = "absent" if observed is None else str(observed)
            raise ContractError(
                f"commit {commit} version {rendered} must remain at {current} "
                f"or advance exactly once to {expected}"
            )
        transitions.append((previous, commit, expected))
        current = expected
        previous = commit
    return transitions


def _validated_history_transitions(
    repository: Path, head_sha: str
) -> list[tuple[str, str, Version]]:
    """Prove every publisher-visible VERSION state on the mainline.

    This standalone repository imported a trusted legacy history whose first
    committed VERSION was 0.1.3, rather than initializing at 0.1.0. The first
    present value is therefore the historical baseline; every later state is
    still exhaustively constrained to retain it or advance one arithmetic
    patch, with deletion, skip, reversion, and transient futures denied.
    """
    history = _first_parent_history(repository, head_sha)
    baseline_index: int | None = None
    for index, commit in enumerate(history):
        if _version_at(repository, commit) is not None:
            baseline_index = index
            break
    if baseline_index is None:
        raise ContractError("release history contains no VERSION baseline")
    baseline = history[baseline_index]
    return _monotonic_transitions(repository, baseline, history[baseline_index + 1 :])


DOCUMENTATION_FILES = frozenset({"AGENTS.md", "README.md", ".gitignore"})
DOCUMENTATION_TREE = "docs/"
RELEASE_LOCK_PATHS = ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
_DOCUMENTATION_DIFF_MODES = frozenset({"000000", "100644", "100755"})
_DOCUMENTATION_DIFF_STATUSES = frozenset({"A", "D", "M"})


def is_documentation_path(path: str) -> bool:
    """Classify one repo-relative path as documentation-only surface.

    The allowlist is deliberately closed: root AGENTS.md, README.md, and
    .gitignore, plus Markdown files under docs/. Everything else — release
    locks, scripts, workflows, application and chart trees, LICENSE — is an
    artifact surface, so widening this set is itself a released gate change.
    """
    if path in DOCUMENTATION_FILES:
        return True
    return path.startswith(DOCUMENTATION_TREE) and path.endswith(".md")


def _diff_entries(repository: Path, base: str, commit: str) -> list[tuple[str, str, str, str]]:
    """Return (src_mode, dst_mode, status, path) for one commit-over-base diff."""
    completed = subprocess.run(
        ["git", "-C", str(repository), "diff", "--raw", "-z", "--no-renames", "--no-color", base, commit],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ContractError(f"git diff walk failed between {base} and {commit}")
    try:
        raw = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"diff between {base} and {commit} carries undecodable paths") from exc
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2 != 0:
        raise ContractError(f"diff between {base} and {commit} is not meta/path paired")
    entries: list[tuple[str, str, str, str]] = []
    for meta, path in zip(fields[0::2], fields[1::2]):
        # --no-renames guarantees two-field records; an R/C record would
        # carry a second path and silently shift this pairing, so the meta
        # shape is pinned strictly enough that any such record denies.
        if not re.fullmatch(r":[0-7]{6} [0-7]{6} [0-9a-f]{7,64} [0-9a-f]{7,64} [ACDMTUX]", meta) or not path:
            raise ContractError(f"diff entry between {base} and {commit} is malformed")
        parts = meta.split(" ")
        entries.append((parts[0][1:], parts[1], parts[4], path))
    return entries


def _undocumented_paths(repository: Path, base: str, commit: str) -> list[str]:
    """Return every changed path that is not a plain-file documentation edit."""
    offending: list[str] = []
    for src_mode, dst_mode, status, path in _diff_entries(repository, base, commit):
        if status not in _DOCUMENTATION_DIFF_STATUSES:
            offending.append(path)
            continue
        if src_mode not in _DOCUMENTATION_DIFF_MODES or dst_mode not in _DOCUMENTATION_DIFF_MODES:
            offending.append(path)
            continue
        if not is_documentation_path(path):
            offending.append(path)
    return offending


def classify_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> dict[str, object]:
    """Classify one protected range as artifact or no-artifact, fail closed.

    Any path anywhere in the range outside the documentation allowlist puts
    the whole range under the unchanged one-exact-patch release contract via
    ``validate_transition`` — including its exhaustive mainline-history
    cross-check. Only a range whose every commit is individually confined to
    documentation surfaces — so the artifact cannot have changed — classifies
    as no-artifact, and even then the range must cross no patch boundary,
    every release lock must be byte-identical from base to head, and the
    retained head snapshot must still validate. There is no flag, environment
    variable, or third verdict.
    """
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    commits = _linear_commits(repository, base_sha, head_sha)
    offending: list[str] = []
    previous = base_sha
    for commit in commits:
        offending.extend(_undocumented_paths(repository, previous, commit))
        previous = commit
    if offending:
        if not _monotonic_transitions(repository, base_sha, commits):
            raise ContractError(
                "artifact-surface paths changed without one exact release patch: "
                + ", ".join(sorted(set(offending))[:8])
            )
        intent = validate_transition(repository, base_sha, head_sha, first_parent=first_parent)
        return {
            "class": "artifact",
            "base_sha": base_sha,
            "source_sha": intent.source_sha,
            "version": str(intent.version),
            "tag": intent.tag,
        }
    boundaries = _monotonic_transitions(repository, base_sha, commits)
    if boundaries:
        raise ContractError(
            "documentation-only range must contain exactly 0 one-patch "
            f"boundaries; found {len(boundaries)}"
        )
    for path in RELEASE_LOCK_PATHS:
        if _git_file(repository, base_sha, path) != _git_file(repository, head_sha, path):
            raise ContractError(f"documentation-only range mutated release lock {path}")
    head_files = {
        path: _git_file(repository, head_sha, path) for path in RELEASE_LOCK_PATHS
    }
    retained = validate_snapshot(head_files)
    return {
        "class": "no-artifact",
        "base_sha": base_sha,
        "source_sha": head_sha,
        "version": str(retained.version),
        "tag": retained.tag,
        "commits": len(commits),
    }


def validate_transition(repository: Path, base_sha: str, head_sha: str, *, first_parent: bool) -> ReleaseIntent:
    base_sha = require_sha(base_sha, "base SHA")
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ContractError("base SHA did not resolve exactly")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    commits = _linear_commits(repository, base_sha, head_sha)
    transitions = _monotonic_transitions(repository, base_sha, commits)
    if len(transitions) != 1:
        raise ContractError("release range must contain exactly one patch boundary")
    history_transitions = _validated_history_transitions(repository, head_sha)
    if not history_transitions or history_transitions[-1] != transitions[0]:
        raise ContractError(
            "release range boundary is not the exact publisher-visible boundary"
        )
    base_version = Version.parse(_git_file(repository, base_sha, "VERSION"))
    head_files = {
        path: _git_file(repository, head_sha, path)
        for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
    }
    head = validate_snapshot(head_files)
    # Released changelog history is append-only (issue #105). The snapshot half
    # above cannot see a deletion -- a file missing three releases is a
    # perfectly well-formed file -- so the ledger's retention is proven here,
    # against the protected base this range actually advances from.
    require_appended_changelog(
        _git_file(repository, base_sha, "CHANGELOG.md"),
        head_files["CHANGELOG.md"],
        _changelog_corrections(repository, head_sha),
    )
    # A squash merge is a one-commit range; GitHub's enabled rebase merge can
    # install several commits atomically. The source identity is the complete
    # final tree, while the exact base -> head patch step remains one release
    # intent regardless of how many linear commits carried that tree there.
    require_next_patch(base_version, head.version)
    return ReleaseIntent(source_sha=head_sha, version=head.version)


def discover_transition_window(repository: Path, head_sha: str) -> TransitionWindow:
    """Recover the last boundary from the exhaustively validated mainline."""
    head_sha = require_sha(head_sha, "head SHA")
    if _git(repository, "rev-parse", f"{head_sha}^{{commit}}") != head_sha:
        raise ContractError("head SHA did not resolve exactly")
    transitions = _validated_history_transitions(repository, head_sha)
    if not transitions:
        raise ContractError("release history contains no patch boundary")
    head_files = {
        path: _git_file(repository, head_sha, path)
        for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")
    }
    head = validate_snapshot(head_files)
    base_sha, _transition_commit, transition_version = transitions[-1]
    if transition_version != head.version:
        raise ContractError("release head does not retain the last patch boundary")
    return TransitionWindow(
        base_sha=base_sha,
        intent=ReleaseIntent(source_sha=head_sha, version=head.version),
    )


def plan_workflow_run(event: Mapping[str, object], expected_repository: str) -> str:
    repository = event.get("repository")
    run = event.get("workflow_run")
    if not isinstance(repository, Mapping) or repository.get("full_name") != expected_repository:
        raise ContractError("workflow_run repository identity mismatch")
    if not isinstance(run, Mapping):
        raise ContractError("workflow_run payload is absent")
    exact = {
        "name": EXPECTED_WORKFLOW,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"workflow_run {key} must equal {expected!r}")
    path = run.get("path")
    if not isinstance(path, str) or path.split("@", 1)[0] != EXPECTED_WORKFLOW_PATH:
        raise ContractError("workflow_run path is not the protected PR gate")
    head_repository = run.get("head_repository")
    if not isinstance(head_repository, Mapping) or head_repository.get("full_name") != expected_repository:
        raise ContractError("workflow_run head repository identity mismatch")
    return require_sha(run.get("head_sha"), "workflow_run head SHA")


def validate_main_run_record(
    run: Mapping[str, object],
    *,
    expected_repository: str,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Bind a publisher request to one authoritative successful main run."""
    if (
        isinstance(expected_run_id, bool)
        or not isinstance(expected_run_id, int)
        or expected_run_id <= 0
        or run.get("id") != expected_run_id
    ):
        raise ContractError("Actions run ID is not the exact positive requested run ID")
    repository = _object(run.get("repository"), "Actions run repository")
    head_repository = _object(run.get("head_repository"), "Actions run head repository")
    if repository.get("full_name") != expected_repository:
        raise ContractError("Actions run repository identity mismatch")
    if head_repository.get("full_name") != expected_repository:
        raise ContractError("Actions run head repository identity mismatch")
    exact = {
        "name": EXPECTED_WORKFLOW,
        "path": EXPECTED_WORKFLOW_PATH,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"Actions run {key} must equal {expected!r}")
    source_sha = require_sha(expected_source_sha, "publisher source SHA")
    if require_sha(run.get("head_sha"), "Actions run head SHA") != source_sha:
        raise ContractError("successful main run does not bind the requested source SHA")
    return source_sha


def validate_main_jobs_record(
    record: Mapping[str, object],
    *,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Require the exact completed job set, not only a successful run summary."""
    if isinstance(expected_run_id, bool) or expected_run_id <= 0:
        raise ContractError("Actions jobs run ID must be positive")
    source_sha = require_sha(expected_source_sha, "Actions jobs source SHA")
    jobs = _array(record.get("jobs"), "Actions jobs")
    total_count = record.get("total_count")
    if isinstance(total_count, bool) or total_count != len(jobs):
        raise ContractError("Actions jobs total_count does not equal the returned job count")
    if len(jobs) != len(EXPECTED_MAIN_JOBS):
        raise ContractError("successful main run does not contain the exact job count")

    observed: dict[str, str] = {}
    job_ids: set[int] = set()
    for raw_job in jobs:
        job = _object(raw_job, "Actions job")
        job_id = job.get("id")
        if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
            raise ContractError("Actions job ID must be a positive integer")
        if job_id in job_ids:
            raise ContractError("Actions jobs contain a duplicate job ID")
        job_ids.add(job_id)
        if job.get("run_id") != expected_run_id:
            raise ContractError("Actions job belongs to a different run")
        if require_sha(job.get("head_sha"), "Actions job head SHA") != source_sha:
            raise ContractError("Actions job belongs to a different source SHA")
        name = job.get("name")
        if not isinstance(name, str) or name not in EXPECTED_MAIN_JOBS:
            raise ContractError("Actions jobs contain a missing or foreign job name")
        if name in observed:
            raise ContractError("Actions jobs contain a duplicate job name")
        if job.get("status") != "completed":
            raise ContractError(f"Actions job {name!r} is not completed")
        conclusion = job.get("conclusion")
        if conclusion != EXPECTED_MAIN_JOBS[name]:
            raise ContractError(
                f"Actions job {name!r} conclusion must equal "
                f"{EXPECTED_MAIN_JOBS[name]!r}"
            )
        observed[name] = conclusion
    if observed != EXPECTED_MAIN_JOBS:
        raise ContractError("successful main run job inventory is not exact")
    return source_sha


def classify_codeql_run_record(
    record: Mapping[str, object],
    *,
    expected_repository: str,
    expected_source_sha: str,
) -> int | None:
    """Resolve exactly one CodeQL push run for the authorized main SHA."""
    source_sha = require_sha(expected_source_sha, "CodeQL source SHA")
    runs = _array(record.get("workflow_runs"), "CodeQL workflow runs")
    total_count = record.get("total_count")
    if isinstance(total_count, bool) or total_count != len(runs):
        raise ContractError("CodeQL run total_count does not equal the returned run count")
    if not runs:
        return None
    if len(runs) != 1:
        raise ContractError("CodeQL exact-SHA query returned duplicate or foreign runs")
    run = _object(runs[0], "CodeQL workflow run")
    run_id = run.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise ContractError("CodeQL run ID must be a positive integer")
    repository = _object(run.get("repository"), "CodeQL run repository")
    head_repository = _object(run.get("head_repository"), "CodeQL run head repository")
    if repository.get("full_name") != expected_repository:
        raise ContractError("CodeQL run repository identity mismatch")
    if head_repository.get("full_name") != expected_repository:
        raise ContractError("CodeQL run head repository identity mismatch")
    exact = {
        "name": EXPECTED_CODEQL_WORKFLOW,
        "path": EXPECTED_CODEQL_WORKFLOW_PATH,
        "event": "push",
        "head_branch": "main",
        "head_sha": source_sha,
    }
    for key, expected in exact.items():
        if run.get(key) != expected:
            raise ContractError(f"CodeQL run {key} must equal {expected!r}")
    status = run.get("status")
    if status in {"queued", "in_progress", "waiting", "requested", "pending"}:
        if run.get("conclusion") is not None:
            raise ContractError("incomplete CodeQL run already has a conclusion")
        return None
    if status != "completed" or run.get("conclusion") != "success":
        raise ContractError("exact-SHA CodeQL run is not completed successfully")
    return run_id


def validate_codeql_jobs_record(
    record: Mapping[str, object],
    *,
    expected_run_id: int,
    expected_source_sha: str,
) -> str:
    """Require every exact CodeQL matrix job to complete successfully."""
    if isinstance(expected_run_id, bool) or expected_run_id <= 0:
        raise ContractError("CodeQL jobs run ID must be positive")
    source_sha = require_sha(expected_source_sha, "CodeQL jobs source SHA")
    jobs = _array(record.get("jobs"), "CodeQL jobs")
    total_count = record.get("total_count")
    if isinstance(total_count, bool) or total_count != len(jobs):
        raise ContractError("CodeQL jobs total_count does not equal the returned job count")
    if len(jobs) != len(EXPECTED_CODEQL_JOBS):
        raise ContractError("CodeQL run does not contain the exact job count")
    observed: dict[str, str] = {}
    job_ids: set[int] = set()
    for raw_job in jobs:
        job = _object(raw_job, "CodeQL job")
        job_id = job.get("id")
        if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
            raise ContractError("CodeQL job ID must be positive")
        if job_id in job_ids:
            raise ContractError("CodeQL jobs contain a duplicate job ID")
        job_ids.add(job_id)
        if job.get("run_id") != expected_run_id:
            raise ContractError("CodeQL job belongs to a different run")
        if require_sha(job.get("head_sha"), "CodeQL job head SHA") != source_sha:
            raise ContractError("CodeQL job belongs to a different source SHA")
        name = job.get("name")
        if not isinstance(name, str) or name not in EXPECTED_CODEQL_JOBS:
            raise ContractError("CodeQL jobs contain a missing or foreign matrix identity")
        if name in observed:
            raise ContractError("CodeQL jobs contain a duplicate matrix identity")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise ContractError(f"CodeQL job {name!r} is not completed successfully")
        observed[name] = "success"
    if observed != EXPECTED_CODEQL_JOBS:
        raise ContractError("CodeQL job inventory is not exact")
    return source_sha


def validate_release_destinations(repository: str, image: str, chart: str) -> None:
    """Bind the dotted repository identity to explicit GHCR package names."""
    if repository != EXPECTED_REPOSITORY:
        raise ContractError("release repository identity is not exact")
    if image != EXPECTED_IMAGE:
        raise ContractError("release image package identity is not exact")
    if chart != EXPECTED_CHART:
        raise ContractError("release chart package identity is not exact")


def validate_publisher(
    root: Path,
    source_sha: str,
    checkout_sha: str,
    ref: str,
    event_name: str,
    repository: str,
    workflow_ref: str,
    image: str,
    chart: str,
) -> ReleaseIntent:
    source_sha = require_sha(source_sha, "publisher source SHA")
    checkout_sha = require_sha(checkout_sha, "publisher checkout SHA")
    if event_name != "workflow_dispatch":
        raise ContractError("publisher accepts only explicit workflow_dispatch")
    if ref != "refs/heads/main":
        raise ContractError("publisher workflow must be selected from protected main")
    expected_workflow_ref = f"{repository}/{EXPECTED_PUBLISHER_PATH}@refs/heads/main"
    if workflow_ref != expected_workflow_ref:
        raise ContractError("publisher workflow identity is not protected main")
    validate_release_destinations(repository, image, chart)
    if source_sha != checkout_sha:
        raise ContractError("publisher source SHA does not equal the authorized checkout")
    files = {path: (root / path).read_text(encoding="utf-8") for path in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md")}
    intent = validate_snapshot(files)
    return ReleaseIntent(source_sha=source_sha, version=intent.version)


def _object(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field} must be a JSON object")
    return value


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{field} must be a JSON array")
    return value


def _string_set(value: object, field: str) -> set[str]:
    values = _array(value, field)
    if any(not isinstance(item, str) or not item for item in values):
        raise ContractError(f"{field} must contain only non-empty strings")
    result = set(values)
    if len(result) != len(values):
        raise ContractError(f"{field} must not contain duplicates")
    return result


def _exact_pin(actual: object, expected: object) -> bool:
    """Compare one pinned settings value with bool/int conflation closed.

    Python evaluates ``True == 1`` and ``False == 0`` as true, so a plain
    ``==`` against a pinned boolean ALSO accepts the integers 1 and 0, and a
    pin of the integer 0 also accepts ``False``.  Both directions are live
    holes in the settings validators: GitHub speaks JSON, where ``true`` and
    ``1`` are different tokens, so a record carrying the wrong one means the
    enforcing surface moved out from under the anchor -- exactly what
    ``require_extra_approval_for_unattributed_changes`` did on 2026-08-20
    (issue #91) -- and it must deny instead of round-tripping into the
    receipt.  Issue #93.  Fail-closed direction only: nothing a genuine
    boolean or a genuine integer used to satisfy stops satisfying.
    """
    if isinstance(actual, bool) != isinstance(expected, bool):
        return False
    return actual == expected


def _exact_pin_mapping(actual: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    """Exact both-direction mapping compare with ``_exact_pin`` per value."""
    if set(actual) != set(expected):
        return False
    return all(_exact_pin(actual[key], expected[key]) for key in expected)


def _status_check_set(value: object) -> set[tuple[str, int]]:
    checks: set[tuple[str, int]] = set()
    values = _array(value, "required status checks")
    for item in values:
        record = _object(item, "required status check")
        if set(record) != {"context", "integration_id"}:
            raise ContractError("required status check fields are missing or foreign")
        context = record.get("context")
        integration_id = record.get("integration_id")
        if not isinstance(context, str) or not context:
            raise ContractError("required status check context must be non-empty")
        if isinstance(integration_id, bool) or not isinstance(integration_id, int):
            raise ContractError("required status check integration_id must be an integer")
        check = (context, integration_id)
        if check in checks:
            raise ContractError("required status checks must not contain duplicates")
        checks.add(check)
    return checks


def validate_immutable_settings(settings: Mapping[str, object]) -> None:
    """Require the authoritative repository immutable-release control."""
    if set(settings) != {"enabled", "enforced_by_owner"}:
        raise ContractError("immutable-release settings fields are missing or foreign")
    if settings.get("enabled") is not True:
        raise ContractError("GitHub immutable releases must be enabled")
    if not isinstance(settings.get("enforced_by_owner"), bool):
        raise ContractError("immutable-release owner-enforcement state must be boolean")


def validate_private_vulnerability_reporting(settings: Mapping[str, object]) -> None:
    """Require the authoritative private vulnerability reporting control."""
    if set(settings) != {"enabled"}:
        raise ContractError(
            "private-vulnerability-reporting settings fields are missing or foreign"
        )
    if settings.get("enabled") is not True:
        raise ContractError("GitHub private vulnerability reporting must be enabled")


def validate_settings_receipt(receipt: Mapping[str, object], repository: str) -> None:
    """Validate the closed, value-only release-readiness receipt."""
    fields = {
        "active_main_branch_ruleset_count",
        "allow_deletions",
        "allow_force_pushes",
        "branch",
        "code_quality_severity",
        "code_scanning_tools",
        "dismiss_stale_reviews_on_push",
        "maximum_code_coverage_drop",
        "merge_methods",
        "minimum_code_coverage",
        "private_vulnerability_reporting",
        "repository",
        "require_code_owner_review",
        "require_extra_approval_for_unattributed_changes",
        "require_last_push_approval",
        "require_linear_history",
        "require_pull_request",
        "required_approving_review_count",
        "required_review_thread_resolution",
        "required_reviewers",
        "require_signed_commits",
        "required_status_checks",
        "restrict_creations",
        "restrict_updates",
        "strict_status_checks",
    }
    if set(receipt) != fields:
        raise ContractError("settings receipt fields are missing or foreign")
    # The inventory count is what closes the gap the retired owner-update
    # ruleset opened: `restrict_updates` describes Protect-Main alone, so a
    # second active branch ruleset could carry the `update` rule — and the
    # bypass actor that rule needs to stay mergeable — where this receipt
    # never looked. Exactly one active repository-owned branch ruleset means
    # the rule types and the bypass state this receipt does state are the
    # whole branch-protection story. Type-exact: `True == 1` in Python.
    count = receipt.get("active_main_branch_ruleset_count")
    if type(count) is not int or count != ACTIVE_MAIN_BRANCH_RULESETS:
        raise ContractError(
            "exactly one active repository-owned branch ruleset may protect main"
        )
    if receipt.get("repository") != repository or receipt.get("branch") != "main":
        raise ContractError("settings receipt repository or branch is not exact")
    if _string_set(receipt.get("merge_methods"), "merge methods") != {"rebase", "squash"}:
        raise ContractError("only squash and rebase merge methods may be enabled")
    expected_checks = {
        (context, GITHUB_ACTIONS_INTEGRATION_ID) for context in REQUIRED_STATUS_CHECKS
    }
    if _status_check_set(receipt.get("required_status_checks")) != expected_checks:
        raise ContractError("required GitHub Actions checks are missing, foreign, or unbound")
    for field, expected in (
        ("private_vulnerability_reporting", True),
        ("strict_status_checks", True),
        ("require_pull_request", True),
        ("require_linear_history", True),
        ("require_signed_commits", True),
        ("restrict_creations", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
        ("restrict_updates", False),
    ):
        if receipt.get(field) is not expected:
            raise ContractError(f"settings receipt {field} must be {expected}")
    expected_pull_receipt = {
        key: value
        for key, value in EXPECTED_PULL_REQUEST_PARAMETERS.items()
        if key != "allowed_merge_methods"
    }
    for field, expected in expected_pull_receipt.items():
        if not _exact_pin(receipt.get(field), expected):
            raise ContractError(f"settings receipt {field} is not exact")
    if receipt.get("code_scanning_tools") != EXPECTED_CODE_SCANNING_TOOLS:
        raise ContractError("settings receipt code-scanning tools are not exact")
    if receipt.get("code_quality_severity") != "errors":
        raise ContractError("settings receipt code-quality severity is not exact")
    if receipt.get("minimum_code_coverage") != 80:
        raise ContractError("settings receipt minimum code coverage is not exact")
    if receipt.get("maximum_code_coverage_drop") is not None:
        raise ContractError("settings receipt maximum code-coverage drop is not exact")


#: Exactly `Protect-Main`. The `Owner-PR-Updates` restriction was retired on
#: 2026-09-22 by owner directive: its one `update` rule made the repository
#: owner's bypass the only way to merge a passing pull request, from any
#: device. Nothing replaces it — the core ruleset already denies creation,
#: deletion and force pushes, and it carries no `update` rule at all.
ACTIVE_MAIN_BRANCH_RULESETS = 1


def _select_main_ruleset_id(summaries: object, repository: str) -> int:
    selected: dict[str, int] = {}
    for value in _array(summaries, "repository rulesets"):
        summary = _object(value, "repository ruleset summary")
        if summary.get("target") != "branch" or summary.get("enforcement") != "active":
            continue
        name, ruleset_id = summary.get("name"), summary.get("id")
        if (name != EXPECTED_MAIN_RULESET or name in selected
                or summary.get("source_type") != "Repository"
                or summary.get("source") != repository
                or type(ruleset_id) is not int or ruleset_id <= 0):
            raise ContractError("active main ruleset inventory is foreign or ambiguous")
        selected[name] = ruleset_id
    if len(selected) != ACTIVE_MAIN_BRANCH_RULESETS:
        raise ContractError("exactly the core security branch ruleset is required")
    return selected[EXPECTED_MAIN_RULESET]



def build_settings_receipt(
    repository: str,
    repository_record: Mapping[str, object],
    private_vulnerability_record: Mapping[str, object],
    ruleset_id: int,
    ruleset_record: Mapping[str, object],
) -> dict[str, object]:
    """Derive and validate a privacy-bounded receipt from authoritative REST."""
    if repository_record.get("full_name") != repository or repository_record.get("default_branch") != "main":
        raise ContractError("repository settings identity or default branch is not exact")
    # This receipt is built from what the workflow's own short-lived
    # `github.token` (contents: read) can read on a public repository: the
    # repository identity, private vulnerability reporting, and every
    # Protect-Main rule and parameter, and nothing more. The
    # Administration-only surfaces (Actions policy, default token permissions,
    # the repository record's security_and_analysis block, the
    # immutable-releases switch) are not observable with that token, so they
    # are neither read nor asserted here; reading one would deny every run
    # rather than prove anything. Immutability is still enforced per release,
    # because the Release state machine refuses a published Release that does
    # not report `immutable: true`, and the rest is the owner-verified column of
    # docs/release-governance.md.
    validate_private_vulnerability_reporting(private_vulnerability_record)

    if (
        ruleset_record.get("id") != ruleset_id
        or ruleset_record.get("name") != EXPECTED_MAIN_RULESET
        or ruleset_record.get("target") != "branch"
        or ruleset_record.get("source_type") != "Repository"
        or ruleset_record.get("source") != repository
        or ruleset_record.get("enforcement") != "active"
    ):
        raise ContractError("Protect-Main ruleset identity or enforcement is not exact")
    conditions = _object(ruleset_record.get("conditions"), "Protect-Main conditions")
    if set(conditions) != {"ref_name"}:
        raise ContractError("Protect-Main conditions are missing or foreign")
    ref_name = _object(conditions.get("ref_name"), "Protect-Main ref condition")
    if set(ref_name) != {"exclude", "include"} or ref_name.get("exclude") != [] or ref_name.get(
        "include"
    ) != ["refs/heads/main"]:
        raise ContractError("Protect-Main must target only refs/heads/main")

    # bypass_actors is deliberately neither read nor asserted here.  GitHub's
    # REST reference for "Get a repository ruleset" states: "To prevent leaking
    # sensitive information, the bypass_actors property is only returned if the
    # user making the API request has write access to the ruleset."  The
    # settings job's `github.token` holds contents read alone, so the property
    # is simply absent from its response, and reading it would deny every run
    # before rules[] was ever parsed.  CI asserts exactly what the enforcing surface exposes to the CI
    # credential, with no conditional assertion and no credential-dependent
    # branch.  The no-bypass invariant is not abandoned: because this deletion
    # is credential-independent, no preflight run reads the property, so it is
    # discharged instead by the standalone GET-only bypass command the owner
    # runs under a ruleset-write credential, which docs/release-governance.md
    # records in the owner-verified column.
    rules_by_type: dict[str, Mapping[str, object]] = {}
    for value in _array(ruleset_record.get("rules"), "Protect-Main rules"):
        rule = _object(value, "Protect-Main rule")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type or rule_type in rules_by_type:
            raise ContractError("Protect-Main rule types must be non-empty and unique")
        rules_by_type[rule_type] = rule
    if set(rules_by_type) != EXPECTED_MAIN_RULE_TYPES:
        raise ContractError("Protect-Main rule types are missing or foreign")
    for rule_type in (
        "creation",
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "required_signatures",
    ):
        if set(rules_by_type[rule_type]) != {"type"}:
            raise ContractError(f"Protect-Main {rule_type} rule is malformed")

    pull_request = rules_by_type.get("pull_request")
    if pull_request is None:
        raise ContractError("Protect-Main must require pull requests")
    pull_parameters = _object(pull_request.get("parameters"), "pull-request rule parameters")
    if set(pull_request) != {"type", "parameters"}:
        raise ContractError("pull-request rule fields are missing or foreign")
    if not _exact_pin_mapping(pull_parameters, EXPECTED_PULL_REQUEST_PARAMETERS):
        raise ContractError("pull-request rule parameters are not exact")
    # The ruleset is the authoritative merge-method source: it is what actually
    # enforces merge behaviour on refs/heads/main, and unlike the repository
    # record's allow_*_merge booleans it is readable by the settings job's
    # read-only `github.token`.  GitHub returns those booleans only to
    # credentials carrying Contents write visibility, so deriving from them
    # would make this receipt unbuildable under that least-privilege token.
    merge_methods = _string_set(
        pull_parameters.get("allowed_merge_methods"), "ruleset merge methods"
    )

    status_rule = rules_by_type.get("required_status_checks")
    if status_rule is None:
        raise ContractError("Protect-Main must require exact status checks")
    status_parameters = _object(status_rule.get("parameters"), "status-check rule parameters")
    if set(status_rule) != {"type", "parameters"} or set(status_parameters) != {
        "do_not_enforce_on_create",
        "required_status_checks",
        "strict_required_status_checks_policy",
    }:
        raise ContractError("required-status-check rule fields are missing or foreign")
    if status_parameters.get("do_not_enforce_on_create") is not False:
        raise ContractError("required checks must also apply when the ref is created")
    status_checks = _status_check_set(status_parameters.get("required_status_checks"))

    code_scanning = rules_by_type["code_scanning"]
    code_scanning_parameters = _object(
        code_scanning.get("parameters"), "code-scanning rule parameters"
    )
    if (
        set(code_scanning) != {"type", "parameters"}
        or set(code_scanning_parameters) != {"code_scanning_tools"}
        or code_scanning_parameters.get("code_scanning_tools")
        != EXPECTED_CODE_SCANNING_TOOLS
    ):
        raise ContractError("code-scanning rule is not exact")
    code_quality = rules_by_type["code_quality"]
    code_quality_parameters = _object(
        code_quality.get("parameters"), "code-quality rule parameters"
    )
    if (
        set(code_quality) != {"type", "parameters"}
        or code_quality_parameters != {"severity": "errors"}
    ):
        raise ContractError("code-quality rule is not exact")
    code_coverage = rules_by_type["code_coverage"]
    code_coverage_parameters = _object(
        code_coverage.get("parameters"), "code-coverage rule parameters"
    )
    # Exactly two shapes mean "minimum 80, no maximum-drop threshold".
    # GitHub's ruleset API now refuses an explicit `max_coverage_drop: null`
    # on create and update, so a ruleset written today reads back with the
    # key ABSENT, while one written before that change reads it back as
    # `null`. Both state the same control. Anything else -- a numeric drop
    # threshold, another minimum, a float or boolean twin of 80, an extra
    # key -- is a different control and denies.
    minimum = code_coverage_parameters.get("minimum_coverage")
    if (
        set(code_coverage) != {"type", "parameters"}
        or set(code_coverage_parameters)
        not in ({"minimum_coverage"}, {"minimum_coverage", "max_coverage_drop"})
        or type(minimum) is not int
        or minimum != 80
        or code_coverage_parameters.get("max_coverage_drop") is not None
    ):
        raise ContractError("code-coverage rule is not exact")

    receipt: dict[str, object] = {
        "repository": repository,
        "branch": "main",
        "merge_methods": sorted(merge_methods),
        "required_status_checks": [
            {"context": context, "integration_id": integration_id}
            for context, integration_id in sorted(status_checks)
        ],
        "strict_status_checks": status_parameters.get("strict_required_status_checks_policy"),
        "require_pull_request": True,
        "required_approving_review_count": pull_parameters.get(
            "required_approving_review_count"
        ),
        "dismiss_stale_reviews_on_push": pull_parameters.get(
            "dismiss_stale_reviews_on_push"
        ),
        "required_reviewers": pull_parameters.get("required_reviewers"),
        "require_code_owner_review": pull_parameters.get("require_code_owner_review"),
        "require_extra_approval_for_unattributed_changes": pull_parameters.get(
            "require_extra_approval_for_unattributed_changes"
        ),
        "require_last_push_approval": pull_parameters.get("require_last_push_approval"),
        "required_review_thread_resolution": pull_parameters.get(
            "required_review_thread_resolution"
        ),
        "require_linear_history": "required_linear_history" in rules_by_type,
        "require_signed_commits": "required_signatures" in rules_by_type,
        "allow_force_pushes": "non_fast_forward" not in rules_by_type,
        "allow_deletions": "deletion" not in rules_by_type,
        "restrict_creations": "creation" in rules_by_type,
        "restrict_updates": "update" in rules_by_type,
        "code_scanning_tools": code_scanning_parameters.get("code_scanning_tools"),
        "code_quality_severity": code_quality_parameters.get("severity"),
        "minimum_code_coverage": code_coverage_parameters.get("minimum_coverage"),
        "maximum_code_coverage_drop": code_coverage_parameters.get(
            "max_coverage_drop"
        ),
        "private_vulnerability_reporting": private_vulnerability_record.get("enabled"),
    }
    receipt["active_main_branch_ruleset_count"] = ACTIVE_MAIN_BRANCH_RULESETS
    validate_settings_receipt(receipt, repository)
    return receipt


def _github_api_get(endpoint: str, *, paginate: bool = False) -> object:
    command = [
        "gh",
        "api",
        "--method",
        "GET",
        "--header",
        "Accept: application/vnd.github+json",
        "--header",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    if paginate:
        command.extend(("--paginate", "--slurp"))
    command.append(endpoint)
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ContractError("read-only GitHub settings query failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("read-only GitHub settings query returned malformed JSON") from exc
    if not paginate:
        return value
    flattened: list[object] = []
    for page in _array(value, "paginated GitHub settings response"):
        flattened.extend(_array(page, "paginated GitHub settings page"))
    return flattened


def observe_live_settings(repository: str) -> dict[str, object]:
    """Query only GET endpoints and emit a receipt only for exact live state.

    Exactly four endpoints, each readable by the settings job's `github.token`
    (contents: read) on a public repository: the repository record, private
    vulnerability reporting, the ruleset inventory and the one Protect-Main
    ruleset. An endpoint that needs Administration read -- `immutable-releases`,
    `actions/permissions`, `actions/permissions/workflow` -- is deliberately
    absent: that token cannot read it, so adding one would deny every release.
    The owner verifies those surfaces instead (docs/release-governance.md), and
    the contract suite pins this endpoint list closed.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ContractError("repository must be an exact owner/name pair")
    repository_record = _object(_github_api_get(f"repos/{repository}"), "repository settings")
    private_vulnerability_record = _object(
        _github_api_get(f"repos/{repository}/private-vulnerability-reporting"),
        "private-vulnerability-reporting settings",
    )
    summaries = _github_api_get(f"repos/{repository}/rulesets", paginate=True)
    ruleset_id = _select_main_ruleset_id(summaries, repository)
    ruleset_record = _object(
        _github_api_get(f"repos/{repository}/rulesets/{ruleset_id}"),
        "Protect-Main ruleset",
    )
    return build_settings_receipt(
        repository,
        repository_record,
        private_vulnerability_record,
        ruleset_id,
        ruleset_record,
    )


def _same_instant(actual: object, expected: str, field: str) -> None:
    if not isinstance(actual, str):
        raise ContractError(f"{field} must be an ISO-8601 timestamp")
    try:
        actual_time = dt.datetime.fromisoformat(actual.replace("Z", "+00:00"))
        expected_time = dt.datetime.fromisoformat(expected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} must be an ISO-8601 timestamp") from exc
    if actual_time.tzinfo is None or expected_time.tzinfo is None or actual_time != expected_time:
        raise ContractError(f"{field} does not equal the deterministic source-commit instant")


def validate_tag_record(
    ref_record: Mapping[str, object],
    tag_record: Mapping[str, object],
    *,
    tag: str,
    source_sha: str,
    message: str,
    tagger_name: str,
    tagger_email: str,
    tagger_date: str,
) -> None:
    """Verify the complete annotated-tag identity created by the orchestrator."""
    source_sha = require_sha(source_sha, "tag target SHA")
    ref_object = _object(ref_record.get("object"), "tag ref object")
    tag_object_sha = require_sha(ref_object.get("sha"), "annotated tag object SHA")
    if ref_record.get("ref") != f"refs/tags/{tag}" or ref_object.get("type") != "tag":
        raise ContractError("tag ref is not the exact annotated tag object")
    if tag_record.get("sha") != tag_object_sha or tag_record.get("tag") != tag:
        raise ContractError("annotated tag object identity does not match its ref")
    target = _object(tag_record.get("object"), "annotated tag target")
    if target.get("type") != "commit" or target.get("sha") != source_sha:
        raise ContractError("annotated tag target is not the exact source commit")
    if tag_record.get("message") != message:
        raise ContractError("annotated tag message is not exact")
    tagger = _object(tag_record.get("tagger"), "annotated tagger")
    if tagger.get("name") != tagger_name or tagger.get("email") != tagger_email:
        raise ContractError("annotated tagger identity violates policy")
    _same_instant(tagger.get("date"), tagger_date, "annotated tagger date")


def _canonical_json(record: Mapping[str, object]) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_digest(raw: object, field: str) -> str:
    if not isinstance(raw, str) or DIGEST_RE.fullmatch(raw) is None:
        raise ContractError(f"{field} must be sha256:<64 lowercase hex>")
    return raw


def _require_blob_digest(data: bytes, expected: object, field: str) -> str:
    digest = _require_digest(expected, field)
    computed = "sha256:" + hashlib.sha256(data).hexdigest()
    if computed != digest:
        raise ContractError(f"{field} does not bind the exact downloaded bytes")
    return digest


def _descriptor(record: object, field: str) -> Mapping[str, object]:
    descriptor = _object(record, field)
    if descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
        raise ContractError(f"{field} media type is not an OCI image manifest")
    _require_digest(descriptor.get("digest"), f"{field} digest")
    size = descriptor.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ContractError(f"{field} size must be a positive integer")
    return descriptor


def validate_sbom_index(
    index_bytes: bytes, *, expected_image_digest: str
) -> dict[str, dict[str, str]]:
    """Bind exactly two platform manifests to exactly two SBOM carriers."""
    _require_blob_digest(index_bytes, expected_image_digest, "image index digest")
    index = _object(json.loads(index_bytes), "image index")
    if index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE:
        raise ContractError("image SBOM carrier must be an OCI schema-2 index")
    manifests = _array(index.get("manifests"), "image index manifests")
    if len(manifests) != len(RELEASE_MANIFEST_PLATFORMS) * 2:
        raise ContractError("image index must contain exactly two images and two attestations")

    subjects: dict[str, str] = {}
    attestations_by_subject: dict[str, str] = {}
    descriptor_digests: set[str] = set()
    for position, raw_descriptor in enumerate(manifests):
        descriptor = _descriptor(raw_descriptor, f"image index descriptor {position}")
        digest = _require_digest(descriptor.get("digest"), "image index descriptor digest")
        if digest in descriptor_digests:
            raise ContractError("image index contains a duplicate descriptor digest")
        descriptor_digests.add(digest)
        platform_record = _object(descriptor.get("platform"), "image index platform")
        platform_keys = set(platform_record)
        os_name = platform_record.get("os")
        architecture = platform_record.get("architecture")
        annotations = descriptor.get("annotations")
        if os_name == "linux" and architecture in {"amd64", "arm64"}:
            if platform_keys != {"os", "architecture"} or annotations is not None:
                raise ContractError("image platform descriptor shape is not exact")
            platform = f"linux/{architecture}"
            if platform in subjects:
                raise ContractError("image index contains a duplicate platform")
            subjects[platform] = digest
            continue
        if platform_record != {"architecture": "unknown", "os": "unknown"}:
            raise ContractError("image index contains a foreign platform")
        annotation_record = _object(annotations, "attestation descriptor annotations")
        if set(annotation_record) != {
            "vnd.docker.reference.digest",
            "vnd.docker.reference.type",
        }:
            raise ContractError("attestation descriptor annotation set is not exact")
        if annotation_record.get("vnd.docker.reference.type") != "attestation-manifest":
            raise ContractError("image index descriptor is not an attestation carrier")
        subject = _require_digest(
            annotation_record.get("vnd.docker.reference.digest"),
            "attestation subject digest",
        )
        if subject in attestations_by_subject:
            raise ContractError("image index contains a duplicate attestation carrier")
        attestations_by_subject[subject] = digest

    if set(subjects) != set(RELEASE_MANIFEST_PLATFORMS):
        raise ContractError("image index platform set is not exact")
    if set(attestations_by_subject) != set(subjects.values()):
        raise ContractError("attestation carriers do not bind the exact platform subjects")
    return {
        platform: {
            "subject_digest": subjects[platform],
            "attestation_digest": attestations_by_subject[subjects[platform]],
        }
        for platform in RELEASE_MANIFEST_PLATFORMS
    }


def validate_sbom_attestation_manifest(
    manifest_bytes: bytes,
    *,
    expected_attestation_digest: str,
) -> str:
    """Return the sole SPDX statement layer from one exact OCI carrier."""
    _require_blob_digest(
        manifest_bytes, expected_attestation_digest, "SBOM attestation manifest digest"
    )
    manifest = _object(json.loads(manifest_bytes), "SBOM attestation manifest")
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
        raise ContractError("SBOM carrier must be an OCI schema-2 manifest")
    config = _object(manifest.get("config"), "SBOM carrier config")
    if config.get("mediaType") != OCI_EMPTY_CONFIG_MEDIA_TYPE:
        raise ContractError("SBOM carrier config media type is not exact")
    _require_digest(config.get("digest"), "SBOM carrier config digest")
    config_size = config.get("size")
    if isinstance(config_size, bool) or not isinstance(config_size, int) or config_size <= 0:
        raise ContractError("SBOM carrier config size must be positive")

    layers = _array(manifest.get("layers"), "SBOM carrier layers")
    if len(layers) != 2:
        raise ContractError("SBOM carrier must contain exactly one provenance and one SBOM layer")
    expected_predicates = {SLSA_PREDICATE_TYPE, SBOM_PREDICATE_TYPE}
    observed: dict[str, str] = {}
    for position, raw_layer in enumerate(layers):
        layer = _object(raw_layer, f"SBOM carrier layer {position}")
        if layer.get("mediaType") != INTOTO_LAYER_MEDIA_TYPE:
            raise ContractError("SBOM carrier layer media type is not in-toto JSON")
        layer_digest = _require_digest(layer.get("digest"), "SBOM carrier layer digest")
        layer_size = layer.get("size")
        if isinstance(layer_size, bool) or not isinstance(layer_size, int) or layer_size <= 0:
            raise ContractError("SBOM carrier layer size must be positive")
        annotations = _object(layer.get("annotations"), "SBOM carrier layer annotations")
        if set(annotations) != {"in-toto.io/predicate-type"}:
            raise ContractError("SBOM carrier layer annotations are not exact")
        predicate_type = annotations.get("in-toto.io/predicate-type")
        if predicate_type not in expected_predicates or predicate_type in observed:
            raise ContractError("SBOM carrier predicate set is duplicate or foreign")
        observed[predicate_type] = layer_digest
    if set(observed) != expected_predicates:
        raise ContractError("SBOM carrier predicate set is incomplete")
    return observed[SBOM_PREDICATE_TYPE]


def validate_sbom_statement(
    statement_bytes: bytes,
    *,
    expected_layer_digest: str,
    image: str,
    expected_subject_digest: str,
    platform: str,
) -> None:
    """Validate one raw BuildKit SPDX statement and its platform subject."""
    _require_blob_digest(statement_bytes, expected_layer_digest, "SBOM statement layer digest")
    if platform not in RELEASE_MANIFEST_PLATFORMS:
        raise ContractError("SBOM statement platform is not required")
    if not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+", image):
        raise ContractError("SBOM statement image repository is malformed")
    subject_digest = _require_digest(expected_subject_digest, "SBOM subject digest")
    statement = _object(json.loads(statement_bytes), "SBOM statement")
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise ContractError("SBOM statement top-level schema is not exact")
    if statement.get("_type") != SBOM_STATEMENT_TYPE:
        raise ContractError("SBOM statement type is not exact")
    if statement.get("predicateType") != SBOM_PREDICATE_TYPE:
        raise ContractError("SBOM predicate type is not exact")
    subjects = _array(statement.get("subject"), "SBOM statement subjects")
    if len(subjects) != 1:
        raise ContractError("SBOM statement must contain exactly one subject")
    subject = _object(subjects[0], "SBOM statement subject")
    if set(subject) != {"name", "digest"}:
        raise ContractError("SBOM statement subject schema is not exact")
    name = subject.get("name")
    if not isinstance(name, str):
        raise ContractError("SBOM statement subject name is absent")
    parsed_name = urllib.parse.urlsplit(name)
    expected_prefix = f"docker/{image}@"
    if (
        parsed_name.scheme != "pkg"
        or not parsed_name.path.startswith(expected_prefix)
        or len(parsed_name.path) <= len(expected_prefix)
        or parsed_name.fragment
        or urllib.parse.parse_qs(parsed_name.query, strict_parsing=True)
        != {"platform": [platform]}
    ):
        raise ContractError("SBOM subject name does not bind the exact image and platform")
    subject_digests = _object(subject.get("digest"), "SBOM statement subject digest set")
    if subject_digests != {"sha256": subject_digest[len("sha256:") :]}:
        raise ContractError("SBOM statement subject digest is not exact")

    predicate = _object(statement.get("predicate"), "SPDX predicate")
    for key, expected in (
        ("SPDXID", "SPDXRef-DOCUMENT"),
        ("dataLicense", "CC0-1.0"),
        ("spdxVersion", "SPDX-2.3"),
    ):
        if predicate.get(key) != expected:
            raise ContractError(f"SPDX predicate {key} is not exact")
    for key in ("name", "documentNamespace"):
        value = predicate.get(key)
        if not isinstance(value, str) or not value:
            raise ContractError(f"SPDX predicate {key} is absent")
    if not str(predicate["documentNamespace"]).startswith("https://"):
        raise ContractError("SPDX document namespace is not HTTPS")
    creation = _object(predicate.get("creationInfo"), "SPDX creationInfo")
    if not isinstance(creation.get("created"), str) or not creation.get("created"):
        raise ContractError("SPDX creation time is absent")
    creators = _array(creation.get("creators"), "SPDX creators")
    if not creators or any(not isinstance(value, str) or not value for value in creators):
        raise ContractError("SPDX creators are malformed")
    packages = _array(predicate.get("packages"), "SPDX packages")
    for raw_package in packages:
        package = _object(raw_package, "SPDX package")
        for key in ("SPDXID", "name", "downloadLocation"):
            if not isinstance(package.get(key), str) or not package.get(key):
                raise ContractError(f"SPDX package {key} is malformed")
        if not isinstance(package.get("filesAnalyzed"), bool):
            raise ContractError("SPDX package filesAnalyzed must be boolean")
    relationships = _array(predicate.get("relationships"), "SPDX relationships")
    for raw_relationship in relationships:
        relationship = _object(raw_relationship, "SPDX relationship")
        for key in ("spdxElementId", "relationshipType", "relatedSpdxElement"):
            if not isinstance(relationship.get(key), str) or not relationship.get(key):
                raise ContractError(f"SPDX relationship {key} is malformed")
    if "files" in predicate:
        _array(predicate.get("files"), "SPDX files")


def build_release_manifest(
    *,
    repository: str,
    source_sha: str,
    main_run_id: int,
    version: str,
    image: str,
    image_digest: str,
    chart: str,
    chart_digest: str,
) -> dict[str, object]:
    """Build the one canonical, deterministic publication evidence asset."""
    validate_release_destinations(repository, image, chart)
    source_sha = require_sha(source_sha, "release manifest source SHA")
    if isinstance(main_run_id, bool) or main_run_id <= 0:
        raise ContractError("release manifest main run ID must be positive")
    parsed_version = Version.parse(version)
    image_digest = _require_digest(image_digest, "release manifest image digest")
    chart_digest = _require_digest(chart_digest, "release manifest chart digest")
    identity = (
        f"https://github.com/{repository}/{RELEASE_MANIFEST_WORKFLOW}"
        "@refs/heads/main"
    )
    policy = {
        "scanner": "trivy",
        "scanner_version": TRIVY_VERSION,
        "severities": list(TRIVY_SEVERITIES),
        "ignore_unfixed": False,
        "result": "pass",
    }
    return {
        "schema": RELEASE_MANIFEST_SCHEMA,
        "repository": repository,
        "source_sha": source_sha,
        "main_run_id": main_run_id,
        "release": {"version": str(parsed_version), "tag": parsed_version.tag},
        "publisher": {
            "workflow": RELEASE_MANIFEST_WORKFLOW,
            "ref": "refs/heads/main",
        },
        "artifacts": {
            "image": {
                "repository": image,
                "tag": parsed_version.tag,
                "digest": image_digest,
                "platforms": RELEASE_MANIFEST_PLATFORMS,
                "signature_identity": identity,
                "provenance": "slsa-v1-per-platform",
            },
            "chart": {
                "repository": chart,
                "tag": str(parsed_version),
                "digest": chart_digest,
                "signature_identity": identity,
            },
        },
        "vulnerability_scans": {
            "source": {**copy.deepcopy(policy), "target": source_sha, "main_run_id": main_run_id},
            "image": {**copy.deepcopy(policy), "target": f"{image}@{image_digest}"},
        },
    }


def validate_release_manifest_record(
    manifest: Mapping[str, object],
    *,
    repository: str,
    source_sha: str,
    main_run_id: int,
    version: str,
    image: str,
    image_digest: str,
    chart: str,
    chart_digest: str,
) -> None:
    expected = build_release_manifest(
        repository=repository,
        source_sha=source_sha,
        main_run_id=main_run_id,
        version=version,
        image=image,
        image_digest=image_digest,
        chart=chart,
        chart_digest=chart_digest,
    )
    if manifest != expected:
        raise ContractError("release manifest is not the exact canonical evidence record")


def build_release_notes(manifest: Mapping[str, object]) -> str:
    """Render immutable Release notes from an already validated manifest."""
    release = _object(manifest.get("release"), "release manifest release")
    artifacts = _object(manifest.get("artifacts"), "release manifest artifacts")
    image = _object(artifacts.get("image"), "release manifest image")
    chart = _object(artifacts.get("chart"), "release manifest chart")
    tag = release.get("tag")
    manifest_bytes = _canonical_json(manifest)
    asset_name = release_manifest_asset_name(str(tag))
    asset_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    return (
        f"## hospedajedonlolo.com {tag}\n\n"
        "Immutable artifacts (deploy by digest, never by tag):\n\n"
        "| Artifact | Reference |\n| --- | --- |\n"
        f"| Image | `{image.get('repository')}:{image.get('tag')}@{image.get('digest')}` |\n"
        f"| Chart | `{chart.get('repository')}:{chart.get('tag')}@{chart.get('digest')}` |\n"
        "\nSigned with keyless Cosign by this workflow identity; SBOM and SLSA provenance "
        "embedded in the image index.\n"
        "That complete provenance is additionally attached as two keyless cosign "
        "attestations (slsaprovenance1), one per architecture, with exact source, "
        "revision, platform, image, and digest bindings.\n"
        f"\nPublication evidence: `{asset_name}` (`{asset_digest}`).\n"
        "\nSee CHANGELOG.md for human-readable changes.\n"
    )


def release_manifest_asset_name(tag: str) -> str:
    if not re.fullmatch(r"v" + SEMVER_RE.pattern[1:-1], tag):
        raise ContractError("release manifest tag is malformed")
    return f"hospedajedonlolo-com-{tag}-release-manifest.json"


def _validate_release_actor(value: object, field: str) -> None:
    actor = _object(value, field)
    actor_id = actor.get("id")
    if (
        actor.get("login") != GITHUB_ACTIONS_BOT_LOGIN
        or isinstance(actor_id, bool)
        or not isinstance(actor_id, int)
        or actor_id != GITHUB_ACTIONS_BOT_ID
    ):
        raise ContractError(f"{field} is not the workflow bot")


def _validate_release_asset(asset: Mapping[str, object], *, tag: str, manifest: bytes) -> None:
    _validate_release_actor(asset.get("uploader"), "GitHub Release manifest asset uploader")
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    expected = {
        "name": release_manifest_asset_name(tag),
        "content_type": "application/json",
        "state": "uploaded",
        "size": len(manifest),
        "digest": digest,
    }
    for field, value in expected.items():
        if asset.get(field) != value:
            raise ContractError(f"GitHub Release manifest asset {field} is not exact")


def validate_release_record(
    release_record: Mapping[str, object],
    *,
    tag: str,
    title: str,
    body: str,
    manifest: bytes,
    state: str = "exact",
) -> None:
    """Verify exact prepared, staged, or immutable Release metadata/evidence."""
    _validate_release_actor(release_record.get("author"), "GitHub Release author")
    if release_record.get("tag_name") != tag or release_record.get("name") != title:
        raise ContractError("GitHub Release tag or title is not exact")
    actual_body = release_record.get("body")
    if not isinstance(actual_body, str) or actual_body.rstrip("\r\n") != body.rstrip("\r\n"):
        raise ContractError("GitHub Release notes are not exact")
    if release_record.get("prerelease") is not False:
        raise ContractError("GitHub Release must be non-prerelease")
    if state in {"prepared", "staged"}:
        if release_record.get("draft") is not True or release_record.get("immutable") is not False:
            raise ContractError("prepared/staged GitHub Release must be mutable draft state")
    elif state == "exact":
        if release_record.get("draft") is not False or release_record.get("immutable") is not True:
            raise ContractError("published GitHub Release must report authoritative immutable state")
    else:
        raise ContractError("unknown GitHub Release validation state")
    assets = release_record.get("assets")
    if state == "prepared":
        if assets != []:
            raise ContractError("prepared GitHub Release asset inventory must be exactly empty")
        return
    if not isinstance(assets, list) or len(assets) != 1:
        raise ContractError("GitHub Release asset inventory must contain exactly one manifest")
    _validate_release_asset(_object(assets[0], "GitHub Release manifest asset"), tag=tag, manifest=manifest)


def classify_tag_state(
    http_status: int,
    ref_record: Mapping[str, object] | None,
    tag_record: Mapping[str, object] | None,
    **expected: str,
) -> str:
    """Classify authoritative REST tag state without requiring a local ref."""
    if http_status == 404:
        if ref_record is not None or tag_record is not None:
            raise ContractError("absent tag state cannot carry tag records")
        return "absent"
    if http_status != 200:
        raise ContractError(f"tag ref probe returned unexpected HTTP {http_status}")
    if ref_record is None or tag_record is None:
        raise ContractError("present tag state requires both REST tag records")
    validate_tag_record(ref_record, tag_record, **expected)
    return "exact"


def classify_release_state(
    http_status: int,
    release_record: Mapping[str, object] | None,
    *,
    tag: str,
    title: str,
    body: str,
    manifest: bytes,
) -> str:
    """Classify authoritative REST Release state for create/retry transactions."""
    if http_status == 404:
        if release_record is not None:
            raise ContractError("absent GitHub Release state cannot carry a record")
        return "absent"
    if http_status != 200:
        raise ContractError(f"GitHub Release probe returned unexpected HTTP {http_status}")
    if release_record is None:
        raise ContractError("present GitHub Release state requires its REST record")
    if release_record.get("draft") is True and release_record.get("immutable") is False:
        state = "prepared" if release_record.get("assets") == [] else "staged"
    elif release_record.get("draft") is False and release_record.get("immutable") is True:
        state = "exact"
    else:
        raise ContractError("present GitHub Release is neither exact staged nor immutable state")
    validate_release_record(
        release_record, tag=tag, title=title, body=body, manifest=manifest, state=state
    )
    return state


def require_publication_state(actual: str, required: str) -> str:
    """Turn an API classification into a shell-safe exact-state assertion."""
    if required not in {"absent", "prepared", "staged", "exact"} or actual != required:
        raise ContractError(f"publication state {actual!r} does not equal required {required!r}")
    return actual


def build_attestation_statement(
    predicate: Mapping[str, object],
    *,
    image: str,
    digest: str,
    source: str,
    revision: str,
    platform: str,
    builder_run_id: str,
) -> dict[str, object]:
    """Bind one embedded BuildKit predicate to an exact signed release member."""
    match = DIGEST_RE.fullmatch(digest)
    if not match:
        raise ContractError("attestation subject digest must be sha256:<64 lowercase hex>")
    require_sha(revision, "attestation source revision")
    if not image or "@" in image or not source.startswith("https://github.com/"):
        raise ContractError("attestation image or source identity is malformed")
    if not re.fullmatch(r"linux/[a-z0-9_-]+", platform):
        raise ContractError("attestation platform identity is malformed")
    if not isinstance(builder_run_id, str) or not ACTIONS_RUN_ID_RE.fullmatch(builder_run_id):
        raise ContractError(
            "attestation builder run ID must be a positive decimal Actions run ID"
        )

    normalized = copy.deepcopy(dict(predicate))
    build = _object(normalized.get("buildDefinition"), "SLSA buildDefinition")
    run = _object(normalized.get("runDetails"), "SLSA runDetails")
    builder = _object(run.get("builder"), "SLSA builder")
    metadata = _object(run.get("metadata"), "SLSA metadata")
    buildkit = _object(metadata.get("buildkit_metadata"), "BuildKit metadata")
    vcs = _object(buildkit.get("vcs"), "BuildKit vcs metadata")
    # The builder identity is bound to ONE run, not to the repository: a prefix
    # match on `<source>/actions/runs/` is satisfied by every run of every
    # workflow in this repository, forever, and never reads the digits that say
    # WHICH run produced these bytes (issue #137). The comparison is anchored on
    # both ends, so neither a different run (`/runs/124`) nor a longer run ID
    # sharing this one's leading digits (`/runs/1234`) nor trailing junk after
    # the attempt can satisfy it.
    builder_id = builder.get("id")
    if not isinstance(builder_id, str) or not re.fullmatch(
        re.escape(f"{source}/actions/runs/{builder_run_id}") + BUILDER_ATTEMPT_SUFFIX,
        builder_id,
    ):
        raise ContractError(
            "embedded predicate builder does not name this repository's exact Actions run"
        )
    if vcs.get("source") != source or vcs.get("revision") != revision:
        raise ContractError("embedded predicate source or revision is foreign")

    internal = build.get("internalParameters")
    if internal is None:
        internal = {}
        build["internalParameters"] = internal
    internal = _object(internal, "SLSA internalParameters")
    if "release" in internal:
        raise ContractError("embedded predicate already carries a release binding")
    internal["release"] = {
        "source": source,
        "revision": revision,
        "platform": platform,
    }
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{"name": image, "digest": {"sha256": match.group(1)}}],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": normalized,
    }


def _verified_statements(text: str) -> list[Mapping[str, object]]:
    decoder = json.JSONDecoder()
    values: list[object] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        value, position = decoder.raw_decode(text, position)
        values.append(value)
    if len(values) == 1 and isinstance(values[0], list):
        values = values[0]
    statements: list[Mapping[str, object]] = []
    for value in values:
        record = _object(value, "verified cosign record")
        payload = record.get("payload")
        if not isinstance(payload, str):
            raise ContractError("verified cosign record has no signed payload")
        try:
            decoded = base64.b64decode(payload, validate=True).decode("utf-8")
            statement = json.loads(decoded)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractError("verified cosign payload is not canonical JSON evidence") from exc
        statements.append(_object(statement, "verified in-toto statement"))
    return statements


def validate_attestation_set(
    verified_output: str, expected_by_platform: Mapping[str, Mapping[str, object]]
) -> int:
    """Accept only the exact authenticated per-platform statement set."""
    if not expected_by_platform:
        raise ContractError("expected attestation platform set is empty")
    statements = _verified_statements(verified_output)
    if len(statements) != len(expected_by_platform):
        raise ContractError("verified attestation count does not equal the required platform set")
    actual: dict[str, Mapping[str, object]] = {}
    for statement in statements:
        predicate = _object(statement.get("predicate"), "verified SLSA predicate")
        build = _object(predicate.get("buildDefinition"), "verified SLSA buildDefinition")
        internal = _object(build.get("internalParameters"), "verified SLSA internalParameters")
        release = _object(internal.get("release"), "verified release binding")
        platform = release.get("platform")
        if not isinstance(platform, str) or platform in actual:
            raise ContractError("verified attestation platform is absent or duplicated")
        actual[platform] = statement
    if set(actual) != set(expected_by_platform):
        raise ContractError("verified attestation platforms are missing or foreign")
    for platform, expected in expected_by_platform.items():
        if actual[platform] != expected:
            raise ContractError(f"verified {platform} subject or predicate is not exact")
    return len(statements)


def classify_artifact(*, present: bool, source_match: bool, signature_match: bool, evidence_count: int, expected_evidence: int) -> str:
    if expected_evidence < 0 or evidence_count < 0:
        raise ContractError("evidence counts cannot be negative")
    if not present:
        if source_match or signature_match or evidence_count:
            raise ContractError("absent artifact cannot carry positive evidence")
        return "absent"
    if source_match and signature_match and evidence_count == expected_evidence:
        return "complete"
    return "burned"


def classify_registry_response(http_status: int) -> str:
    """Distinguish authoritative absence from every fail-closed registry error."""
    if http_status == 200:
        return "present"
    if http_status == 404:
        return "absent"
    raise ContractError(f"registry manifest probe returned unexpected HTTP {http_status}")


def _emit(intent: ReleaseIntent) -> None:
    print(json.dumps({"source_sha": intent.source_sha, "version": str(intent.version), "tag": intent.tag}, sort_keys=True))


def _read_object(path: Path) -> Mapping[str, object]:
    return _object(json.loads(path.read_text(encoding="utf-8")), str(path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transition = commands.add_parser("transition")
    transition.add_argument("--repository", type=Path, required=True)
    transition.add_argument("--base", required=True)
    transition.add_argument("--head", required=True)
    transition.add_argument("--first-parent", action="store_true")
    window = commands.add_parser("release-window")
    window.add_argument("--repository", type=Path, required=True)
    window.add_argument("--head", required=True)
    event = commands.add_parser("workflow-run")
    event.add_argument("--event", type=Path, required=True)
    event.add_argument("--repository", required=True)
    main_run = commands.add_parser("main-run-record")
    main_run.add_argument("--run-json", type=Path, required=True)
    main_run.add_argument("--run-id", type=int, required=True)
    main_run.add_argument("--repository", required=True)
    main_run.add_argument("--source-sha", required=True)
    main_jobs = commands.add_parser("main-jobs-record")
    main_jobs.add_argument("--jobs-json", type=Path, required=True)
    main_jobs.add_argument("--run-id", type=int, required=True)
    main_jobs.add_argument("--source-sha", required=True)
    codeql_run = commands.add_parser("codeql-run-record")
    codeql_run.add_argument("--runs-json", type=Path, required=True)
    codeql_run.add_argument("--repository", required=True)
    codeql_run.add_argument("--source-sha", required=True)
    codeql_jobs = commands.add_parser("codeql-jobs-record")
    codeql_jobs.add_argument("--jobs-json", type=Path, required=True)
    codeql_jobs.add_argument("--run-id", type=int, required=True)
    codeql_jobs.add_argument("--source-sha", required=True)
    publisher = commands.add_parser("publisher")
    publisher.add_argument("--root", type=Path, required=True)
    publisher.add_argument("--source-sha", required=True)
    publisher.add_argument("--checkout-sha", required=True)
    publisher.add_argument("--ref", required=True)
    publisher.add_argument("--event-name", required=True)
    publisher.add_argument("--repository", required=True)
    publisher.add_argument("--workflow-ref", required=True)
    publisher.add_argument("--image", required=True)
    publisher.add_argument("--chart", required=True)
    settings_receipt = commands.add_parser("settings-receipt")
    settings_receipt.add_argument("--receipt", type=Path, required=True)
    settings_receipt.add_argument("--repository", required=True)
    settings_preflight = commands.add_parser("settings-preflight")
    settings_preflight.add_argument("--repository", required=True)
    immutable_settings = commands.add_parser("immutable-settings")
    immutable_settings.add_argument("--settings-json", type=Path, required=True)
    tag_record = commands.add_parser("tag-record")
    tag_record.add_argument("--ref-json", type=Path, required=True)
    tag_record.add_argument("--tag-json", type=Path, required=True)
    tag_record.add_argument("--tag", required=True)
    tag_record.add_argument("--source-sha", required=True)
    tag_record.add_argument("--message", required=True)
    tag_record.add_argument("--tagger-name", required=True)
    tag_record.add_argument("--tagger-email", required=True)
    tag_record.add_argument("--tagger-date", required=True)
    tag_state = commands.add_parser("tag-state")
    tag_state.add_argument("--http-status", type=int, required=True)
    tag_state.add_argument("--require", choices=("absent", "exact"))
    tag_state.add_argument("--ref-json", type=Path)
    tag_state.add_argument("--tag-json", type=Path)
    tag_state.add_argument("--tag", required=True)
    tag_state.add_argument("--source-sha", required=True)
    tag_state.add_argument("--message", required=True)
    tag_state.add_argument("--tagger-name", required=True)
    tag_state.add_argument("--tagger-email", required=True)
    tag_state.add_argument("--tagger-date", required=True)
    release_record = commands.add_parser("release-record")
    release_record.add_argument("--release-json", type=Path, required=True)
    release_record.add_argument("--tag", required=True)
    release_record.add_argument("--title", required=True)
    release_record.add_argument("--body", type=Path, required=True)
    release_record.add_argument("--manifest", type=Path, required=True)
    release_state = commands.add_parser("release-state")
    release_state.add_argument("--http-status", type=int, required=True)
    release_state.add_argument("--require", choices=("absent", "prepared", "staged", "exact"))
    release_state.add_argument("--release-json", type=Path)
    release_state.add_argument("--tag", required=True)
    release_state.add_argument("--title", required=True)
    release_state.add_argument("--body", type=Path, required=True)
    release_state.add_argument("--manifest", type=Path, required=True)
    manifest = commands.add_parser("release-manifest")
    manifest.add_argument("--output", type=Path, required=True)
    manifest_record = commands.add_parser("manifest-record")
    manifest_record.add_argument("--manifest", type=Path, required=True)
    release_notes = commands.add_parser("release-notes")
    release_notes.add_argument("--manifest", type=Path, required=True)
    release_notes.add_argument("--output", type=Path, required=True)
    for manifest_command in (manifest, manifest_record, release_notes):
        manifest_command.add_argument("--repository", required=True)
        manifest_command.add_argument("--source-sha", required=True)
        manifest_command.add_argument("--main-run-id", type=int, required=True)
        manifest_command.add_argument("--version", required=True)
        manifest_command.add_argument("--image", required=True)
        manifest_command.add_argument("--image-digest", required=True)
        manifest_command.add_argument("--chart", required=True)
        manifest_command.add_argument("--chart-digest", required=True)
    statement = commands.add_parser("attestation-statement")
    statement.add_argument("--predicate", type=Path, required=True)
    statement.add_argument("--output", type=Path, required=True)
    statement.add_argument("--predicate-output", type=Path, required=True)
    statement.add_argument("--image", required=True)
    statement.add_argument("--digest", required=True)
    statement.add_argument("--source", required=True)
    statement.add_argument("--revision", required=True)
    statement.add_argument("--platform", required=True)
    statement.add_argument("--builder-run-id", required=True)
    attestations = commands.add_parser("attestation-set")
    attestations.add_argument("--verified", type=Path, required=True)
    attestations.add_argument("--expected", action="append", required=True)
    artifact = commands.add_parser("artifact-state")
    artifact.add_argument("--present", choices=("true", "false"), required=True)
    artifact.add_argument("--source-match", choices=("true", "false"), required=True)
    artifact.add_argument("--signature-match", choices=("true", "false"), required=True)
    artifact.add_argument("--evidence-count", type=int, required=True)
    artifact.add_argument("--expected-evidence", type=int, required=True)
    registry = commands.add_parser("registry-state")
    registry.add_argument("--http-status", type=int, required=True)
    chart_digest_embed = commands.add_parser("chart-digest-embed")
    chart_digest_assert = commands.add_parser("chart-digest-assert")
    for chart_digest_command in (chart_digest_embed, chart_digest_assert):
        chart_digest_command.add_argument("--values", type=Path, required=True)
        chart_digest_command.add_argument("--digest", required=True)
    sbom_index = commands.add_parser("sbom-index-record")
    sbom_index.add_argument("--index", type=Path, required=True)
    sbom_index.add_argument("--image-digest", required=True)
    sbom_index.add_argument("--output", type=Path, required=True)
    sbom_layer = commands.add_parser("sbom-layer-record")
    sbom_layer.add_argument("--manifest", type=Path, required=True)
    sbom_layer.add_argument("--attestation-digest", required=True)
    sbom_statement = commands.add_parser("sbom-statement")
    sbom_statement.add_argument("--statement", type=Path, required=True)
    sbom_statement.add_argument("--layer-digest", required=True)
    sbom_statement.add_argument("--image", required=True)
    sbom_statement.add_argument("--subject-digest", required=True)
    sbom_statement.add_argument("--platform", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "transition":
            print(
                json.dumps(
                    classify_transition(
                        args.repository, args.base, args.head, first_parent=args.first_parent
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "release-window":
            window = discover_transition_window(args.repository, args.head)
            print(
                json.dumps(
                    {
                        "base_sha": window.base_sha,
                        "source_sha": window.intent.source_sha,
                        "version": str(window.intent.version),
                        "tag": window.intent.tag,
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "workflow-run":
            event = json.loads(args.event.read_text(encoding="utf-8"))
            print(plan_workflow_run(event, args.repository))
        elif args.command == "main-run-record":
            print(
                validate_main_run_record(
                    _read_object(args.run_json),
                    expected_repository=args.repository,
                    expected_run_id=args.run_id,
                    expected_source_sha=args.source_sha,
                )
            )
        elif args.command == "main-jobs-record":
            print(
                validate_main_jobs_record(
                    _read_object(args.jobs_json),
                    expected_run_id=args.run_id,
                    expected_source_sha=args.source_sha,
                )
            )
        elif args.command == "codeql-run-record":
            run_id = classify_codeql_run_record(
                _read_object(args.runs_json),
                expected_repository=args.repository,
                expected_source_sha=args.source_sha,
            )
            print("pending" if run_id is None else run_id)
        elif args.command == "codeql-jobs-record":
            print(
                validate_codeql_jobs_record(
                    _read_object(args.jobs_json),
                    expected_run_id=args.run_id,
                    expected_source_sha=args.source_sha,
                )
            )
        elif args.command == "publisher":
            _emit(
                validate_publisher(
                    args.root,
                    args.source_sha,
                    args.checkout_sha,
                    args.ref,
                    args.event_name,
                    args.repository,
                    args.workflow_ref,
                    args.image,
                    args.chart,
                )
            )
        elif args.command == "settings-receipt":
            validate_settings_receipt(_read_object(args.receipt), args.repository)
            print("exact")
        elif args.command == "settings-preflight":
            print(json.dumps(observe_live_settings(args.repository), indent=2, sort_keys=True))
        elif args.command == "immutable-settings":
            validate_immutable_settings(_read_object(args.settings_json))
            print("exact")
        elif args.command == "tag-record":
            validate_tag_record(
                _read_object(args.ref_json),
                _read_object(args.tag_json),
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print("exact")
        elif args.command == "tag-state":
            state = classify_tag_state(
                args.http_status,
                _read_object(args.ref_json) if args.ref_json else None,
                _read_object(args.tag_json) if args.tag_json else None,
                tag=args.tag,
                source_sha=args.source_sha,
                message=args.message,
                tagger_name=args.tagger_name,
                tagger_email=args.tagger_email,
                tagger_date=args.tagger_date,
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command == "release-record":
            validate_release_record(
                _read_object(args.release_json),
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
                manifest=args.manifest.read_bytes(),
            )
            print("exact")
        elif args.command == "release-state":
            state = classify_release_state(
                args.http_status,
                _read_object(args.release_json) if args.release_json else None,
                tag=args.tag,
                title=args.title,
                body=args.body.read_text(encoding="utf-8"),
                manifest=args.manifest.read_bytes(),
            )
            print(require_publication_state(state, args.require) if args.require else state)
        elif args.command in {"release-manifest", "manifest-record", "release-notes"}:
            expected = build_release_manifest(
                repository=args.repository,
                source_sha=args.source_sha,
                main_run_id=args.main_run_id,
                version=args.version,
                image=args.image,
                image_digest=args.image_digest,
                chart=args.chart,
                chart_digest=args.chart_digest,
            )
            if args.command == "release-manifest":
                args.output.write_bytes(_canonical_json(expected))
            else:
                validate_release_manifest_record(
                    _read_object(args.manifest),
                    repository=args.repository,
                    source_sha=args.source_sha,
                    main_run_id=args.main_run_id,
                    version=args.version,
                    image=args.image,
                    image_digest=args.image_digest,
                    chart=args.chart,
                    chart_digest=args.chart_digest,
                )
                if args.command == "release-notes":
                    args.output.write_text(build_release_notes(expected), encoding="utf-8")
                else:
                    print("exact")
        elif args.command == "attestation-statement":
            statement = build_attestation_statement(
                _read_object(args.predicate),
                image=args.image,
                digest=args.digest,
                source=args.source,
                revision=args.revision,
                platform=args.platform,
                builder_run_id=args.builder_run_id,
            )
            args.output.write_text(json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8")
            # cosign's `attest --predicate` consumes ONLY the bare predicate,
            # never the in-toto statement wrapper written above: write the
            # exact same release-bound predicate object cosign will embed
            # verbatim, so the file the workflow signs and the statement this
            # command later verifies against can never drift apart.
            args.predicate_output.write_text(
                json.dumps(statement["predicate"], sort_keys=True) + "\n", encoding="utf-8"
            )
        elif args.command == "attestation-set":
            expected: dict[str, Mapping[str, object]] = {}
            for item in args.expected:
                platform, separator, raw_path = item.partition("=")
                if not separator or not platform or platform in expected:
                    raise ContractError("expected attestation arguments must be unique platform=path pairs")
                expected[platform] = _read_object(Path(raw_path))
            print(validate_attestation_set(args.verified.read_text(encoding="utf-8"), expected))
        elif args.command == "artifact-state":
            state = classify_artifact(
                present=args.present == "true",
                source_match=args.source_match == "true",
                signature_match=args.signature_match == "true",
                evidence_count=args.evidence_count,
                expected_evidence=args.expected_evidence,
            )
            print(state)
            if state == "burned":
                return 1
        elif args.command == "registry-state":
            print(classify_registry_response(args.http_status))
        elif args.command == "chart-digest-embed":
            embedded = embed_chart_image_digest(
                args.values.read_text(encoding="utf-8"), args.digest
            )
            args.values.write_text(embedded, encoding="utf-8")
            print("embedded")
        elif args.command == "chart-digest-assert":
            assert_chart_image_digest(args.values.read_text(encoding="utf-8"), args.digest)
            print("exact")
        elif args.command == "sbom-index-record":
            plan = validate_sbom_index(
                args.index.read_bytes(), expected_image_digest=args.image_digest
            )
            args.output.write_bytes(_canonical_json(plan))
        elif args.command == "sbom-layer-record":
            print(
                validate_sbom_attestation_manifest(
                    args.manifest.read_bytes(),
                    expected_attestation_digest=args.attestation_digest,
                )
            )
        elif args.command == "sbom-statement":
            validate_sbom_statement(
                args.statement.read_bytes(),
                expected_layer_digest=args.layer_digest,
                image=args.image,
                expected_subject_digest=args.subject_digest,
                platform=args.platform,
            )
            print("exact")
        else:  # pragma: no cover - argparse owns this path
            raise ContractError("unknown command")
    except (ContractError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
