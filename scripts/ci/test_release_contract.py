"""Hostile tests for the per-main-merge release contract."""

from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("release_contract", HERE / "release_contract.py")
assert SPEC and SPEC.loader
RC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RC
SPEC.loader.exec_module(RC)


def changelog(version: str) -> str:
    """A complete released ladder ending at `version`, newest heading first.

    Issue #105 made the changelog's own history part of the contract, so a
    fixture carrying ONE heading no longer describes any real repository: the
    append-only comparison reads a 0.1.9 -> 0.1.10 step whose head dropped
    0.1.9 as exactly the deletion it exists to refuse. The ladder is generated
    rather than listed so a synthetic release step is append-only by
    construction, and every date is the same day, which the shape rule permits
    (dates must not INCREASE downward) and which keeps the fixture free of an
    invented release calendar.
    """
    major, minor, patch = (int(part) for part in version.split("."))
    return "# Changelog\n\n## [Unreleased]\n\n" + "\n".join(
        f"## [{major}.{minor}.{step}] - 2026-08-13\n\n- release\n"
        for step in range(patch, -1, -1)
    )


def snapshot(version: str) -> dict[str, str]:
    return {
        "VERSION": version + "\n",
        "chart/Chart.yaml": f"apiVersion: v2\nversion: {version}\nappVersion: \"{version}\"\n",
        "chart/values.yaml": f"image:\n  tag: v{version}\n",
        "CHANGELOG.md": changelog(version),
    }


# --- Normalized workflow parsing -------------------------------------------
#
# Issue #69 follow-up. The publisher-order contract first asserted over raw
# indented workflow text, and two spellings defeat that. Both were reproduced
# live against the complete suite before this hardening landed:
#
#  1. HEADINGS ARE NOT SIDE EFFECTS. Pinning the canonical step names and
#     their relative order says nothing about what any OTHER step does, so a
#     step named anything at all could run `cosign sign` over the resolved
#     digest before the vulnerability gate while every heading assertion
#     stayed green -- issue #69's exact failure mode, restored under a new
#     name.
#  2. KEYS ARE NOT THEIR SPELLING. YAML permits whitespace and quoting
#     between a key and its colon, so `if :`, `"if":`, and `'if' :` are the
#     same live conditional to the Actions runner while defeating an
#     `^        if:` regex. An ABSENCE assertion written against raw text
#     therefore fails OPEN -- the dangerous direction. (A PRESENCE assertion
#     written the same way fails closed, which is why the `tags:`/`sbom:`
#     regexes nearby are safe as written.)
#
# Every key-based and position-based publisher assertion normalizes through
# these helpers, so the contract binds step objects and executable run-block
# content rather than source spelling. Stdlib only by design: the gate runs
# `python3 -I -B`, which cannot import PyYAML.

_STEP_START = "      - "
_STEP_KEY = re.compile(r"^        (?=\S)")
_NEXT_JOB = re.compile(r"(?m)^  [A-Za-z_][A-Za-z0-9_-]*:[ \t]*$")

# Signing-capable commands, for the publisher ordering property. Each binds
# this repository's release identity to bytes: `cosign sign` and
# `cosign sign-blob` emit a bare signature, and `cosign attest` emits a SIGNED
# in-toto attestation -- an attested-then-refused digest carries exactly the
# false assurance a signed-then-refused digest does, so it counts. `cosign
# verify` and `cosign verify-attestation` are read-only and are deliberately
# absent from this tuple: they may run at any position. The lookarounds keep
# `cosign sign` from also matching `cosign sign-blob`, and keep
# `cosign verify-attestation` from matching `cosign attest`.
SIGNING_CAPABLE = (
    re.compile(r"(?<![\w./-])cosign\s+sign-blob(?![\w-])"),
    re.compile(r"(?<![\w./-])cosign\s+sign(?![\w-])"),
    re.compile(r"(?<![\w./-])cosign\s+attest(?![\w-])"),
)
IMAGE_SIGNATURE = re.compile(r"(?<![\w./-])cosign\s+sign(?![\w-])")
# Installing cosign is not signing with it. Every publisher action is pinned
# to a full commit SHA, so the companion check is name-level by construction:
# it refuses an obviously signing-capable action ahead of the gate and cannot
# prove what arbitrary pinned bytes do -- a stated boundary, not a claim.
SIGNING_TOOL_INSTALLERS = ("sigstore/cosign-installer",)
SIGNING_CAPABLE_ACTION = re.compile(r"(?i)(cosign|sigstore|attest|notary|signer)")


def normalized_yaml_key(line: str) -> str:
    """Return one YAML line's normalized mapping key, or "" if it declares none.

    `if:`, `if :`, `"if":`, and `'if' :` all normalize to `if` -- the one key
    the Actions runner honors and the spelling difference that defeated the
    raw-text assertions this replaces.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if stripped.startswith("- "):
        stripped = stripped[2:].strip()
    head, separator, _value = stripped.partition(":")
    if not separator:
        return ""
    key = head.strip()
    if len(key) >= 2 and key[0] == key[-1] and key[0] in "\"'":
        key = key[1:-1].strip()
    if not key or any(character.isspace() for character in key):
        return ""
    return key


def normalized_keys(block: str, indent: int) -> list[str]:
    """Return the normalized mapping keys declared at exactly `indent` spaces."""
    at_indent = re.compile(r"^ {%d}(?=\S)" % indent)
    keys = []
    for line in block.split("\n"):
        if at_indent.match(line):
            key = normalized_yaml_key(line)
            if key:
                keys.append(key)
    return keys


def job_conditions(block: str) -> list[str]:
    """Return every job-level `if` VALUE declared at exactly four spaces.

    Reading the value, not searching the text, is what makes a conditional
    pin non-vacuous in both directions: a comment quoting the condition
    declares no key and is ignored, and every spelling the Actions runner
    honors (`if :`, `"if":`) normalizes to the same key, so a mutant cannot
    hide behind punctuation.
    """
    at_indent = re.compile(r"^ {4}(?=\S)")
    return [
        line.split(":", 1)[1].strip()
        for line in block.split("\n")
        if at_indent.match(line) and normalized_yaml_key(line) == "if"
    ]


def _step_scalar(lines: list[str], key: str) -> str:
    """Return a step key's scalar value, block scalars folded to their body."""
    for index, line in enumerate(lines):
        if not (line.startswith(_STEP_START) or _STEP_KEY.match(line)):
            continue
        if normalized_yaml_key(line) != key:
            continue
        _head, _separator, value = line.partition(":")
        value = value.strip()
        if value and value[0] not in "|>":
            return value
        body = []
        for follow in lines[index + 1 :]:
            if not follow.strip():
                body.append("")
                continue
            if follow.startswith(_STEP_START) or _STEP_KEY.match(follow):
                break
            body.append(follow.strip())
        return "\n".join(body).strip()
    return ""


def workflow_run_block(workflow: str, step_name: str, *, fold: bool = False) -> str:
    """Return one workflow step's run body VERBATIM, dedented, ready to execute.

    Four classes had hand-rolled a copy of this, which the oldest of them said
    out loud ("repeats its exact dedent logic against the orchestrator
    workflow instead"); `ChartDigestEmbedShellPathTests.run_block` had already
    shown the shape the fix takes, delegating instead of copying. Two of those
    copies were byte-for-byte identical apart from the filename literal, so
    the workflow becomes a parameter.

    Deliberately NOT `job_steps`/`_step_scalar`, which are right next door:
    those `.strip()` every line (`_step_scalar`, above), which is correct for
    reading a scalar and fatal for running one -- bash needs the interior
    indentation a heredoc and an `if` block are written with. This reader
    removes exactly the block scalar's own ten-space indent and nothing else.

    Two copies FAILED OPEN and now do not, which is the point of consolidating
    onto this one rather than onto them:

    * a renamed or deleted step raised a bare `ValueError` from `list.index`
      in the pr-gate copies. It now raises `AssertionError` naming the
      workflow and the step, so the failure says what broke.
    * an empty body was returned as `"\\n"` by the pr-gate copies, handing bash
      an empty script that every assertion then passed vacuously. It now
      raises.

    `fold=True` reads a `run: >-` folded scalar and joins with spaces, which is
    YAML's own folding and the one genuinely distinct output contract of the
    four; blank lines are skipped there exactly as the folded copy skipped
    them. Block style preserves a blank line as a blank line.
    """
    lines = (ROOT / ".github" / "workflows" / workflow).read_text(
        encoding="utf-8"
    ).splitlines()
    marker = f"      - name: {step_name}"
    anchor = "        run: >-" if fold else "        run: |"
    try:
        start = lines.index(marker)
        run = lines.index(anchor, start)
    except ValueError as exc:
        raise AssertionError(f"workflow step is missing: {workflow}: {step_name}") from exc
    body: list[str] = []
    for line in lines[run + 1 :]:
        if line.startswith("      - name:"):
            break
        if line.startswith("          "):
            body.append(line[10:])
        elif not line:
            if not fold:
                body.append("")
        else:
            break
    if not body:
        raise AssertionError(
            f"workflow step has no executable run block: {workflow}: {step_name}"
        )
    return (" " if fold else "\n").join(body) + "\n"


class SyntheticRepo:
    """Build a throwaway git repository the transition readers can walk.

    Three test classes had carried their own copy of these four helpers, and
    the third said so in a section header ("mirroring NoArtifactClassTests").
    Two of those copies were functionally identical -- same argv, same file
    set, same staging, same identity flags -- differing only in line wrapping,
    and `repo()` was character-for-character the same in both.

    Identity is injected per invocation and never written to config, and
    nothing here creates a tag or a signature: these repositories exist to be
    READ by the release-boundary walk, so the only facts that matter are the
    commit graph and the four release locks in `snapshot()`.
    """

    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True, text=True, stdout=subprocess.PIPE
        ).stdout.strip()

    def release_commit(self, root: Path, version: str) -> str:
        """Commit all four release locks at one version."""
        files = snapshot(version)
        for name, contents in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self.git(root, "add", ".")
        self.git(
            root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
            "commit", "-m", version,
        )
        return self.git(root, "rev-parse", "HEAD")

    def paths_commit(self, root: Path, files: dict[str, str | None], marker: str) -> str:
        """Commit an exact path set; a None value deletes that path."""
        for name, contents in files.items():
            path = root / name
            if contents is None:
                path.unlink()
                self.git(root, "rm", "-q", "--cached", name)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            self.git(root, "add", name)
        self.git(
            root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
            "commit", "-m", marker,
        )
        return self.git(root, "rev-parse", "HEAD")

    def main_repo(self, temporary: str) -> Path:
        """An EMPTY repository on main, for a test that seeds its own history.

        Seven tests hand-rolled these two commands because `repo` below also
        commits a 0.1.9 release and they each need a different first commit.
        The seeding is what differs between them; being on `main` is not.
        """
        root = Path(temporary)
        self.git(root, "init", "-q")
        self.git(root, "branch", "-m", "main")
        return root

    def repo(self, temporary: str) -> tuple[Path, str]:
        """A main-branch repository seeded with one 0.1.9 release commit."""
        root = self.main_repo(temporary)
        return root, self.release_commit(root, "0.1.9")


def job_steps(workflow: str, job: str) -> list[dict]:
    """Split one job's `steps:` list into normalized execution-ordered records."""
    marker = f"\n  {job}:\n"
    if workflow.count(marker) != 1:
        raise ValueError(f"workflow must declare exactly one job named {job}")
    block = workflow.split(marker, 1)[1]
    following = _NEXT_JOB.search(block)
    if following is not None:
        block = block[: following.start()]
    steps_marker = "\n    steps:\n"
    if block.count(steps_marker) != 1:
        raise ValueError(f"job {job} must declare exactly one steps list")
    steps: list[dict] = []
    current: dict | None = None
    for line in block.split(steps_marker, 1)[1].split("\n"):
        if line.startswith(_STEP_START):
            current = {"position": len(steps), "lines": [], "keys": []}
            steps.append(current)
        elif current is None:
            continue
        elif line.strip() and not line.startswith("      "):
            break
        current["lines"].append(line)
        if line.startswith(_STEP_START) or _STEP_KEY.match(line):
            key = normalized_yaml_key(line)
            if key:
                current["keys"].append(key)
    for step in steps:
        step["name"] = _step_scalar(step["lines"], "name")
        step["run"] = _step_scalar(step["lines"], "run")
        step["uses"] = _step_scalar(step["lines"], "uses")
    return steps


def executable_commands(run: str) -> list[str]:
    """Return a run block's executable commands, comments dropped and continuations joined.

    A `#` line is never executed, so it must not register as a side effect --
    the vulnerability gate's own comment names `cosign sign/attest`.
    """
    commands = []
    pending = ""
    for raw in run.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        commands.append((pending + line).strip())
        pending = ""
    if pending.strip():
        commands.append(pending.strip())
    return commands


def signing_invocations(steps: list[dict]) -> list[tuple[int, str, str]]:
    """Return (position, step name, command) for every signing-capable command."""
    found = []
    for step in steps:
        for command in executable_commands(step["run"]):
            if any(pattern.search(command) for pattern in SIGNING_CAPABLE):
                found.append((step["position"], step["name"], command))
    return found


def event(sha: str) -> dict[str, object]:
    return {
        "repository": {"full_name": "owner/site"},
        "workflow_run": {
            "name": "PR gate",
            "path": ".github/workflows/pr-gate.yml@refs/heads/main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": sha,
            "head_repository": {"full_name": "owner/site"},
        },
    }


def main_run_record(sha: str, run_id: int = 123) -> dict[str, object]:
    return {
        "id": run_id,
        "name": "PR gate",
        "path": ".github/workflows/pr-gate.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": sha,
        "repository": {"full_name": "owner/site"},
        "head_repository": {"full_name": "owner/site"},
    }


def main_jobs_record(sha: str, run_id: int = 123) -> dict[str, object]:
    jobs = [
        {
            "id": index,
            "run_id": run_id,
            "head_sha": sha,
            "name": name,
            "status": "completed",
            "conclusion": conclusion,
        }
        for index, (name, conclusion) in enumerate(RC.EXPECTED_MAIN_JOBS.items(), start=1)
    ]
    return {"total_count": len(jobs), "jobs": jobs}


def codeql_run_record(sha: str, *, run_id: int = 456) -> dict[str, object]:
    run = {
        "id": run_id,
        "name": "CodeQL",
        "path": ".github/workflows/codeql.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": sha,
        "repository": {"full_name": "owner/site"},
        "head_repository": {"full_name": "owner/site"},
    }
    return {"total_count": 1, "workflow_runs": [run]}


def codeql_jobs_record(sha: str, *, run_id: int = 456) -> dict[str, object]:
    jobs = [
        {
            "id": index,
            "run_id": run_id,
            "head_sha": sha,
            "name": name,
            "status": "completed",
            "conclusion": "success",
        }
        for index, name in enumerate(RC.EXPECTED_CODEQL_JOBS, start=10)
    ]
    return {"total_count": len(jobs), "jobs": jobs}


def sbom_registry_fixture() -> dict[str, object]:
    image = "ghcr.io/owner/site"
    subject_digests = {
        "linux/amd64": "sha256:" + "1" * 64,
        "linux/arm64": "sha256:" + "2" * 64,
    }
    statements: dict[str, bytes] = {}
    attestation_manifests: dict[str, bytes] = {}
    attestation_digests: dict[str, str] = {}
    for platform, subject_digest in subject_digests.items():
        statement = {
            "_type": RC.SBOM_STATEMENT_TYPE,
            "subject": [
                {
                    "name": (
                        f"pkg:docker/{image}@{subject_digest}"
                        f"?platform={platform.replace('/', '%2F')}"
                    ),
                    "digest": {"sha256": subject_digest[len("sha256:") :]},
                }
            ],
            "predicateType": RC.SBOM_PREDICATE_TYPE,
            "predicate": {
                "SPDXID": "SPDXRef-DOCUMENT",
                "creationInfo": {
                    "created": "2026-08-14T00:00:00Z",
                    "creators": ["Tool: fixture"],
                },
                "dataLicense": "CC0-1.0",
                "documentNamespace": "https://example.test/spdx/fixture",
                "name": "fixture",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package",
                        "name": "fixture",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                    }
                ],
                "relationships": [],
                "spdxVersion": "SPDX-2.3",
            },
        }
        statement_bytes = json.dumps(statement, sort_keys=True).encode("utf-8")
        statements[platform] = statement_bytes
        layer_digest = "sha256:" + hashlib.sha256(statement_bytes).hexdigest()
        provenance_digest = "sha256:" + hashlib.sha256(
            f"provenance:{platform}".encode("utf-8")
        ).hexdigest()
        manifest = {
            "schemaVersion": 2,
            "mediaType": RC.OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": RC.OCI_EMPTY_CONFIG_MEDIA_TYPE,
                "digest": "sha256:" + "0" * 64,
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": RC.INTOTO_LAYER_MEDIA_TYPE,
                    "digest": provenance_digest,
                    "size": 100,
                    "annotations": {
                        "in-toto.io/predicate-type": RC.SLSA_PREDICATE_TYPE
                    },
                },
                {
                    "mediaType": RC.INTOTO_LAYER_MEDIA_TYPE,
                    "digest": layer_digest,
                    "size": len(statement_bytes),
                    "annotations": {
                        "in-toto.io/predicate-type": RC.SBOM_PREDICATE_TYPE
                    },
                },
            ],
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        attestation_manifests[platform] = manifest_bytes
        attestation_digests[platform] = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    descriptors: list[dict[str, object]] = []
    for platform, subject_digest in subject_digests.items():
        os_name, architecture = platform.split("/", 1)
        descriptors.append(
            {
                "mediaType": RC.OCI_MANIFEST_MEDIA_TYPE,
                "digest": subject_digest,
                "size": 1000,
                "platform": {"architecture": architecture, "os": os_name},
            }
        )
    for platform, subject_digest in subject_digests.items():
        descriptors.append(
            {
                "mediaType": RC.OCI_MANIFEST_MEDIA_TYPE,
                "digest": attestation_digests[platform],
                "size": len(attestation_manifests[platform]),
                "annotations": {
                    "vnd.docker.reference.digest": subject_digest,
                    "vnd.docker.reference.type": "attestation-manifest",
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            }
        )
    index_bytes = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": RC.OCI_INDEX_MEDIA_TYPE,
            "manifests": descriptors,
        },
        sort_keys=True,
    ).encode("utf-8")
    return {
        "image": image,
        "index": index_bytes,
        "image_digest": "sha256:" + hashlib.sha256(index_bytes).hexdigest(),
        "subjects": subject_digests,
        "attestation_manifests": attestation_manifests,
        "attestation_digests": attestation_digests,
        "statements": statements,
    }


BUILDER_RUN_ID = "123"


def embedded_predicate(
    source: str, revision: str, marker: str, builder_id: object | None = None
) -> dict[str, object]:
    return {
        "buildDefinition": {
            "buildType": "https://mobyproject.org/buildkit@v1",
            "externalParameters": {"marker": marker},
            "internalParameters": {},
        },
        "runDetails": {
            "builder": {
                "id": (
                    f"{source}/actions/runs/{BUILDER_RUN_ID}"
                    if builder_id is None
                    else builder_id
                )
            },
            "metadata": {"buildkit_metadata": {"vcs": {"source": source, "revision": revision}}},
        },
    }


def verified_record(statement: dict[str, object]) -> dict[str, str]:
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode("utf-8")).decode("ascii")
    return {"payload": payload}


def exact_tag_records(tag: str, source: str, message: str, date: str) -> tuple[dict[str, object], dict[str, object]]:
    tag_object = "b" * 40
    return (
        {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": tag_object}},
        {
            "sha": tag_object,
            "tag": tag,
            "message": message,
            "object": {"type": "commit", "sha": source},
            "tagger": {
                "name": "github-actions[bot]",
                "email": "41898282+github-actions[bot]@users.noreply.github.com",
                "date": date,
            },
        },
    )


def exact_release_manifest(
    *, source: str = "a" * 40, main_run_id: int = 123, version: str = "0.1.10"
) -> dict[str, object]:
    return RC.build_release_manifest(
        repository=RC.EXPECTED_REPOSITORY,
        source_sha=source,
        main_run_id=main_run_id,
        version=version,
        image=RC.EXPECTED_IMAGE,
        image_digest="sha256:" + "c" * 64,
        chart=RC.EXPECTED_CHART,
        chart_digest="sha256:" + "d" * 64,
    )


def canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def exact_release_record(
    manifest: bytes, *, tag: str = "v0.1.10", state: str = "exact", body: str = "exact notes\n"
) -> dict[str, object]:
    asset = {
        "name": f"hospedajedonlolo-com-{tag}-release-manifest.json",
        "content_type": "application/json",
        "state": "uploaded",
        "size": len(manifest),
        "digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
        "url": "https://api.github.test/assets/1",
        "uploader": {
            "login": RC.GITHUB_ACTIONS_BOT_LOGIN,
            "id": RC.GITHUB_ACTIONS_BOT_ID,
        },
    }
    return {
        "tag_name": tag,
        "name": f"hospedajedonlolo.com {tag}",
        "body": body,
        "draft": state in {"prepared", "staged"},
        "prerelease": False,
        "immutable": state == "exact",
        "author": {
            "login": RC.GITHUB_ACTIONS_BOT_LOGIN,
            "id": RC.GITHUB_ACTIONS_BOT_ID,
        },
        "assets": [] if state == "prepared" else [asset],
    }


REQUIRED_CHECKS = (
    "analyze (go, manual)",
    "analyze (javascript-typescript, none)",
    "application",
    "chart",
    "container",
    "dependency-review",
    "security",
)


def settings_receipt() -> dict[str, object]:
    return {
        "active_main_branch_ruleset_count": 1,
        "repository": "owner/site",
        "branch": "main",
        "merge_methods": ["rebase", "squash"],
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": False,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_extra_approval_for_unattributed_changes": True,
        "require_last_push_approval": False,
        "required_review_thread_resolution": True,
        "required_status_checks": [
            {"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS
        ],
        "strict_status_checks": True,
        "require_pull_request": True,
        "require_linear_history": True,
        "require_signed_commits": True,
        "restrict_creations": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "restrict_updates": False,
        "code_scanning_tools": [
            {
                "tool": "CodeQL",
                "security_alerts_threshold": "high_or_higher",
                "alerts_threshold": "errors",
            }
        ],
        "code_quality_severity": "errors",
        "minimum_code_coverage": 80,
        "maximum_code_coverage_drop": None,
        "private_vulnerability_reporting": True,
    }


#: The receipt fields the settings job's `github.token` cannot observe. Each
#: needs Administration read (or, for secret scanning, the repository record's
#: admin-only `security_and_analysis` block), so none is read or receipted: the
#: owner verifies these surfaces (docs/release-governance.md).
ADMIN_ONLY_RECEIPT_FIELDS = (
    "actions_allowed_actions",
    "actions_can_approve_pull_request_reviews",
    "actions_enabled",
    "actions_sha_pinning_required",
    "default_workflow_permissions",
    "immutable_releases",
    "secret_scanning",
    "secret_scanning_non_provider_patterns",
    "secret_scanning_push_protection",
    "secret_scanning_validity_checks",
)

#: The endpoints behind those fields. A preflight that GETs any of them under
#: the job token is denied on every run, so none may be read.
ADMIN_ONLY_SETTINGS_ENDPOINTS = (
    "repos/owner/site/immutable-releases",
    "repos/owner/site/actions/permissions",
    "repos/owner/site/actions/permissions/workflow",
)


def settings_api() -> dict[str, object]:
    ruleset_id = 42
    checks = [
        {"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS
    ]
    records = {
        # The exact shape GitHub returns to the settings job's read-only
        # `github.token` on a public repository: no allow_*_merge booleans
        # (returned only to credentials carrying Contents write) and no
        # `security_and_analysis` block (returned only to administrators).
        # The merge-method proof therefore binds to the Protect-Main ruleset
        # below, which is the control that actually enforces merge behaviour
        # on refs/heads/main.
        "repos/owner/site": {
            "full_name": "owner/site",
            "default_branch": "main",
        },
        "repos/owner/site/private-vulnerability-reporting": {"enabled": True},
        "repos/owner/site/rulesets": [
            {
                "id": ruleset_id,
                "name": "Protect-Main",
                "target": "branch",
                "source_type": "Repository",
                "source": "owner/site",
                "enforcement": "active",
            }
        ],
        f"repos/owner/site/rulesets/{ruleset_id}": {
            "id": ruleset_id,
            "name": "Protect-Main",
            "target": "branch",
            "source_type": "Repository",
            "source": "owner/site",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/heads/main"]},
            },
            # No bypass_actors: GitHub returns that property only to a
            # credential with write access to the ruleset, and the settings
            # job's token holds contents read alone.  This is the exact shape
            # CI sees, so the receipt must build from it.
            "rules": [
                {"type": "creation"},
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 0,
                        "dismiss_stale_reviews_on_push": False,
                        "required_reviewers": [],
                        "require_code_owner_review": False,
                        "require_extra_approval_for_unattributed_changes": True,
                        "require_last_push_approval": False,
                        "required_review_thread_resolution": True,
                        "allowed_merge_methods": ["squash", "rebase"],
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "required_status_checks": checks,
                        "strict_required_status_checks_policy": True,
                    },
                },
                {"type": "required_signatures"},
                {
                    "type": "code_scanning",
                    "parameters": {
                        "code_scanning_tools": [
                            {
                                "tool": "CodeQL",
                                "security_alerts_threshold": "high_or_higher",
                                "alerts_threshold": "errors",
                            }
                        ]
                    },
                },
                {"type": "code_quality", "parameters": {"severity": "errors"}},
                # This repository's live shape: GitHub now refuses an explicit
                # `max_coverage_drop: null` on create, so the key reads back
                # absent. The older `null` shape is admitted too, and pinned
                # in `test_coverage_rule_admits_exactly_the_two_no_drop_shapes`.
                {
                    "type": "code_coverage",
                    "parameters": {"minimum_coverage": 80},
                },
            ],
        },
    }

    return records


class VersionTests(unittest.TestCase):
    def test_next_patch_is_arithmetic_not_decimal_concatenation(self):
        RC.require_next_patch(RC.Version.parse("0.1.9"), RC.Version.parse("0.1.10"))
        for wrong in ("0.0.20", "0.1.9", "0.1.11", "0.2.0", "1.0.0"):
            with self.subTest(wrong=wrong), self.assertRaises(RC.ContractError):
                RC.require_next_patch(RC.Version.parse("0.1.9"), RC.Version.parse(wrong))

    def test_source_locks_and_changelog_are_one_identity(self):
        self.assertEqual(RC.validate_snapshot(snapshot("0.1.10")).tag, "v0.1.10")
        extended = snapshot("0.1.10")
        extended["chart/Chart.yaml"] += "dependencies:\n  - name: database\n    version: 1.2.3\n"
        extended["chart/values.yaml"] += "sidecar:\n  tag: unrelated\n"
        self.assertEqual(RC.validate_snapshot(extended).tag, "v0.1.10")
        mutations = []
        for path, replacement in (
            ("chart/Chart.yaml", "apiVersion: v2\nversion: 0.1.9\nappVersion: \"0.1.10\"\n"),
            ("chart/Chart.yaml", "apiVersion: v2\nversion: 0.1.10\nappVersion: \"v0.1.10\"\n"),
            ("chart/Chart.yaml", "apiVersion: v2\nversion: vv0.1.10\nappVersion: \"v0.1.10\"\n"),
            ("chart/values.yaml", "image:\n  tag: vv0.1.10\n"),
            ("chart/values.yaml", "image:\n  tag: v0.1.10\n  tag: v0.1.10\n"),
            ("chart/values.yaml", "image:\n  tag: v0.0.20\n"),
            ("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n- not released\n"),
        ):
            changed = snapshot("0.1.10")
            changed[path] = replacement
            mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(RC.ContractError):
                RC.validate_snapshot(changed)


class EventTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_successful_main_push_is_accepted(self):
        self.assertEqual(RC.plan_workflow_run(event(self.SHA), "owner/site"), self.SHA)

    def test_event_branch_conclusion_sha_path_and_identity_mutants_fail(self):
        mutations = (
            ("repository", "full_name", "attacker/site"),
            ("workflow_run", "name", "PR Gate"),
            ("workflow_run", "path", ".github/workflows/other.yml"),
            ("workflow_run", "event", "pull_request"),
            ("workflow_run", "status", "in_progress"),
            ("workflow_run", "conclusion", "failure"),
            ("workflow_run", "head_branch", "release"),
            ("workflow_run", "head_sha", "1234567"),
        )
        for parent, key, value in mutations:
            payload = json.loads(json.dumps(event(self.SHA)))
            payload[parent][key] = value
            with self.subTest(parent=parent, key=key), self.assertRaises(RC.ContractError):
                RC.plan_workflow_run(payload, "owner/site")
        payload = event(self.SHA)
        payload["workflow_run"]["head_repository"]["full_name"] = "attacker/site"
        with self.assertRaises(RC.ContractError):
            RC.plan_workflow_run(payload, "owner/site")

    def test_two_and_three_rapid_merges_are_unique_even_out_of_order(self):
        versions = [RC.Version.parse(v) for v in ("0.1.10", "0.1.11", "0.1.12")]
        shas = [character * 40 for character in "abc"]
        intents = [RC.ReleaseIntent(sha, version) for sha, version in zip(shas, versions)]
        completion_order = [intents[2], intents[0], intents[1]]
        self.assertEqual({intent.tag for intent in completion_order}, {"v0.1.10", "v0.1.11", "v0.1.12"})
        self.assertEqual(len({intent.source_sha for intent in completion_order}), 3)
        self.assertEqual(RC.ReleaseIntent(shas[0], versions[0]), RC.ReleaseIntent(shas[0], versions[0]))


class MainRunBindingTests(unittest.TestCase):
    SHA = "a" * 40

    @staticmethod
    def invoke(record: dict[str, object], *, run_id: int = 123, source_sha: str | None = None) -> int:
        with tempfile.TemporaryDirectory() as temporary:
            run_json = Path(temporary) / "main-run.json"
            run_json.write_text(json.dumps(record), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return RC.main(
                    [
                        "main-run-record",
                        "--run-json",
                        str(run_json),
                        "--run-id",
                        str(run_id),
                        "--repository",
                        "owner/site",
                        "--source-sha",
                        source_sha or MainRunBindingTests.SHA,
                    ]
                )

    def test_exact_authoritative_successful_main_run_is_accepted(self):
        exact = main_run_record(self.SHA)
        self.assertEqual(
            RC.validate_main_run_record(
                exact,
                expected_repository="owner/site",
                expected_run_id=123,
                expected_source_sha=self.SHA,
            ),
            self.SHA,
        )
        self.assertEqual(self.invoke(exact), 0)

    def test_ordinary_manual_unmerged_dispatch_is_executable_denial(self):
        unmerged = main_run_record(self.SHA)
        unmerged["event"] = "pull_request"
        unmerged["head_branch"] = "ci/unmerged-source"
        self.assertEqual(self.invoke(unmerged), 1)

    def test_foreign_failed_stale_path_identity_and_id_mutants_fail(self):
        exact = main_run_record(self.SHA)
        mutations: list[dict[str, object]] = []
        for path, value in (
            (("id",), 124),
            (("name",), "PR Gate"),
            (("path",), ".github/workflows/other.yml"),
            (("event",), "pull_request"),
            (("status",), "in_progress"),
            (("conclusion",), "failure"),
            (("head_branch",), "release"),
            (("head_sha",), "b" * 40),
            (("repository", "full_name"), "attacker/site"),
            (("head_repository", "full_name"), "attacker/site"),
        ):
            changed = copy.deepcopy(exact)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(record_mutation=index):
                self.assertEqual(self.invoke(changed), 1)
        self.assertEqual(self.invoke(exact, run_id=124), 1)
        self.assertEqual(self.invoke(exact, source_sha="b" * 40), 1)


class MainJobBindingTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_main_job_inventory_and_contextual_skip_are_accepted(self):
        record = main_jobs_record(self.SHA)
        self.assertEqual(
            RC.validate_main_jobs_record(
                record, expected_run_id=123, expected_source_sha=self.SHA
            ),
            self.SHA,
        )

    def test_skipped_critical_missing_duplicate_extra_and_foreign_jobs_fail(self):
        exact = main_jobs_record(self.SHA)
        mutations: list[dict[str, object]] = []
        for name in ("security", "application", "chart"):
            changed = copy.deepcopy(exact)
            job = next(job for job in changed["jobs"] if job["name"] == name)
            job["conclusion"] = "skipped"
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"] = changed["jobs"][:-1]
        changed["total_count"] -= 1
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"][-1]["name"] = changed["jobs"][0]["name"]
        mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["jobs"].append(
            {
                "id": 99,
                "run_id": 123,
                "head_sha": self.SHA,
                "name": "foreign",
                "status": "completed",
                "conclusion": "success",
            }
        )
        changed["total_count"] += 1
        mutations.append(changed)
        for path, value in (
            (("jobs", 0, "run_id"), 999),
            (("jobs", 0, "head_sha"), "b" * 40),
            (("jobs", 0, "status"), "in_progress"),
            (("jobs", 0, "conclusion"), "cancelled"),
            (("total_count",), 99),
        ):
            changed = copy.deepcopy(exact)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(job_mutant=index), self.assertRaises(RC.ContractError):
                RC.validate_main_jobs_record(
                    changed, expected_run_id=123, expected_source_sha=self.SHA
                )

    def test_a_contextually_skipped_job_reporting_success_is_refused(self):
        """The skip pins are load-bearing in the fail-OPEN direction too.

        Every mutation above turns an expected `success` into `skipped` --
        the direction where a job silently stopped running. The opposite
        direction was untested: a job the inventory expects to be `skipped`
        can only report `success` because its pull-request condition in
        pr-gate.yml is gone, which is exactly the drift the closed inventory
        exists to catch. Both pull-request-only jobs are proven here, and
        each asserts its recorded conclusion first so a future constant
        change cannot quietly turn this mutation into a no-op.
        """
        exact = main_jobs_record(self.SHA)
        for name in ("container", "dependency-review"):
            changed = copy.deepcopy(exact)
            job = next(job for job in changed["jobs"] if job["name"] == name)
            self.assertEqual(job["conclusion"], "skipped")
            job["conclusion"] = "success"
            with self.subTest(fail_open_mutant=name), self.assertRaises(RC.ContractError):
                RC.validate_main_jobs_record(
                    changed, expected_run_id=123, expected_source_sha=self.SHA
                )

    def test_no_badge_outcome_reaches_the_release_inventory(self):
        """A badge job is not a release input, either way.

        This repository publishes no coverage badge. The inventory is exactly
        the five gate jobs, so a badge job added to the gate is foreign
        whatever it concluded -- a success cannot admit a release, and a
        failure was never asked about. The five-job record stands without any
        badge job, and every one of its five names is still required.
        """
        self.assertEqual(
            RC.EXPECTED_MAIN_JOBS,
            {
                "application": "success",
                "chart": "success",
                "container": "skipped",
                "dependency-review": "skipped",
                "security": "success",
            },
        )
        exact = main_jobs_record(self.SHA)
        self.assertEqual(
            RC.validate_main_jobs_record(exact, expected_run_id=123, expected_source_sha=self.SHA),
            self.SHA,
        )
        for conclusion in ("success", "failure", "skipped", "cancelled"):
            changed = copy.deepcopy(exact)
            changed["jobs"].append(
                {
                    "id": 6,
                    "run_id": 123,
                    "head_sha": self.SHA,
                    "name": "coverage-badges",
                    "status": "completed",
                    "conclusion": conclusion,
                }
            )
            changed["total_count"] += 1
            with self.subTest(badge_job=conclusion), self.assertRaises(RC.ContractError):
                RC.validate_main_jobs_record(
                    changed, expected_run_id=123, expected_source_sha=self.SHA
                )
        for name in RC.EXPECTED_MAIN_JOBS:
            changed = copy.deepcopy(exact)
            changed["jobs"] = [job for job in changed["jobs"] if job["name"] != name]
            changed["total_count"] -= 1
            with self.subTest(missing=name), self.assertRaises(RC.ContractError):
                RC.validate_main_jobs_record(
                    changed, expected_run_id=123, expected_source_sha=self.SHA
                )


class CodeQLAuthorizationTests(unittest.TestCase):
    SHA = "a" * 40

    def test_exact_source_run_and_all_matrix_jobs_are_accepted(self):
        run = codeql_run_record(self.SHA)
        self.assertEqual(
            RC.classify_codeql_run_record(
                run, expected_repository="owner/site", expected_source_sha=self.SHA
            ),
            456,
        )
        self.assertEqual(
            RC.validate_codeql_jobs_record(
                codeql_jobs_record(self.SHA),
                expected_run_id=456,
                expected_source_sha=self.SHA,
            ),
            self.SHA,
        )

    def test_absent_and_in_progress_exact_source_runs_remain_bounded_pending(self):
        self.assertIsNone(
            RC.classify_codeql_run_record(
                {"total_count": 0, "workflow_runs": []},
                expected_repository="owner/site",
                expected_source_sha=self.SHA,
            )
        )
        pending = codeql_run_record(self.SHA)
        pending["workflow_runs"][0]["status"] = "in_progress"
        pending["workflow_runs"][0]["conclusion"] = None
        self.assertIsNone(
            RC.classify_codeql_run_record(
                pending, expected_repository="owner/site", expected_source_sha=self.SHA
            )
        )

    def test_failed_skipped_wrong_sha_duplicate_and_foreign_runs_fail(self):
        exact = codeql_run_record(self.SHA)
        mutations: list[dict[str, object]] = []
        for path, value in (
            (("workflow_runs", 0, "conclusion"), "failure"),
            (("workflow_runs", 0, "conclusion"), "skipped"),
            (("workflow_runs", 0, "head_sha"), "b" * 40),
            (("workflow_runs", 0, "head_branch"), "release"),
            (("workflow_runs", 0, "event"), "pull_request"),
            (("workflow_runs", 0, "path"), ".github/workflows/foreign.yml"),
            (("workflow_runs", 0, "repository", "full_name"), "attacker/site"),
        ):
            changed = copy.deepcopy(exact)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(changed)
        duplicate = copy.deepcopy(exact)
        duplicate["workflow_runs"].append(copy.deepcopy(duplicate["workflow_runs"][0]))
        duplicate["total_count"] = 2
        mutations.append(duplicate)
        for index, changed in enumerate(mutations):
            with self.subTest(run_mutant=index), self.assertRaises(RC.ContractError):
                RC.classify_codeql_run_record(
                    changed,
                    expected_repository="owner/site",
                    expected_source_sha=self.SHA,
                )

    def test_skipped_failed_missing_duplicate_extra_and_wrong_sha_jobs_fail(self):
        exact = codeql_jobs_record(self.SHA)
        mutations: list[dict[str, object]] = []
        for conclusion in ("skipped", "failure", "cancelled"):
            changed = copy.deepcopy(exact)
            changed["jobs"][0]["conclusion"] = conclusion
            mutations.append(changed)
        for path, value in (
            (("jobs", 0, "head_sha"), "b" * 40),
            (("jobs", 0, "status"), "in_progress"),
            (("jobs", 0, "name"), "analyze (ruby, none)"),
            (("jobs", 0, "run_id"), 999),
        ):
            changed = copy.deepcopy(exact)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(changed)
        missing = copy.deepcopy(exact)
        missing["jobs"] = missing["jobs"][:1]
        missing["total_count"] = 1
        mutations.append(missing)
        duplicate = copy.deepcopy(exact)
        duplicate["jobs"][1]["name"] = duplicate["jobs"][0]["name"]
        mutations.append(duplicate)
        extra = copy.deepcopy(exact)
        extra["jobs"].append(copy.deepcopy(extra["jobs"][0]))
        extra["jobs"][-1]["id"] = 99
        extra["jobs"][-1]["name"] = "foreign"
        extra["total_count"] = len(extra["jobs"])
        mutations.append(extra)
        for index, changed in enumerate(mutations):
            with self.subTest(codeql_job_mutant=index), self.assertRaises(RC.ContractError):
                RC.validate_codeql_jobs_record(
                    changed, expected_run_id=456, expected_source_sha=self.SHA
                )

    def test_python_analysis_is_present_and_cannot_be_missing_or_skipped(self):
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        matrix = re.findall(r"- language: ([\w-]+)\s+build-mode: (\w+)", workflow)
        self.assertIn(("python", "none"), matrix)
        exact = codeql_jobs_record(self.SHA)
        python_job = next(job for job in exact["jobs"] if job["name"] == "analyze (python, none)")
        python_job["conclusion"] = "skipped"
        with self.assertRaises(RC.ContractError):
            RC.validate_codeql_jobs_record(exact, expected_run_id=456, expected_source_sha=self.SHA)
        exact["jobs"].remove(python_job)
        exact["total_count"] = len(exact["jobs"])
        with self.assertRaises(RC.ContractError):
            RC.validate_codeql_jobs_record(exact, expected_run_id=456, expected_source_sha=self.SHA)


class RawSBOMBindingTests(unittest.TestCase):
    def test_exact_two_platform_raw_sbom_chain_is_accepted(self):
        fixture = sbom_registry_fixture()
        plan = RC.validate_sbom_index(
            fixture["index"], expected_image_digest=fixture["image_digest"]
        )
        self.assertEqual(set(plan), {"linux/amd64", "linux/arm64"})
        for platform in RC.RELEASE_MANIFEST_PLATFORMS:
            layer_digest = RC.validate_sbom_attestation_manifest(
                fixture["attestation_manifests"][platform],
                expected_attestation_digest=fixture["attestation_digests"][platform],
            )
            RC.validate_sbom_statement(
                fixture["statements"][platform],
                expected_layer_digest=layer_digest,
                image=fixture["image"],
                expected_subject_digest=fixture["subjects"][platform],
                platform=platform,
            )

    def test_sbom_statement_type_literal_is_the_pinned_in_toto_v1_uri(self):
        # Hardcoded here rather than read from RC.SBOM_STATEMENT_TYPE: the
        # fixture builds its statement FROM the module constant, so without
        # this literal the oracle is self-referential and any constant value
        # passes -- exactly how the v0.1 pin survived until the first live
        # v0.1.17 publish DENYed on a real BuildKit statement. BuildKit
        # attaches in-toto v1 statements; cosign generates v0.1 ones. The
        # two generators are pinned by SEPARATE constants with OPPOSITE
        # correct values, each guarded by its own literal test (the cosign
        # side is test_statement_type_literal_is_the_pinned_in_toto_v01_uri).
        # A mutant reverting SBOM_STATEMENT_TYPE to v0.1 turns this red.
        fixture = sbom_registry_fixture()
        statement = json.loads(fixture["statements"]["linux/amd64"])
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")

    def test_null_malformed_wrong_platform_wrong_subject_duplicate_and_extra_fail(self):
        fixture = sbom_registry_fixture()
        exact = json.loads(fixture["statements"]["linux/amd64"])
        statements: list[dict[str, object]] = []
        for path, value in (
            (("predicate",), None),
            (("_type",), "https://in-toto.io/Statement/v0.1"),
            (("predicateType",), "https://example.test/foreign"),
            (("predicate", "spdxVersion"), "SPDX-2.2"),
            (("predicate", "packages"), None),
            (("subject", 0, "name"), "pkg:docker/ghcr.io/owner/site@x?platform=linux%2Farm64"),
            (("subject", 0, "digest", "sha256"), "f" * 64),
        ):
            changed = copy.deepcopy(exact)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            statements.append(changed)
        duplicate_subject = copy.deepcopy(exact)
        duplicate_subject["subject"].append(copy.deepcopy(duplicate_subject["subject"][0]))
        statements.append(duplicate_subject)
        extra_top = copy.deepcopy(exact)
        extra_top["foreign"] = True
        statements.append(extra_top)
        for index, changed in enumerate(statements):
            payload = json.dumps(changed, sort_keys=True).encode("utf-8")
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            with self.subTest(statement_mutant=index), self.assertRaises(RC.ContractError):
                RC.validate_sbom_statement(
                    payload,
                    expected_layer_digest=digest,
                    image=fixture["image"],
                    expected_subject_digest=fixture["subjects"]["linux/amd64"],
                    platform="linux/amd64",
                )

    def test_duplicate_extra_foreign_and_missing_carriers_fail(self):
        fixture = sbom_registry_fixture()
        exact_index = json.loads(fixture["index"])
        index_mutants: list[dict[str, object]] = []
        for mutate in (
            lambda value: value["manifests"].pop(),
            lambda value: value["manifests"].append(copy.deepcopy(value["manifests"][0])),
            lambda value: value["manifests"][0]["platform"].update(architecture="s390x"),
            lambda value: value["manifests"][2]["annotations"].update(
                {"vnd.docker.reference.digest": "sha256:" + "f" * 64}
            ),
        ):
            changed = copy.deepcopy(exact_index)
            mutate(changed)
            index_mutants.append(changed)
        for index, changed in enumerate(index_mutants):
            payload = json.dumps(changed, sort_keys=True).encode("utf-8")
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            with self.subTest(index_mutant=index), self.assertRaises(RC.ContractError):
                RC.validate_sbom_index(payload, expected_image_digest=digest)

        exact_manifest = json.loads(fixture["attestation_manifests"]["linux/amd64"])
        manifest_mutants: list[dict[str, object]] = []
        for mutate in (
            lambda value: value["layers"].pop(),
            lambda value: value["layers"].append(copy.deepcopy(value["layers"][1])),
            lambda value: value["layers"][0]["annotations"].update(
                {"in-toto.io/predicate-type": RC.SBOM_PREDICATE_TYPE}
            ),
            lambda value: value["layers"][1].update(
                {"mediaType": "application/octet-stream"}
            ),
        ):
            changed = copy.deepcopy(exact_manifest)
            mutate(changed)
            manifest_mutants.append(changed)
        for index, changed in enumerate(manifest_mutants):
            payload = json.dumps(changed, sort_keys=True).encode("utf-8")
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            with self.subTest(carrier_mutant=index), self.assertRaises(RC.ContractError):
                RC.validate_sbom_attestation_manifest(
                    payload, expected_attestation_digest=digest
                )



class MainBranchRulesetInventoryTests(unittest.TestCase):
    """The branch-ruleset inventory after the owner-update retirement.

    `Owner-PR-Updates` was one `update` rule whose sole bypass actor was the
    repository owner in `pull_request` mode, so every merge of a passing pull
    request went through a bypass instead of through the rules. It was retired
    on 2026-09-22 by owner directive. What replaces its four receipt fields is
    a closed inventory: exactly one active repository-owned branch ruleset,
    the core security one. That is what makes the receipt's existing
    `restrict_updates: false` a statement about the whole branch-protection
    surface rather than about one ruleset among several -- a second active
    branch ruleset is exactly where an `update` rule, and the bypass actor
    such a rule needs to stay mergeable, used to live unseen.
    """

    def test_a_second_active_branch_ruleset_is_refused_however_it_arrives(self):
        exact = settings_api()
        self.assertEqual(SettingsReceiptTests.observe(exact), settings_receipt())
        core = exact["repos/owner/site/rulesets"][0]
        retired = {
            "id": 44, "name": "Owner-PR-Updates", "target": "branch",
            "source_type": "Repository", "source": "owner/site",
            "enforcement": "active",
        }
        for inventory in (
            # The retired restriction itself, back in the inventory.
            [core, retired],
            # Any other active repository-owned branch ruleset, named or not:
            # the receipt cannot describe rules it never reads.
            [core, {**retired, "name": "Protect-Main-Too"}],
            [core, {**retired, "name": RC.EXPECTED_MAIN_RULESET, "id": 45}],
            # A duplicate summary of the core ruleset is ambiguous, not extra.
            [core, core],
            # And the core ruleset must actually be there.
            [retired],
            [],
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/site/rulesets"] = copy.deepcopy(inventory)
            with self.subTest(inventory=inventory), self.assertRaises(RC.ContractError):
                SettingsReceiptTests.observe(changed)

    def test_inactive_and_foreign_target_rulesets_stay_out_of_the_count(self):
        # Retirement is a deletion, but a disabled or evaluate-mode leftover is
        # not an active rule, and the tag ruleset has its own separate
        # zero-bypass check. Neither may deny an otherwise exact preflight.
        exact = settings_api()
        core = exact["repos/owner/site/rulesets"][0]
        for extra in (
            {"id": 44, "name": "Owner-PR-Updates", "target": "branch",
             "source_type": "Repository", "source": "owner/site",
             "enforcement": "disabled"},
            {"id": 44, "name": "Owner-PR-Updates", "target": "branch",
             "source_type": "Repository", "source": "owner/site",
             "enforcement": "evaluate"},
            {"id": 44, "name": RC.EXPECTED_MAIN_RULESET, "target": "tag",
             "source_type": "Repository", "source": "owner/site",
             "enforcement": "active"},
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/site/rulesets"] = [core, extra]
            with self.subTest(extra=(extra["enforcement"], extra["target"])):
                self.assertEqual(
                    SettingsReceiptTests.observe(changed), settings_receipt()
                )

    def test_the_receipt_cannot_claim_another_count_or_a_retired_field(self):
        for invalid in (None, "1", True, 0, 2):
            changed = settings_receipt()
            changed["active_main_branch_ruleset_count"] = invalid
            with self.subTest(count=invalid), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        # The schema is closed in the other direction too: a receipt carrying
        # any field of the retired restriction -- including the bypass claim CI
        # was never able to observe -- is foreign, not merely ignored.
        for retired, value in (
            ("owner_update_ruleset", "Owner-PR-Updates"),
            ("owner_update_ref", "~DEFAULT_BRANCH"),
            ("owner_update_fetch_and_merge", False),
            ("owner_update_bypass", "owner-user-pull-request"),
        ):
            changed = settings_receipt()
            changed[retired] = value
            with self.subTest(retired=retired), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        self.assertNotIn("owner_update_bypass", settings_receipt())


class SettingsReceiptTests(unittest.TestCase):
    #: Load-bearing phrases of the runbook. Each states a fact the code or
    #: the workflows make true; deleting one, or inverting it (see
    #: `RUNBOOK_INVERSIONS`), turns `test_settings_cli_and_runbook_are_load_bearing`
    #: red.
    RUNBOOK_TOKENS = (
        "Release-control readiness receipt",
        '"private_vulnerability_reporting": true',
        '"merge_methods": ["rebase", "squash"]',
        '"context": "security", "integration_id": 15368',
        '"context": "dependency-review", "integration_id": 15368',
        '"strict_status_checks": true',
        '"require_pull_request": true',
        '"required_approving_review_count": 0',
        '"dismiss_stale_reviews_on_push": false',
        '"required_reviewers": []',
        '"require_code_owner_review": false',
        '"require_extra_approval_for_unattributed_changes": true',
        '"require_last_push_approval": false',
        '"required_review_thread_resolution": true',
        '"require_linear_history": true',
        '"require_signed_commits": true',
        '"restrict_creations": true',
        '"allow_force_pushes": false',
        '"allow_deletions": false',
        '"restrict_updates": false',
        '"active_main_branch_ruleset_count": 1',
        '"code_scanning_tools": [',
        '"security_alerts_threshold": "high_or_higher"',
        '"alerts_threshold": "errors"',
        '"code_quality_severity": "errors"',
        '"minimum_code_coverage": 80',
        '"maximum_code_coverage_drop": null',
        "Owner-verified",
        "has write access to the ruleset",
        "--jq '.bypass_actors'",
        "# must print: []",
        "private-vulnerability-reporting",
        "settings-preflight",
        "settings-receipt",
        "zero variables",
        "zero secrets",
        "signed-in owner UI transaction",
        "remains an external Ready blocker",
        "must remain Draft",
        # The settings job's credential, stated exactly as the workflow
        # declares it, and the absence of any App credential.
        "`GH_TOKEN: ${{ github.token }}`",
        "credential is used and none is stored",
        "It reads exactly four endpoints",
        "It reads no Administration-only endpoint",
        "The receipt carries none of these fields",
        # The owner-verified commands for what that token cannot read.
        "release_contract.py immutable-settings",
        "# must print: exact",
        "/actions/permissions \\\n",
        "# must print: true true",
        "/actions/permissions/workflow",
        "# must print: read false",
        "# must print: enabled enabled",
        "No settings of this repository have been observed yet.",
        "it carries no development-dependency scope",
        "`--include-dev-deps` is a source/lockfile concept",
        "rejects as an unknown flag on `trivy image`",
        "the audit does not restate that",
    )
    RUNBOOK_INVERSIONS = (
        ('"private_vulnerability_reporting": true', '"private_vulnerability_reporting": false'),
        ('"strict_status_checks": true', '"strict_status_checks": false'),
        ('"allow_force_pushes": false', '"allow_force_pushes": true'),
        ('"allow_deletions": false', '"allow_deletions": true'),
        ('"restrict_updates": false', '"restrict_updates": true'),
        ('"active_main_branch_ruleset_count": 1', '"active_main_branch_ruleset_count": 2'),
        ('"require_signed_commits": true', '"require_signed_commits": false'),
        (
            '"require_extra_approval_for_unattributed_changes": true',
            '"require_extra_approval_for_unattributed_changes": false',
        ),
        ("credential is used and none is stored", "credential is used and one is stored"),
        ("It reads exactly four endpoints", "It reads exactly seven endpoints"),
        ("# must print: true true", "# must print: true false"),
        ("# must print: read false", "# must print: write false"),
        ("# must print: enabled enabled", "# must print: enabled disabled"),
        (
            "No settings of this repository have been observed yet.",
            "Every setting of this repository has been observed.",
        ),
        (
            "it carries no development-dependency scope",
            "it carries the same development-dependency scope",
        ),
        ("the audit does not restate that", "the audit restates that"),
    )
    #: A settings path this repository does not have. Any of these in the
    #: runbook is a claim of App use, or of an Administration read the job
    #: token cannot make.
    RUNBOOK_FORBIDDEN = (
        "vars.PLATFORM_RELEASE_APP_ID",
        "secrets.PLATFORM_RELEASE_APP_PRIVATE_KEY",
        "create-github-app-token",
        "IMMUTABLE_SETTINGS_TOKEN",
        "App-backed publication",
        "Administration-read App token",
        "`immutable_settings` job",
    )

    @classmethod
    def require_documented_contract(cls, text: str) -> None:
        for token in cls.RUNBOOK_TOKENS:
            if token not in text:
                raise ValueError(f"release settings contract lost: {token}")
        for forbidden in cls.RUNBOOK_FORBIDDEN:
            if forbidden in text:
                raise ValueError(f"release settings contract claims a path it does not have: {forbidden}")

    def test_only_the_exact_immutable_no_bypass_receipt_is_ready(self):
        exact = settings_receipt()
        RC.validate_settings_receipt(exact, "owner/site")
        mutations: list[dict[str, object]] = []
        for key, value in (
            ("repository", "other/site"),
            ("branch", "release"),
            ("merge_methods", ["squash"]),
            ("merge_methods", ["merge", "rebase", "squash"]),
            ("merge_methods", ["rebase", "rebase", "squash"]),
            ("strict_status_checks", False),
            ("require_pull_request", False),
            ("required_approving_review_count", 1),
            ("dismiss_stale_reviews_on_push", True),
            ("required_reviewers", [{"foreign": True}]),
            ("require_code_owner_review", True),
            ("require_extra_approval_for_unattributed_changes", False),
            ("require_last_push_approval", True),
            ("required_review_thread_resolution", False),
            ("require_linear_history", False),
            ("require_signed_commits", False),
            ("restrict_creations", False),
            ("allow_force_pushes", True),
            ("allow_deletions", True),
            ("restrict_updates", True),
            ("code_scanning_tools", []),
            (
                "code_scanning_tools",
                [
                    {
                        "tool": "CodeQL",
                        "security_alerts_threshold": "critical",
                        "alerts_threshold": "errors",
                    }
                ],
            ),
            ("code_quality_severity", "warnings"),
            ("minimum_code_coverage", 79),
            ("maximum_code_coverage_drop", 1),
            ("private_vulnerability_reporting", False),
            ("private_vulnerability_reporting", None),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            mutations.append(changed)
        checks = copy.deepcopy(exact["required_status_checks"])
        for replacement in (
            checks[:-1],
            [*checks, {"context": "foreign", "integration_id": 15368}],
            [*checks, copy.deepcopy(checks[0])],
            [{**check, "integration_id": 1} for check in checks],
            [{"context": check["context"]} for check in checks],
        ):
            changed = copy.deepcopy(exact)
            changed["required_status_checks"] = replacement
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        for key in exact:
            changed = copy.deepcopy(exact)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        changed = copy.deepcopy(exact)
        changed["ruleset_id"] = 42
        with self.assertRaises(RC.ContractError):
            RC.validate_settings_receipt(changed, "owner/site")

    @staticmethod
    def observe(records: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(
            RC,
            "_github_api_get",
            side_effect=lambda endpoint, **_options: records[endpoint],
        ) as getter:
            receipt = RC.observe_live_settings("owner/site")
        self_calls = [call.args[0] for call in getter.call_args_list]
        if self_calls != list(SettingsReceiptTests.TOKEN_READABLE_ENDPOINTS):
            raise AssertionError(f"unexpected settings endpoints: {self_calls}")
        if getter.call_args_list[2].kwargs != {"paginate": True}:
            raise AssertionError("ruleset inventory must use exhaustive pagination")
        if any(call.kwargs for index, call in enumerate(getter.call_args_list) if index != 2):
            raise AssertionError("only the list endpoint should paginate")
        return receipt

    #: Exactly what the settings job's `github.token` (contents: read) can
    #: GET on a public repository, in the order the preflight reads it.
    TOKEN_READABLE_ENDPOINTS = (
        "repos/owner/site",
        "repos/owner/site/private-vulnerability-reporting",
        "repos/owner/site/rulesets",
        "repos/owner/site/rulesets/42",
    )

    @staticmethod
    def observe_as_the_job_token(records: dict[str, object]) -> dict[str, object]:
        """Run the preflight against a GitHub that answers the way it answers
        the settings job's token: every endpoint the fixture holds, and a
        denial -- the `gh api` failure -- for anything else, the
        Administration-only endpoints first among them."""

        def answer(endpoint: str, **_options: object) -> object:
            if endpoint not in records:
                raise RC.ContractError("read-only GitHub settings query failed")
            return records[endpoint]

        with mock.patch.object(RC, "_github_api_get", side_effect=answer):
            return RC.observe_live_settings("owner/site")

    def test_admin_only_settings_are_neither_read_nor_receipted(self):
        """The receipt is exactly what the job token can see, and stays so.

        The settings job runs under its own `github.token` with contents read:
        no App token, no stored credential. Under that token the
        Administration-only endpoints answer with a denial and the repository
        record carries no `security_and_analysis` block. This pins all of it
        shut in both directions, so re-adding one of those GETs, or one of
        those receipt fields, without the credential that could read it is a
        red suite rather than a release that denies on every dispatch.
        """
        records = settings_api()
        for endpoint in ADMIN_ONLY_SETTINGS_ENDPOINTS:
            self.assertNotIn(endpoint, records)
            self.assertNotIn(endpoint, self.TOKEN_READABLE_ENDPOINTS)
        self.assertNotIn("security_and_analysis", records["repos/owner/site"])
        # The token-shaped GitHub builds the exact receipt, reading only the
        # four token-readable endpoints (observe() pins the order).
        receipt = self.observe_as_the_job_token(copy.deepcopy(records))
        self.assertEqual(receipt, settings_receipt())
        self.assertEqual(self.observe(copy.deepcopy(records)), receipt)
        for field in ADMIN_ONLY_RECEIPT_FIELDS:
            self.assertNotIn(field, receipt)
        # An administrator's GitHub answers more -- every Administration-only
        # endpoint, the security block, even values that would fail the old
        # receipt. None of it is read, so none of it steers the outcome.
        widened = copy.deepcopy(records)
        widened["repos/owner/site"]["security_and_analysis"] = {
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
        }
        widened["repos/owner/site/immutable-releases"] = {"enabled": False, "enforced_by_owner": False}
        widened["repos/owner/site/actions/permissions"] = {"enabled": False}
        widened["repos/owner/site/actions/permissions/workflow"] = {
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": True,
        }
        self.assertEqual(self.observe_as_the_job_token(widened), receipt)
        # Re-adding an Administration-only GET is a denial under the job token,
        # whichever endpoint it is and wherever it lands in the sequence.
        original = RC._github_api_get
        for endpoint in ADMIN_ONLY_SETTINGS_ENDPOINTS:
            def regressed(path: str, *, paginate: bool = False, _extra: str = endpoint) -> object:
                if path == "repos/owner/site/private-vulnerability-reporting":
                    original_answer = answer_from(records, path)
                    answer_from(records, _extra)
                    return original_answer
                return answer_from(records, path)

            def answer_from(table: dict[str, object], path: str) -> object:
                if path not in table:
                    raise RC.ContractError("read-only GitHub settings query failed")
                return table[path]

            with self.subTest(admin_get=endpoint), mock.patch.object(
                RC, "_github_api_get", side_effect=regressed
            ), self.assertRaises(RC.ContractError):
                RC.observe_live_settings("owner/site")
        self.assertIs(RC._github_api_get, original)
        # The receipt half is closed: every removed field, re-added with the
        # value the old receipt demanded, is foreign rather than tolerated.
        restored = {
            "actions_allowed_actions": "all",
            "actions_can_approve_pull_request_reviews": False,
            "actions_enabled": True,
            "actions_sha_pinning_required": True,
            "default_workflow_permissions": "read",
            "immutable_releases": True,
            "secret_scanning": True,
            "secret_scanning_non_provider_patterns": False,
            "secret_scanning_push_protection": True,
            "secret_scanning_validity_checks": False,
        }
        self.assertEqual(sorted(restored), sorted(ADMIN_ONLY_RECEIPT_FIELDS))
        for field, value in restored.items():
            changed = settings_receipt()
            changed[field] = value
            with self.subTest(readded_field=field), self.assertRaises(RC.ContractError) as caught:
                RC.validate_settings_receipt(changed, "owner/site")
            self.assertIn("missing or foreign", str(caught.exception))
        # And the runbook's published receipt is the code's receipt, field for
        # field: it validates for this repository and names no removed field.
        runbook = (ROOT / "docs" / "release-governance.md").read_text(encoding="utf-8")
        documented = json.loads(
            runbook.split("The exact successful receipt is:\n\n```json\n", 1)[1].split("\n```", 1)[0]
        )
        RC.validate_settings_receipt(documented, RC.EXPECTED_REPOSITORY)
        self.assertEqual(sorted(documented), sorted(settings_receipt()))
        for field in ADMIN_ONLY_RECEIPT_FIELDS:
            readded = dict(documented, **{field: restored[field]})
            with self.subTest(documented_field=field), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(readded, RC.EXPECTED_REPOSITORY)

    def test_authoritative_raw_preflight_rejects_every_control_mutant(self):
        exact = settings_api()
        self.assertEqual(self.observe(copy.deepcopy(exact)), settings_receipt())

        mutations: list[dict[str, object]] = []
        for endpoint, path, value in (
            ("repos/owner/site", ("default_branch",), "release"),
            ("repos/owner/site", ("full_name",), "other/site"),
            ("repos/owner/site/private-vulnerability-reporting", ("enabled",), False),
            ("repos/owner/site/private-vulnerability-reporting", ("enabled",), 1),
            ("repos/owner/site/private-vulnerability-reporting", ("foreign",), True),
            ("repos/owner/site/rulesets/42", ("enforcement",), "disabled"),
            ("repos/owner/site/rulesets/42", ("conditions", "ref_name", "include"), ["~ALL"]),
        ):
            changed = copy.deepcopy(exact)
            parent = changed[endpoint]
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)

        detail = exact["repos/owner/site/rulesets/42"]
        rules = detail["rules"]
        for rule_type in (
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
        ):
            changed = copy.deepcopy(exact)
            changed["repos/owner/site/rulesets/42"]["rules"] = [
                rule for rule in rules if rule["type"] != rule_type
            ]
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets/42"]["rules"].append({"type": "update"})
        mutations.append(changed)

        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets/42"]["rules"][1]["parameters"] = {}
        mutations.append(changed)

        for field, value in (
            ("allowed_merge_methods", ["merge", "rebase", "squash"]),
            ("allowed_merge_methods", ["squash"]),
            ("allowed_merge_methods", ["rebase", "squash"]),
            ("required_approving_review_count", 1),
            ("dismiss_stale_reviews_on_push", True),
            ("required_reviewers", [{"foreign": True}]),
            ("require_code_owner_review", True),
            ("require_extra_approval_for_unattributed_changes", False),
            ("require_last_push_approval", True),
            ("required_review_thread_resolution", False),
        ):
            changed = copy.deepcopy(exact)
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"][field] = value
            mutations.append(changed)
        for field in RC.EXPECTED_PULL_REQUEST_PARAMETERS:
            changed = copy.deepcopy(exact)
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            del pull["parameters"][field]
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        pull = next(
            rule
            for rule in changed["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "pull_request"
        )
        pull["parameters"]["foreign"] = False
        mutations.append(changed)
        for field, value in (
            ("strict_required_status_checks_policy", False),
            ("do_not_enforce_on_create", True),
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        status = next(
            rule
            for rule in changed["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["foreign"] = False
        mutations.append(changed)
        for replacement in (
            [{"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS[:-1]],
            [
                *[{"context": context, "integration_id": 15368} for context in REQUIRED_CHECKS],
                {"context": "foreign", "integration_id": 15368},
            ],
            [{"context": context, "integration_id": 1} for context in REQUIRED_CHECKS],
        ):
            changed = copy.deepcopy(exact)
            status = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "required_status_checks"
            )
            status["parameters"]["required_status_checks"] = replacement
            mutations.append(changed)
        for rule_type, field, value in (
            ("code_scanning", "code_scanning_tools", []),
            (
                "code_scanning",
                "code_scanning_tools",
                [
                    {
                        "tool": "CodeQL",
                        "security_alerts_threshold": "critical",
                        "alerts_threshold": "errors",
                    }
                ],
            ),
            ("code_quality", "severity", "warnings"),
            ("code_coverage", "minimum_coverage", 79),
            ("code_coverage", "max_coverage_drop", 1),
        ):
            changed = copy.deepcopy(exact)
            rule = next(
                item
                for item in changed["repos/owner/site/rulesets/42"]["rules"]
                if item["type"] == rule_type
            )
            rule["parameters"][field] = value
            mutations.append(changed)
        for rule_type in ("code_scanning", "code_quality", "code_coverage"):
            changed = copy.deepcopy(exact)
            rule = next(
                item
                for item in changed["repos/owner/site/rulesets/42"]["rules"]
                if item["type"] == rule_type
            )
            rule["parameters"]["foreign"] = False
            mutations.append(changed)
        changed = copy.deepcopy(exact)
        changed["repos/owner/site/rulesets"].append(copy.deepcopy(changed["repos/owner/site/rulesets"][0]))
        mutations.append(changed)

        for index, changed in enumerate(mutations):
            with self.subTest(raw_mutation=index), self.assertRaises(RC.ContractError):
                self.observe(changed)

    def test_coverage_rule_admits_exactly_the_two_no_drop_shapes(self):
        """Minimum 80 and no maximum-drop threshold, spelled either way GitHub
        returns it -- the key absent (rulesets written since GitHub began
        refusing an explicit null) or present as null -- and nothing else."""

        def observed_with(parameters: object) -> dict[str, object]:
            records = settings_api()
            rule = next(
                item for item in records["repos/owner/site/rulesets/42"]["rules"]
                if item["type"] == "code_coverage"
            )
            rule["parameters"] = parameters
            return records

        for name, parameters in (
            ("key absent", {"minimum_coverage": 80}),
            ("explicit null", {"minimum_coverage": 80, "max_coverage_drop": None}),
        ):
            with self.subTest(accepted=name):
                receipt = self.observe(observed_with(copy.deepcopy(parameters)))
                self.assertEqual(receipt, settings_receipt())
                self.assertIs(receipt["maximum_code_coverage_drop"], None)
                self.assertEqual(receipt["minimum_code_coverage"], 80)
        for name, parameters in (
            ("numeric drop", {"minimum_coverage": 80, "max_coverage_drop": 1}),
            ("zero drop", {"minimum_coverage": 80, "max_coverage_drop": 0}),
            ("false drop", {"minimum_coverage": 80, "max_coverage_drop": False}),
            ("string drop", {"minimum_coverage": 80, "max_coverage_drop": "null"}),
            ("lower minimum", {"minimum_coverage": 79}),
            ("higher minimum", {"minimum_coverage": 81}),
            ("float minimum", {"minimum_coverage": 80.0}),
            ("string minimum", {"minimum_coverage": "80"}),
            ("boolean minimum", {"minimum_coverage": True}),
            ("no minimum", {}),
            ("drop only", {"max_coverage_drop": None}),
            ("extra key", {"minimum_coverage": 80, "foreign": None}),
            ("extra key beside null", {"minimum_coverage": 80, "max_coverage_drop": None, "foreign": 1}),
        ):
            # Refused by the rule check itself, not merely by a later layer:
            # the receipt validator also refuses a non-null drop, so only the
            # message proves the ruleset compare still holds on its own.
            with self.subTest(refused=name), self.assertRaises(RC.ContractError) as caught:
                self.observe(observed_with(copy.deepcopy(parameters)))
            self.assertIn("code-coverage rule is not exact", str(caught.exception))
        for name, parameters in (("not an object", [80]), ("null parameters", None)):
            with self.subTest(refused=name), self.assertRaises(RC.ContractError):
                self.observe(observed_with(copy.deepcopy(parameters)))
        # A foreign field beside the parameters, on either accepted shape.
        for parameters in ({"minimum_coverage": 80}, {"minimum_coverage": 80, "max_coverage_drop": None}):
            records = observed_with(copy.deepcopy(parameters))
            rule = next(
                item for item in records["repos/owner/site/rulesets/42"]["rules"]
                if item["type"] == "code_coverage"
            )
            rule["foreign"] = True
            with self.subTest(rule_level_foreign=sorted(parameters)), self.assertRaises(RC.ContractError):
                self.observe(records)
        # The receipt half still demands exactly null, whichever shape built it.
        for value in (0, False, 1, "null"):
            changed = settings_receipt()
            changed["maximum_code_coverage_drop"] = value
            with self.subTest(receipt_drop=value), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")

    def test_unattributed_approval_parameter_is_pinned_to_the_live_rule(self):
        # Issue #91.  On 2026-08-20 GitHub began returning
        # require_extra_approval_for_unattributed_changes in the live
        # Protect-Main pull_request rule.  The exact compare denied with
        # "pull-request rule parameters are not exact" -- correctly, because a
        # foreign field means the enforcing surface moved out from under the
        # anchor -- and releases 0.1.20, 0.1.21 and 0.1.22 stayed unpublished.
        # The re-anchor pins the field at its live value True (the stricter
        # direction), and this test binds the pin to the EXACT parameter object
        # the live ruleset returns, field for field, so a future silent drift
        # in either direction is a red test rather than a stuck release.
        live_parameters = {
            "allowed_merge_methods": ["squash", "rebase"],
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False,
            "require_extra_approval_for_unattributed_changes": True,
            "require_last_push_approval": False,
            "required_approving_review_count": 0,
            "required_review_thread_resolution": True,
            "required_reviewers": [],
        }
        self.assertEqual(RC.EXPECTED_PULL_REQUEST_PARAMETERS, live_parameters)

        def observed_with(parameters: dict[str, object]) -> dict[str, object]:
            records = settings_api()
            pull = next(
                rule
                for rule in records["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"] = copy.deepcopy(parameters)
            return records

        receipt = self.observe(observed_with(live_parameters))
        self.assertIs(receipt["require_extra_approval_for_unattributed_changes"], True)
        RC.validate_settings_receipt(receipt, "owner/site")

        absent = copy.deepcopy(live_parameters)
        del absent["require_extra_approval_for_unattributed_changes"]
        for name, parameters in (
            # The exact pre-fix live shape: the pin must no longer accept it.
            ("absent", absent),
            (
                "wrong-value",
                {**live_parameters, "require_extra_approval_for_unattributed_changes": False},
            ),
            # The closed set stays closed: re-anchoring one field must not have
            # taught the compare to tolerate the NEXT unknown field.
            ("further-foreign-field", {**live_parameters, "require_signature_hardening": True}),
        ):
            with self.subTest(pull_parameters=name):
                with self.assertRaises(RC.ContractError) as caught:
                    self.observe(observed_with(parameters))
                self.assertIn(
                    "pull-request rule parameters are not exact", str(caught.exception)
                )

        # The receipt half is closed and exact-valued too, so a receipt that
        # drops, inverts, or stringifies the field can never be Ready.
        for mutation in (
            "delete",
            False,
            "true",
            None,
        ):
            changed = copy.deepcopy(receipt)
            if mutation == "delete":
                del changed["require_extra_approval_for_unattributed_changes"]
            else:
                changed["require_extra_approval_for_unattributed_changes"] = mutation
            with self.subTest(receipt_mutation=mutation), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")

    # --- issue #93: Python's bool/int conflation across the settings pins ---
    #
    # `True == 1` and `False == 0`, so before this hardening a plain `==`
    # against a pinned boolean ALSO accepted the integer lookalike, and the
    # pin of the integer 0 (required_approving_review_count) also accepted
    # False. Both directions were live: the raw pull-request rule compare and
    # the derived receipt loop each admitted an authoritative record whose
    # enforcing surface had silently changed type. The lookalike -- 1 for
    # True, 0 for False, False for 0 -- is the only mutant that can survive a
    # value compare, so it is exactly what these fixtures inject.

    #: Fields whose pinned value has an equal-valued integer/boolean twin.
    CONFLATABLE_RECEIPT_FIELDS = (
        "active_main_branch_ruleset_count",
        "allow_deletions",
        "allow_force_pushes",
        "dismiss_stale_reviews_on_push",
        "private_vulnerability_reporting",
        "require_code_owner_review",
        "require_extra_approval_for_unattributed_changes",
        "require_last_push_approval",
        "require_linear_history",
        "require_pull_request",
        "require_signed_commits",
        "required_approving_review_count",
        "required_review_thread_resolution",
        "restrict_creations",
        "restrict_updates",
        "strict_status_checks",
    )

    @staticmethod
    def lookalike(value: object) -> object:
        """The equal-but-wrong-typed twin of a pinned boolean or 0/1 integer."""
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        raise AssertionError(f"value has no bool/int twin: {value!r}")

    @staticmethod
    def conflatable(record: dict[str, object]) -> dict[str, object]:
        return {
            field: value
            for field, value in record.items()
            if isinstance(value, bool) or (isinstance(value, int) and value in {0, 1})
        }

    def test_exact_pin_helper_closes_the_conflation_in_both_directions(self):
        # The helper is the single mechanism both call sites now share, so its
        # branches are exercised directly: a bool on either side must meet a
        # bool, and everything else keeps ordinary value equality.
        for actual, expected in (
            (True, True),
            (False, False),
            (0, 0),
            (1, 1),
            ("read", "read"),
            (None, None),
            ([], []),
            (["squash", "rebase"], ["squash", "rebase"]),
            (80, 80),
        ):
            with self.subTest(match=(actual, expected)):
                self.assertTrue(RC._exact_pin(actual, expected))
        for actual, expected in (
            (1, True),
            (True, 1),
            (0, False),
            (False, 0),
            (1, False),
            (False, 1),
            ("true", True),
            (None, False),
            ("read", "write"),
            (79, 80),
            ([], None),
        ):
            with self.subTest(mismatch=(actual, expected)):
                self.assertFalse(RC._exact_pin(actual, expected))
        self.assertTrue(
            RC._exact_pin_mapping({"a": True, "b": 0}, {"a": True, "b": 0})
        )
        for actual in (
            {"a": 1, "b": 0},
            {"a": True, "b": False},
            {"a": True},
            {"a": True, "b": 0, "c": "extra"},
            {"a": True, "c": 0},
        ):
            with self.subTest(mapping=actual):
                self.assertFalse(RC._exact_pin_mapping(actual, {"a": True, "b": 0}))

    def test_receipt_boolean_pins_reject_the_integer_one_and_zero(self):
        exact = settings_receipt()
        RC.validate_settings_receipt(exact, "owner/site")
        conflatable = self.conflatable(exact)
        # Re-anchoring is deliberate: a new boolean field must be added here
        # so it arrives with its lookalike mutant, never silently unguarded.
        self.assertEqual(
            sorted(conflatable),
            sorted(self.CONFLATABLE_RECEIPT_FIELDS),
            "the receipt's bool/int surface moved; re-anchor this pin",
        )
        for field, value in sorted(conflatable.items()):
            twin = self.lookalike(value)
            self.assertEqual(twin, value)
            self.assertIsNot(twin, value)
            changed = copy.deepcopy(exact)
            changed[field] = twin
            with self.subTest(receipt_lookalike=field), self.assertRaises(RC.ContractError):
                RC.validate_settings_receipt(changed, "owner/site")
        # Non-regression: the genuine values are untouched by the hardening.
        RC.validate_settings_receipt(settings_receipt(), "owner/site")

    def test_pull_request_rule_pins_reject_the_integer_one_and_zero(self):
        conflatable = self.conflatable(RC.EXPECTED_PULL_REQUEST_PARAMETERS)
        self.assertEqual(
            sorted(conflatable),
            [
                "dismiss_stale_reviews_on_push",
                "require_code_owner_review",
                "require_extra_approval_for_unattributed_changes",
                "require_last_push_approval",
                "required_approving_review_count",
                "required_review_thread_resolution",
            ],
            "the pull-request rule's bool/int surface moved; re-anchor this pin",
        )
        for field, value in sorted(conflatable.items()):
            records = settings_api()
            pull = next(
                rule
                for rule in records["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            self.assertEqual(pull["parameters"][field], value)
            pull["parameters"][field] = self.lookalike(value)
            with self.subTest(rule_lookalike=field):
                with self.assertRaises(RC.ContractError) as caught:
                    self.observe(records)
                self.assertIn(
                    "pull-request rule parameters are not exact", str(caught.exception)
                )
        # Non-regression: the live shape still builds the exact receipt.
        self.assertEqual(self.observe(settings_api()), settings_receipt())

    def test_merge_methods_bind_to_the_enforcing_ruleset_under_the_ci_credential(self):
        # The settings job runs under its read-only `github.token`, and GitHub
        # documents that "to view merge-related settings, you must have the
        # contents:read and contents:write permissions".  Deriving the receipt's
        # merge methods from repos/{owner}/{repo}'s allow_*_merge booleans is
        # therefore unsatisfiable in CI: the sibling repositories' publishers
        # denied on exactly that until the derivation moved.  The Protect-Main
        # ruleset is both readable by that credential and the control that
        # actually governs refs/heads/main, so it is the authoritative source.
        expected = settings_receipt()
        credential_shape = settings_api()
        repository_record = credential_shape["repos/owner/site"]
        for absent in ("allow_merge_commit", "allow_rebase_merge", "allow_squash_merge"):
            self.assertNotIn(absent, repository_record)
        self.assertEqual(self.observe(copy.deepcopy(credential_shape)), expected)
        self.assertEqual(expected["merge_methods"], ["rebase", "squash"])
        RC.validate_settings_receipt(expected, "owner/site")

        # A contents-write credential additionally returns the booleans.  The
        # receipt must be byte-identical either way, and must never be steered
        # by a field the enforcing ruleset does not own.
        for booleans in (
            {
                "allow_merge_commit": False,
                "allow_rebase_merge": True,
                "allow_squash_merge": True,
            },
            {
                "allow_merge_commit": True,
                "allow_rebase_merge": False,
                "allow_squash_merge": False,
            },
            {"allow_merge_commit": "false", "allow_rebase_merge": None},
        ):
            widened = copy.deepcopy(credential_shape)
            widened["repos/owner/site"].update(booleans)
            with self.subTest(repository_booleans=sorted(booleans)):
                self.assertEqual(self.observe(widened), expected)

        # The ruleset half stays fail-closed: a merge-commit-capable, narrowed,
        # duplicated, empty, missing, or non-list value can never build a
        # receipt, so no credential shape can smuggle merge commits onto main.
        for value in (
            ["merge", "squash"],
            ["merge", "rebase", "squash"],
            ["squash"],
            ["rebase"],
            ["squash", "squash"],
            [],
            "squash",
            None,
            {"squash": True, "rebase": True},
        ):
            changed = copy.deepcopy(credential_shape)
            pull = next(
                rule
                for rule in changed["repos/owner/site/rulesets/42"]["rules"]
                if rule["type"] == "pull_request"
            )
            pull["parameters"]["allowed_merge_methods"] = value
            with self.subTest(allowed_merge_methods=value), self.assertRaises(
                RC.ContractError
            ):
                self.observe(changed)
        missing = copy.deepcopy(credential_shape)
        pull = next(
            rule
            for rule in missing["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "pull_request"
        )
        del pull["parameters"]["allowed_merge_methods"]
        with self.assertRaises(RC.ContractError):
            self.observe(missing)

        # And the downstream validator keeps demanding exactly rebase+squash of
        # whatever the builder produced.
        for wrong in (["merge", "rebase", "squash"], ["squash"], ["rebase"], []):
            changed = copy.deepcopy(expected)
            changed["merge_methods"] = wrong
            with self.subTest(receipt_merge_methods=wrong), self.assertRaises(
                RC.ContractError
            ):
                RC.validate_settings_receipt(changed, "owner/site")

    def test_bypass_actors_are_unreadable_by_the_ci_credential_and_not_asserted(self):
        # GitHub's REST reference for "Get a repository ruleset" states: "To
        # prevent leaking sensitive information, the bypass_actors property is
        # only returned if the user making the API request has write access to
        # the ruleset."  The settings job's `github.token` (contents: read) has
        # no write access to the ruleset, so the property is absent from its
        # response entirely.  Reading it would deny before rules[] was ever
        # parsed, which is what happened in the sibling repositories, so CI
        # asserts exactly what the enforcing surface exposes to the CI
        # credential.  The no-bypass invariant is not
        # abandoned; it moves to the owner-verified column, discharged by the
        # standalone GET-only bypass command in docs/release-governance.md,
        # whose ruleset-write credential does return the property.  This
        # deletion is credential-independent, so no preflight run — CI's or the
        # owner's — reads the property (that document records which invariants
        # each side proves).
        expected = settings_receipt()
        credential_shape = settings_api()
        detail = credential_shape["repos/owner/site/rulesets/42"]
        self.assertNotIn("bypass_actors", detail)
        self.assertEqual(self.observe(copy.deepcopy(credential_shape)), expected)
        self.assertNotIn("bypass_actors", expected)
        RC.validate_settings_receipt(expected, "owner/site")

        # A write-access credential additionally returns the property, in any
        # shape.  The receipt must be byte-identical either way: no conditional
        # assertion, no credential-dependent branch, and no field the CI
        # credential cannot see may steer the outcome.
        for actors in (
            [],
            [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}],
            [{"actor_type": "OrganizationAdmin"}, {"actor_type": "DeployKey"}],
            "none",
            None,
            {},
        ):
            widened = copy.deepcopy(credential_shape)
            widened["repos/owner/site/rulesets/42"]["bypass_actors"] = actors
            with self.subTest(bypass_actors=actors):
                self.assertEqual(self.observe(widened), expected)

        # The receipt schema is closed and carries no bypass field at all, so a
        # dangling one is foreign and fails rather than being quietly tolerated.
        dangling = copy.deepcopy(expected)
        dangling["bypass_actors"] = []
        with self.assertRaises(RC.ContractError):
            RC.validate_settings_receipt(dangling, "owner/site")

        # rules[] parsing is now actually reachable under the CI-credential
        # shape: a rules-layer defect must deny for its own reason, never for
        # the bypass read that used to preempt it.
        for mutate, expected_error in (
            (lambda detail: detail.__setitem__("rules", None), "Protect-Main rules"),
            (
                lambda detail: detail["rules"].append({"type": "update"}),
                "Protect-Main rule types",
            ),
        ):
            changed = copy.deepcopy(credential_shape)
            mutate(changed["repos/owner/site/rulesets/42"])
            with self.subTest(rules_mutation=expected_error):
                with self.assertRaises(RC.ContractError) as caught:
                    self.observe(changed)
                self.assertIn(expected_error, str(caught.exception))
                self.assertNotIn("bypass", str(caught.exception))
        broken_merge = copy.deepcopy(credential_shape)
        pull = next(
            rule
            for rule in broken_merge["repos/owner/site/rulesets/42"]["rules"]
            if rule["type"] == "pull_request"
        )
        del pull["parameters"]["allowed_merge_methods"]
        with self.assertRaises(RC.ContractError) as caught:
            self.observe(broken_merge)
        self.assertNotIn("bypass", str(caught.exception))

    def test_github_settings_reader_is_get_only_and_fails_closed(self):
        completed = subprocess.CompletedProcess([], 0, stdout='{"enabled": true}', stderr="")
        with mock.patch.object(RC.subprocess, "run", return_value=completed) as run:
            self.assertEqual(RC._github_api_get("repos/owner/site/private-vulnerability-reporting"), {"enabled": True})
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", command)
        self.assertNotIn("POST", command)
        self.assertNotIn("PUT", command)
        self.assertNotIn("PATCH", command)
        self.assertNotIn("DELETE", command)
        pages = subprocess.CompletedProcess(
            [],
            0,
            stdout='[[{"id": 1}], [{"id": 2}]]',
            stderr="",
        )
        with mock.patch.object(RC.subprocess, "run", return_value=pages) as run:
            self.assertEqual(RC._github_api_get("repos/owner/site/rulesets", paginate=True), [{"id": 1}, {"id": 2}])
        paginated_command = run.call_args.args[0]
        self.assertIn("--paginate", paginated_command)
        self.assertIn("--slurp", paginated_command)
        for result in (
            subprocess.CompletedProcess([], 1, stdout="", stderr="denied"),
            subprocess.CompletedProcess([], 0, stdout="not-json", stderr=""),
        ):
            with mock.patch.object(RC.subprocess, "run", return_value=result), self.assertRaises(
                RC.ContractError
            ):
                RC._github_api_get("repos/owner/site/private-vulnerability-reporting")

    def test_immutable_settings_cli_and_private_reporting_kill_field_mutants(self):
        immutable = {"enabled": True, "enforced_by_owner": False}
        RC.validate_immutable_settings(immutable)
        for changed in (
            {"enabled": False, "enforced_by_owner": False},
            {"enabled": True, "enforced_by_owner": "false"},
            {"enabled": True},
            {**immutable, "foreign": True},
        ):
            with self.subTest(immutable=changed), self.assertRaises(RC.ContractError):
                RC.validate_immutable_settings(changed)
        private = {"enabled": True}
        RC.validate_private_vulnerability_reporting(private)
        for changed in ({"enabled": False}, {}, {"enabled": True, "foreign": True}):
            with self.subTest(private=changed), self.assertRaises(RC.ContractError):
                RC.validate_private_vulnerability_reporting(changed)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "immutable.json"
            path.write_text(json.dumps(immutable), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    RC.main(["immutable-settings", "--settings-json", str(path)]),
                    0,
                )
            self.assertEqual(output.getvalue().strip(), "exact")

    def test_settings_cli_and_runbook_are_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "settings.json"
            receipt.write_text(json.dumps(settings_receipt()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    RC.main(
                        [
                            "settings-receipt",
                            "--receipt",
                            str(receipt),
                            "--repository",
                            "owner/site",
                        ]
                    ),
                    0,
                )
            self.assertEqual(output.getvalue().strip(), "exact")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    RC.main(
                        [
                            "settings-receipt",
                            "--receipt",
                            str(receipt),
                            "--repository",
                            "other/site",
                        ]
                    ),
                    1,
                )

        runbook = (ROOT / "docs" / "release-governance.md").read_text(encoding="utf-8")
        self.require_documented_contract(runbook)
        for token in self.RUNBOOK_TOKENS:
            self.assertIn(token, runbook)
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                self.require_documented_contract(runbook.replace(token, ""))
        for old, new in self.RUNBOOK_INVERSIONS:
            self.assertIn(old, runbook)
            with self.subTest(inversion=old), self.assertRaises(ValueError):
                self.require_documented_contract(runbook.replace(old, new, 1))
        for forbidden in self.RUNBOOK_FORBIDDEN:
            with self.subTest(claim=forbidden), self.assertRaises(ValueError):
                self.require_documented_contract(runbook + "\n" + forbidden + "\n")


class NoReleaseAppCredentialTests(unittest.TestCase):
    """No workflow mints, reads or stores a GitHub App credential.

    The settings preflight runs under the settings job's own short-lived
    `github.token`; nothing else needs a credential beyond each job's
    `GITHUB_TOKEN`. An App token, its variable, its secret or the
    Administration grant it carried coming back anywhere under `.github/`
    would be a credential this repository does not have -- every run would
    deny -- or worse, one it should not have.
    """

    FORBIDDEN = (
        "create-github-app-token",
        "PLATFORM_RELEASE_APP",
        "IMMUTABLE_SETTINGS_TOKEN",
        "permission-administration",
        "immutable_settings",
        "app-id:",
        "private-key:",
    )

    @classmethod
    def require_no_app_credential(cls, documents: Mapping[str, str]) -> None:
        for name, text in documents.items():
            for forbidden in cls.FORBIDDEN:
                if forbidden in text:
                    raise ValueError(f"{name} names an App credential path: {forbidden}")
            if re.search(r"\$\{\{\s*vars\.", text):
                raise ValueError(f"{name} reads a repository or environment variable")
            for secret in re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)", text):
                if secret != "GITHUB_TOKEN":
                    raise ValueError(f"{name} reads the stored secret {secret}")

    def test_no_workflow_names_an_app_credential(self):
        documents = {
            path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted((ROOT / ".github").rglob("*"))
            if path.is_file()
        }
        self.assertIn(".github/workflows/release-publisher.yml", documents)
        self.require_no_app_credential(documents)
        publisher = documents[".github/workflows/release-publisher.yml"]
        for name, mutant in (
            ("App token step", publisher.replace(
                "      - name: Require authoritative release settings before side effects\n",
                "      - name: Mint\n        uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0\n"
                "      - name: Require authoritative release settings before side effects\n", 1)),
            ("App variable", publisher + "\n# ${{ vars.PLATFORM_RELEASE_APP_ID }}\n"),
            ("any variable", publisher.replace(
                "GH_TOKEN: ${{ github.token }}", "GH_TOKEN: ${{ vars.SETTINGS_TOKEN }}", 1)),
            ("stored secret", publisher.replace(
                "GH_TOKEN: ${{ github.token }}", "GH_TOKEN: ${{ secrets.SETTINGS_TOKEN }}", 1)),
            ("old job name", publisher.replace("repository_settings", "immutable_settings")),
        ):
            self.assertNotEqual(mutant, publisher, name)
            with self.subTest(mutant=name), self.assertRaises(ValueError):
                self.require_no_app_credential({**documents, ".github/workflows/release-publisher.yml": mutant})


class ArtifactStateTests(unittest.TestCase):
    def test_absent_complete_and_every_partial_state(self):
        self.assertEqual(RC.classify_artifact(present=False, source_match=False, signature_match=False, evidence_count=0, expected_evidence=2), "absent")
        self.assertEqual(RC.classify_artifact(present=True, source_match=True, signature_match=True, evidence_count=2, expected_evidence=2), "complete")
        # (True, False, 0) is the exact residue a gate-before-sign publisher
        # leaves when the HIGH/CRITICAL scan denies (issue #69): Buildx has
        # already pushed the alias, so the digest is present with matching
        # provenance and SBOMs, but nothing signed it and no attestation
        # exists. It must classify burned, which the resolver then refuses as
        # an unpublishable state -- the tag is consumed and needs an operator,
        # never a silent republish over a vulnerable digest.
        for source, signed, count in ((False, True, 2), (True, False, 2), (True, False, 0), (True, True, 0), (True, True, 1), (True, True, 3)):
            with self.subTest(source=source, signed=signed, count=count):
                self.assertEqual(RC.classify_artifact(present=True, source_match=source, signature_match=signed, evidence_count=count, expected_evidence=2), "burned")
        with self.assertRaises(RC.ContractError):
            RC.classify_artifact(present=False, source_match=True, signature_match=False, evidence_count=0, expected_evidence=2)

    def test_only_an_authoritative_404_means_absent(self):
        self.assertEqual(RC.classify_registry_response(200), "present")
        self.assertEqual(RC.classify_registry_response(404), "absent")
        for status in (0, 301, 401, 403, 408, 409, 429, 500, 502, 503, 504):
            with self.subTest(status=status), self.assertRaises(RC.ContractError):
                RC.classify_registry_response(status)


class ChartDigestEmbedTests(unittest.TestCase):
    """The substitution that makes the published chart deployable as published.

    Issue #111 / ADR 0016 step 1. `chart/values.yaml` ships an all-zeros
    fail-closed sentinel: a SYNTACTICALLY VALID digest -- it satisfies
    values.schema.json's `^sha256:[0-9a-f]{64}$` and the gate's rendered
    reference assertion -- that no registry can resolve. The publisher
    substitutes the resolved digest on the runner and never commits it, so
    both halves need proving: a real digest reaches the published artifact,
    and the sentinel cannot survive into one.

    Every literal below is written out here rather than read from RC, so a
    mutated module constant turns these red instead of moving with them.
    """

    VALUES = ROOT / "chart" / "values.yaml"
    SENTINEL = "sha256:" + "0" * 64
    RESOLVED = "sha256:" + "ab" * 32
    OTHER = "sha256:" + "cd" * 32

    def committed(self) -> str:
        return self.VALUES.read_text(encoding="utf-8")

    @staticmethod
    def invoke(*arguments: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = RC.main(list(arguments))
        return code, out.getvalue(), err.getvalue()

    def test_the_committed_chart_still_carries_the_fail_closed_sentinel(self):
        # Acceptance 4: the SOURCE tree never gains a real digest. If this
        # ever fails, a release has leaked its digest into reviewed history
        # and the publisher's substitution has nothing left to replace.
        self.assertIn("\n  digest: " + self.SENTINEL + "\n", self.committed())

    def test_substitution_moves_exactly_the_one_digest_line(self):
        values = self.committed()
        embedded = RC.embed_chart_image_digest(values, self.RESOLVED)
        self.assertNotIn(self.SENTINEL, embedded)
        self.assertIn("\n  digest: " + self.RESOLVED + "\n", embedded)
        before, after = values.split("\n"), embedded.split("\n")
        self.assertEqual(len(before), len(after))
        moved = [index for index, (old, new) in enumerate(zip(before, after)) if old != new]
        self.assertEqual(len(moved), 1)
        self.assertEqual(before[moved[0]], "  digest: " + self.SENTINEL)
        # Acceptance 3: the four-way release lock keeps its current meaning.
        # `image.tag` is the lock's fourth leg, and a substitution that
        # disturbed it would publish a chart claiming another release.
        self.assertIn("\n  tag: v", embedded)
        self.assertEqual(
            [line for line in before if line.startswith("  tag: ")],
            [line for line in after if line.startswith("  tag: ")],
        )

    def test_a_malformed_or_sentinel_digest_can_never_be_embedded_or_asserted(self):
        values = self.committed()
        substituted = values.replace(self.SENTINEL, self.RESOLVED)
        for name, digest in (
            ("63 hex characters", "sha256:" + "ab" * 31 + "a"),
            ("65 hex characters", "sha256:" + "ab" * 32 + "a"),
            ("no sha256: prefix", "ab" * 32),
            ("another algorithm", "sha512:" + "ab" * 32),
            ("upper-case hex", "sha256:" + "AB" * 32),
            ("non-hex characters", "sha256:" + "zz" * 32),
            ("leading whitespace", " sha256:" + "ab" * 32),
            ("empty", ""),
        ):
            with self.subTest(digest=name):
                with self.assertRaises(RC.ContractError):
                    RC.embed_chart_image_digest(values, digest)
                with self.assertRaises(RC.ContractError):
                    RC.assert_chart_image_digest(substituted, digest)
        # The sentinel is well formed and still unpullable: the one value the
        # format check alone cannot refuse, and the exact bug being closed.
        # Its refusal is pinned by MESSAGE, not merely by raising. Both calls
        # would still fail without the sentinel guard -- the whole-file scan
        # and the equality compare catch them downstream -- but they would
        # blame the CHART for a bad IMAGE digest, sending whoever reads the
        # red build to the wrong file. A guard nothing can observe is
        # decorative; this pins the observation.
        refusal = "fail-closed sentinel, not a resolved digest"
        with self.assertRaisesRegex(RC.ContractError, refusal):
            RC.embed_chart_image_digest(values, self.SENTINEL)
        with self.assertRaisesRegex(RC.ContractError, refusal):
            RC.assert_chart_image_digest(substituted, self.SENTINEL)

    def test_the_assertion_fails_both_directions(self):
        values = self.committed()
        embedded = RC.embed_chart_image_digest(values, self.RESOLVED)
        # Acceptance 6, direction one: a real digest passes.
        RC.assert_chart_image_digest(embedded, self.RESOLVED)
        # Direction two: the sentinel that survived packaging fails.
        with self.assertRaises(RC.ContractError):
            RC.assert_chart_image_digest(values, self.RESOLVED)
        # ...and so does a chart carrying SOME OTHER real digest, so the
        # assertion binds the exact scanned, signed digest rather than
        # merely observing that the sentinel is gone.
        with self.assertRaises(RC.ContractError):
            RC.assert_chart_image_digest(embedded, self.OTHER)
        # The sentinel is refused wherever it appears, including a comment a
        # packaged chart could carry outside the digest line itself.
        with self.assertRaises(RC.ContractError):
            RC.assert_chart_image_digest(embedded + f"\n# leftover {self.SENTINEL}\n", self.RESOLVED)

    def test_a_values_file_that_lost_the_sentinel_is_never_rewritten(self):
        # Either committed source drift or a second substitution over an
        # already substituted tree. Both are fail-closed: a publisher that
        # rewrote whatever it found could overwrite a correct digest with a
        # stale one and never say so.
        embedded = RC.embed_chart_image_digest(self.committed(), self.RESOLVED)
        with self.assertRaises(RC.ContractError):
            RC.embed_chart_image_digest(embedded, self.OTHER)
        with self.assertRaises(RC.ContractError):
            RC.embed_chart_image_digest(self.committed().replace("  digest: ", "  digest:", 1), self.RESOLVED)
        # The sharp case, and the reason the pre-check is not redundant with
        # the one-substitution count below it: `image.digest` ALREADY holds
        # the expected digest while some other two-space block carries the
        # sentinel. Without the pre-check the substitution rewrites that other
        # line, the post-substitution assertion sees a sentinel-free file
        # whose image.digest is exactly what was asked for, and a document
        # nobody intended to touch is silently rewritten.
        decoy = embedded + "\ndecoy:\n  digest: " + self.SENTINEL + "\n"
        with self.assertRaisesRegex(RC.ContractError, "must carry the"):
            RC.embed_chart_image_digest(decoy, self.RESOLVED)

    def test_the_subcommands_write_and_verify_a_real_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = Path(temporary) / "values.yaml"
            values.write_text(self.committed(), encoding="utf-8")
            unchanged = values.read_text(encoding="utf-8")

            code, _out, err = self.invoke("chart-digest-assert", "--values", str(values), "--digest", self.RESOLVED)
            self.assertEqual(code, 1)
            self.assertIn("DENY:", err)
            self.assertEqual(values.read_text(encoding="utf-8"), unchanged)

            code, _out, err = self.invoke("chart-digest-embed", "--values", str(values), "--digest", self.SENTINEL)
            self.assertEqual(code, 1)
            self.assertEqual(values.read_text(encoding="utf-8"), unchanged)

            code, out, _err = self.invoke("chart-digest-embed", "--values", str(values), "--digest", self.RESOLVED)
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), "embedded")
            self.assertIn("\n  digest: " + self.RESOLVED + "\n", values.read_text(encoding="utf-8"))

            code, out, _err = self.invoke("chart-digest-assert", "--values", str(values), "--digest", self.RESOLVED)
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), "exact")

            code, _out, _err = self.invoke("chart-digest-assert", "--values", str(values), "--digest", self.OTHER)
            self.assertEqual(code, 1)
            code, _out, _err = self.invoke("chart-digest-embed", "--values", str(values), "--digest", self.OTHER)
            self.assertEqual(code, 1)
            self.assertIn("\n  digest: " + self.RESOLVED + "\n", values.read_text(encoding="utf-8"))


class PublisherBindingTests(unittest.TestCase):
    SHA = "a" * 40

    def test_source_sha_ref_event_and_snapshot_checks_are_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, contents in snapshot("0.1.10").items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            workflow_ref = (
                f"{RC.EXPECTED_REPOSITORY}/.github/workflows/"
                "release-publisher.yml@refs/heads/main"
            )
            intent = RC.validate_publisher(
                root,
                self.SHA,
                self.SHA,
                "refs/heads/main",
                "workflow_dispatch",
                RC.EXPECTED_REPOSITORY,
                workflow_ref,
                RC.EXPECTED_IMAGE,
                RC.EXPECTED_CHART,
            )
            self.assertEqual(intent, RC.ReleaseIntent(self.SHA, RC.Version.parse("0.1.10")))
            valid = (
                self.SHA,
                self.SHA,
                "refs/heads/main",
                "workflow_dispatch",
                RC.EXPECTED_REPOSITORY,
                workflow_ref,
                RC.EXPECTED_IMAGE,
                RC.EXPECTED_CHART,
            )
            mutants = (
                ("b" * 40, *valid[1:]),
                (valid[0], "b" * 40, *valid[2:]),
                (*valid[:2], "refs/tags/v0.1.10", *valid[3:]),
                (*valid[:3], "push", *valid[4:]),
                (*valid[:4], "other/site", *valid[5:]),
                (
                    self.SHA,
                    self.SHA,
                    "refs/heads/main",
                    "workflow_dispatch",
                    RC.EXPECTED_REPOSITORY,
                    f"{RC.EXPECTED_REPOSITORY}/.github/workflows/"
                    "release-publisher.yml@refs/tags/v0.1.10",
                    RC.EXPECTED_IMAGE,
                    RC.EXPECTED_CHART,
                ),
                (*valid[:6], "ghcr.io/snaraj/hospedajedonlolo.com", valid[7]),
                (*valid[:7], "ghcr.io/snaraj/charts/hospedajedonlolo.com"),
            )
            for source, checkout, ref, event_name, repository, selected_workflow, image, chart in mutants:
                with self.subTest(
                    source=source,
                    checkout=checkout,
                    ref=ref,
                    event=event_name,
                    repository=repository,
                    workflow=selected_workflow,
                    image=image,
                    chart=chart,
                ), self.assertRaises(RC.ContractError):
                    RC.validate_publisher(
                        root,
                        source,
                        checkout,
                        ref,
                        event_name,
                        repository,
                        selected_workflow,
                        image,
                        chart,
                    )

    def test_real_dotted_repository_maps_only_to_explicit_hyphenated_packages(self):
        RC.validate_release_destinations(
            "snaraj/hospedajedonlolo.com",
            "ghcr.io/snaraj/hospedajedonlolo-com",
            "ghcr.io/snaraj/charts/hospedajedonlolo-com",
        )
        for repository, image, chart in (
            (
                "snaraj/hospedajedonlolo.com",
                "ghcr.io/snaraj/hospedajedonlolo.com",
                RC.EXPECTED_CHART,
            ),
            (
                "snaraj/hospedajedonlolo.com",
                RC.EXPECTED_IMAGE,
                "ghcr.io/snaraj/charts/hospedajedonlolo.com",
            ),
            ("snaraj/hospedajedonlolo-com", RC.EXPECTED_IMAGE, RC.EXPECTED_CHART),
        ):
            with self.subTest(repository=repository, image=image, chart=chart), self.assertRaises(
                RC.ContractError
            ):
                RC.validate_release_destinations(repository, image, chart)


class ImmutableMetadataTests(unittest.TestCase):
    TAG = "v0.1.10"
    SOURCE = "a" * 40
    MESSAGE = f"Release {TAG} from {SOURCE}"
    DATE = "2026-08-13T15:21:32Z"

    def test_annotated_tag_type_target_message_and_tagger_are_exact(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        RC.validate_tag_record(
            ref,
            tag,
            tag=self.TAG,
            source_sha=self.SOURCE,
            message=self.MESSAGE,
            tagger_name="github-actions[bot]",
            tagger_email="41898282+github-actions[bot]@users.noreply.github.com",
            tagger_date="2026-08-13T08:21:32-07:00",
        )
        mutations: list[tuple[dict[str, object], dict[str, object]]] = []
        for target, path, value in (
            ("ref", ("ref",), "refs/tags/v0.1.11"),
            ("ref", ("object", "type"), "commit"),
            ("ref", ("object", "sha"), "c" * 40),
            ("tag", ("tag",), "v0.1.11"),
            ("tag", ("message",), self.MESSAGE + " foreign"),
            ("tag", ("object", "type"), "tree"),
            ("tag", ("object", "sha"), "d" * 40),
            ("tag", ("tagger", "name"), "snaraj"),
            ("tag", ("tagger", "email"), "foreign@example.invalid"),
            ("tag", ("tagger", "date"), "2026-08-13T15:21:33Z"),
        ):
            changed_ref, changed_tag = copy.deepcopy(ref), copy.deepcopy(tag)
            changed = changed_ref if target == "ref" else changed_tag
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append((changed_ref, changed_tag))
        for index, (changed_ref, changed_tag) in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.validate_tag_record(
                    changed_ref,
                    changed_tag,
                    tag=self.TAG,
                    source_sha=self.SOURCE,
                    message=self.MESSAGE,
                    tagger_name="github-actions[bot]",
                    tagger_email="41898282+github-actions[bot]@users.noreply.github.com",
                    tagger_date=self.DATE,
                )

    def test_release_metadata_and_one_manifest_asset_are_exact(self):
        manifest = canonical_manifest_bytes(exact_release_manifest(source=self.SOURCE))
        exact = exact_release_record(manifest, tag=self.TAG)
        RC.validate_release_record(
            exact,
            tag=self.TAG,
            title=f"hospedajedonlolo.com {self.TAG}",
            body="exact notes",
            manifest=manifest,
        )
        prepared = exact_release_record(manifest, tag=self.TAG, state="prepared")
        RC.validate_release_record(
            prepared,
            tag=self.TAG,
            title=f"hospedajedonlolo.com {self.TAG}",
            body="exact notes",
            manifest=manifest,
            state="prepared",
        )
        actor_mutants = (
            None,
            {},
            {"login": RC.GITHUB_ACTIONS_BOT_LOGIN},
            {"id": RC.GITHUB_ACTIONS_BOT_ID},
            {"login": "foreign-writer", "id": RC.GITHUB_ACTIONS_BOT_ID},
            {"login": RC.GITHUB_ACTIONS_BOT_LOGIN, "id": 1},
            {"login": RC.GITHUB_ACTIONS_BOT_LOGIN, "id": True},
            {"login": RC.GITHUB_ACTIONS_BOT_LOGIN, "id": float(RC.GITHUB_ACTIONS_BOT_ID)},
        )
        for state in ("prepared", "staged", "exact"):
            for actor in actor_mutants:
                changed = exact_release_record(manifest, tag=self.TAG, state=state)
                changed["author"] = actor
                with self.subTest(state=state, release_author=actor), self.assertRaises(
                    RC.ContractError
                ):
                    RC.validate_release_record(
                        changed,
                        tag=self.TAG,
                        title=f"hospedajedonlolo.com {self.TAG}",
                        body="exact notes",
                        manifest=manifest,
                        state=state,
                    )
        for state in ("staged", "exact"):
            for uploader in actor_mutants:
                changed = exact_release_record(manifest, tag=self.TAG, state=state)
                changed["assets"][0]["uploader"] = uploader
                with self.subTest(state=state, asset_uploader=uploader), self.assertRaises(
                    RC.ContractError
                ):
                    RC.validate_release_record(
                        changed,
                        tag=self.TAG,
                        title=f"hospedajedonlolo.com {self.TAG}",
                        body="exact notes",
                        manifest=manifest,
                        state=state,
                    )
        for key, value in (
            ("tag_name", "v0.1.11"),
            ("name", "foreign"),
            ("body", "foreign"),
            ("body", None),
            ("draft", True),
            ("prerelease", True),
            ("immutable", False),
            ("immutable", None),
            ("assets", []),
            ("assets", [exact["assets"][0], {"name": "foreign.bin"}]),
            ("assets", None),
        ):
            changed = copy.deepcopy(exact)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RC.ContractError):
                RC.validate_release_record(
                    changed,
                    tag=self.TAG,
                    title=f"hospedajedonlolo.com {self.TAG}",
                    body="exact notes",
                    manifest=manifest,
                )
        for field, value in (
            ("name", "foreign.json"),
            ("content_type", "application/octet-stream"),
            ("state", "new"),
            ("size", len(manifest) + 1),
            ("digest", "sha256:" + "0" * 64),
        ):
            changed = copy.deepcopy(exact)
            changed["assets"][0][field] = value
            with self.subTest(asset_field=field), self.assertRaises(RC.ContractError):
                RC.validate_release_record(
                    changed,
                    tag=self.TAG,
                    title=f"hospedajedonlolo.com {self.TAG}",
                    body="exact notes",
                    manifest=manifest,
                )
        with self.assertRaises(RC.ContractError):
            RC.validate_release_record(
                exact,
                tag=self.TAG,
                title=f"hospedajedonlolo.com {self.TAG}",
                body="exact notes",
                manifest=manifest + b" ",
            )

    def test_manifest_binds_source_run_artifacts_scans_and_notes_exactly(self):
        exact = exact_release_manifest(source=self.SOURCE)
        expected = {
            "repository": RC.EXPECTED_REPOSITORY,
            "source_sha": self.SOURCE,
            "main_run_id": 123,
            "version": "0.1.10",
            "image": RC.EXPECTED_IMAGE,
            "image_digest": "sha256:" + "c" * 64,
            "chart": RC.EXPECTED_CHART,
            "chart_digest": "sha256:" + "d" * 64,
        }
        RC.validate_release_manifest_record(exact, **expected)
        notes = RC.build_release_notes(exact)
        self.assertIn("hospedajedonlolo-com-v0.1.10-release-manifest.json", notes)
        self.assertIn("sha256:" + hashlib.sha256(canonical_manifest_bytes(exact)).hexdigest(), notes)
        mutations = (
            (("schema",), "foreign"),
            (("source_sha",), "b" * 40),
            (("main_run_id",), 124),
            (("release", "version"), "0.1.11"),
            (("release", "tag"), "v0.1.11"),
            (("publisher", "workflow"), ".github/workflows/foreign.yml"),
            (("publisher", "ref"), "refs/tags/v0.1.10"),
            (("artifacts", "image", "digest"), "sha256:" + "e" * 64),
            (("artifacts", "image", "tag"), "0.1.10"),
            (("artifacts", "image", "platforms"), ["linux/amd64"]),
            (("artifacts", "image", "signature_identity"), "foreign"),
            (("artifacts", "image", "provenance"), "none"),
            (("artifacts", "chart", "digest"), "sha256:" + "e" * 64),
            (("artifacts", "chart", "tag"), "v0.1.10"),
            (("vulnerability_scans", "source", "scanner_version"), "latest"),
            (("vulnerability_scans", "source", "main_run_id"), 124),
            (("vulnerability_scans", "source", "result"), "unknown"),
            (("vulnerability_scans", "image", "target"), "foreign"),
            (("vulnerability_scans", "image", "severities"), ["CRITICAL"]),
            (("vulnerability_scans", "image", "ignore_unfixed"), True),
        )
        for path, value in mutations:
            changed = copy.deepcopy(exact)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(RC.ContractError):
                RC.validate_release_manifest_record(changed, **expected)
        changed = copy.deepcopy(exact)
        changed["foreign"] = True
        with self.assertRaises(RC.ContractError):
            RC.validate_release_manifest_record(changed, **expected)


class PublicationTransactionTests(unittest.TestCase):
    TAG = "v0.1.10"
    SOURCE = "a" * 40
    MESSAGE = f"Release {TAG} from {SOURCE}"
    DATE = "2026-08-13T15:21:32Z"

    def tag_expected(self) -> dict[str, str]:
        return {
            "tag": self.TAG,
            "source_sha": self.SOURCE,
            "message": self.MESSAGE,
            "tagger_name": "github-actions[bot]",
            "tagger_email": "41898282+github-actions[bot]@users.noreply.github.com",
            "tagger_date": self.DATE,
        }

    def manifest(self) -> bytes:
        return canonical_manifest_bytes(exact_release_manifest(source=self.SOURCE))

    def release(self, state: str = "exact") -> dict[str, object]:
        return exact_release_record(self.manifest(), tag=self.TAG, state=state)

    def test_absent_create_verify_and_concurrent_retry_need_no_local_tag_ref(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        # Both racers can observe absence. The winner creates the exact REST
        # records; the loser re-queries those records after its create fails.
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(404, None, None, **self.tag_expected()), "absent")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")
        self.assertEqual(RC.classify_tag_state(200, ref, tag, **self.tag_expected()), "exact")

        manifest = self.manifest()
        prepared_release = self.release("prepared")
        staged_release = self.release("staged")
        expected_release = self.release()
        for _racer in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    404,
                    None,
                    tag=self.TAG,
                    title=f"hospedajedonlolo.com {self.TAG}",
                    body="exact notes",
                    manifest=manifest,
                ),
                "absent",
            )
        self.assertEqual(
            RC.classify_release_state(
                200,
                prepared_release,
                tag=self.TAG,
                title=f"hospedajedonlolo.com {self.TAG}",
                body="exact notes",
                manifest=manifest,
            ),
            "prepared",
        )
        self.assertEqual(
            RC.classify_release_state(
                200,
                staged_release,
                tag=self.TAG,
                title=f"hospedajedonlolo.com {self.TAG}",
                body="exact notes",
                manifest=manifest,
            ),
            "staged",
        )
        for _retry in range(2):
            self.assertEqual(
                RC.classify_release_state(
                    200,
                    expected_release,
                    tag=self.TAG,
                    title=f"hospedajedonlolo.com {self.TAG}",
                    body="exact notes",
                    manifest=manifest,
                ),
                "exact",
            )

    def test_missing_records_conflicts_and_non_authoritative_absence_fail_closed(self):
        ref, tag = exact_tag_records(self.TAG, self.SOURCE, self.MESSAGE, self.DATE)
        for status in (0, 301, 401, 403, 409, 422, 429, 500, 503):
            with self.subTest(kind="tag-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_tag_state(status, None, None, **self.tag_expected())
            with self.subTest(kind="release-status", status=status), self.assertRaises(RC.ContractError):
                RC.classify_release_state(
                    status,
                    None,
                    tag=self.TAG,
                    title=f"hospedajedonlolo.com {self.TAG}",
                    body="exact notes",
                    manifest=self.manifest(),
                )
        for changed_ref, changed_tag in ((None, tag), (ref, None)):
            with self.assertRaises(RC.ContractError):
                RC.classify_tag_state(200, changed_ref, changed_tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_tag_state(404, ref, tag, **self.tag_expected())
        with self.assertRaises(RC.ContractError):
            RC.classify_release_state(
                404,
                self.release(),
                tag=self.TAG,
                title=f"hospedajedonlolo.com {self.TAG}",
                body="exact notes",
                manifest=self.manifest(),
            )

    def test_exact_shell_state_assertions_kill_deletion_and_inversion_mutants(self):
        for state in ("absent", "prepared", "staged", "exact"):
            self.assertEqual(RC.require_publication_state(state, state), state)
        for actual, required in (
            ("absent", "staged"),
            ("prepared", "staged"),
            ("staged", "exact"),
            ("exact", "absent"),
            ("foreign", "exact"),
        ):
            with self.subTest(actual=actual, required=required), self.assertRaises(RC.ContractError):
                RC.require_publication_state(actual, required)

    def test_cli_require_flag_is_load_bearing_for_tag_and_release_transactions(self):
        def invoke(arguments: list[str]) -> int:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return RC.main(arguments)

        tag_args = [
            "tag-state",
            "--http-status",
            "404",
            "--tag",
            self.TAG,
            "--source-sha",
            self.SOURCE,
            "--message",
            self.MESSAGE,
            "--tagger-name",
            "github-actions[bot]",
            "--tagger-email",
            "41898282+github-actions[bot]@users.noreply.github.com",
            "--tagger-date",
            self.DATE,
        ]
        self.assertEqual(invoke([*tag_args, "--require", "absent"]), 0)
        self.assertEqual(invoke([*tag_args, "--require", "exact"]), 1)

        with tempfile.TemporaryDirectory() as temporary:
            notes = Path(temporary) / "notes.md"
            notes.write_text("exact notes\n", encoding="utf-8")
            manifest = Path(temporary) / "manifest.json"
            manifest.write_bytes(self.manifest())
            release_args = [
                "release-state",
                "--http-status",
                "404",
                "--tag",
                self.TAG,
                "--title",
                f"hospedajedonlolo.com {self.TAG}",
                "--body",
                str(notes),
                "--manifest",
                str(manifest),
            ]
            self.assertEqual(invoke([*release_args, "--require", "absent"]), 0)
            self.assertEqual(invoke([*release_args, "--require", "exact"]), 1)


class AttestationSetTests(unittest.TestCase):
    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "d" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "a" * 40
    PLATFORMS = ("linux/amd64", "linux/arm64")

    def expected(self) -> dict[str, dict[str, object]]:
        return {
            platform: RC.build_attestation_statement(
                embedded_predicate(self.SOURCE, self.REVISION, platform),
                image=self.IMAGE,
                digest=self.DIGEST,
                source=self.SOURCE,
                revision=self.REVISION,
                platform=platform,
                builder_run_id=BUILDER_RUN_ID,
            )
            for platform in self.PLATFORMS
        }

    def encode(self, statements) -> str:
        return "\n".join(json.dumps(verified_record(statement)) for statement in statements)

    def test_exact_authenticated_subject_predicate_and_platform_set(self):
        expected = self.expected()
        self.assertEqual(RC.validate_attestation_set(self.encode(expected.values()), expected), 2)

    def test_authentic_plus_foreign_missing_duplicate_and_inverted_bindings_fail(self):
        expected = self.expected()
        amd = expected["linux/amd64"]
        foreign = copy.deepcopy(expected["linux/arm64"])
        foreign["predicate"]["buildDefinition"]["internalParameters"]["release"]["source"] = "https://github.com/attacker/site"
        wrong_subject = copy.deepcopy(expected["linux/arm64"])
        wrong_subject["subject"][0]["digest"]["sha256"] = "e" * 64
        wrong_type = copy.deepcopy(expected["linux/arm64"])
        wrong_type["predicateType"] = "https://example.invalid/foreign"
        for statements in (
            [amd],
            [amd, amd],
            [amd, foreign],
            [amd, wrong_subject],
            [amd, wrong_type],
            [*expected.values(), foreign],
        ):
            with self.subTest(count=len(statements)), self.assertRaises(RC.ContractError):
                RC.validate_attestation_set(self.encode(statements), expected)

    def test_embedded_source_revision_builder_and_reserved_binding_mutants_fail(self):
        base = embedded_predicate(self.SOURCE, self.REVISION, "linux/amd64")
        mutations = []
        for path, value in (
            (("runDetails", "builder", "id"), "https://github.com/attacker/site/actions/runs/1"),
            (("runDetails", "metadata", "buildkit_metadata", "vcs", "source"), "https://github.com/attacker/site"),
            (("runDetails", "metadata", "buildkit_metadata", "vcs", "revision"), "b" * 40),
            (("buildDefinition", "internalParameters", "release"), {"platform": "linux/amd64"}),
        ):
            changed = copy.deepcopy(base)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            mutations.append(changed)
        for index, predicate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RC.ContractError):
                RC.build_attestation_statement(
                    predicate,
                    image=self.IMAGE,
                    digest=self.DIGEST,
                    source=self.SOURCE,
                    revision=self.REVISION,
                    platform="linux/amd64",
                    builder_run_id=BUILDER_RUN_ID,
                )


class AttestationBuilderRunBindingTests(unittest.TestCase):
    """Issue #137: the SLSA builder identity must name ONE authoritative run.

    The shipped check was
    `builder["id"].startswith(source + "/actions/runs/")`, which every run of
    every workflow in this repository satisfies forever -- the digits after
    the prefix were never read. Every neighbouring identity in the same
    function is bound exactly (digest full-matched, revision through
    require_sha, platform re.fullmatch-ed, vcs compared with !=), so the
    builder was the one loose outlier.

    Restoring that prefix match turns
    test_a_different_run_in_this_repository_denies and
    test_a_longer_run_id_sharing_the_leading_digits_denies red; replacing the
    anchored full match with `startswith(expected)` still leaves the second
    of those red, and dropping the `/attempts/<n>` pattern in favour of
    ignoring everything after the run ID turns
    test_unexpected_suffixes_after_the_exact_run_deny red.
    """

    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "b" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "a" * 40
    PLATFORM = "linux/amd64"
    # Shape measured in this repository's own published provenance: every
    # release from v0.1.2 to v0.1.32 carries
    # `https://github.com/snaraj/hospedajedonlolo.com/actions/runs/<id>/attempts/1`,
    # and that <id> is the release-publisher run that ran `docker buildx
    # build`, not the PR-gate run the manifest records as `main_run_id`.
    RUN_ID = "32697375411"

    def build(self, builder_id: object, *, builder_run_id: object = RUN_ID) -> dict[str, object]:
        return RC.build_attestation_statement(
            embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM, builder_id),
            image=self.IMAGE,
            digest=self.DIGEST,
            source=self.SOURCE,
            revision=self.REVISION,
            platform=self.PLATFORM,
            builder_run_id=builder_run_id,
        )

    def test_the_exact_run_is_accepted_bare_and_with_the_measured_attempt_suffix(self):
        for builder_id in (
            f"{self.SOURCE}/actions/runs/{self.RUN_ID}",
            f"{self.SOURCE}/actions/runs/{self.RUN_ID}/attempts/1",
            f"{self.SOURCE}/actions/runs/{self.RUN_ID}/attempts/2",
            f"{self.SOURCE}/actions/runs/{self.RUN_ID}/attempts/17",
        ):
            with self.subTest(builder_id=builder_id):
                statement = self.build(builder_id)
                # Accepted AND carried through unchanged: the binding reads the
                # builder identity, it never rewrites it into something the
                # signed predicate would not contain.
                self.assertEqual(
                    statement["predicate"]["runDetails"]["builder"]["id"], builder_id
                )

    def test_a_different_run_in_this_repository_denies(self):
        # The mutant that survived the prefix match: same repository, same
        # workflow family, wrong run.
        for other in ("32697375412", "1", "9" * 20):
            with self.subTest(other=other), self.assertRaises(RC.ContractError):
                self.build(f"{self.SOURCE}/actions/runs/{other}")

    def test_a_longer_run_id_sharing_the_leading_digits_denies(self):
        # Kills a half-fix that anchors only the left side with
        # startswith(f"{source}/actions/runs/{run_id}").
        for suffix in ("9", "0", "12"):
            with self.subTest(suffix=suffix), self.assertRaises(RC.ContractError):
                self.build(f"{self.SOURCE}/actions/runs/{self.RUN_ID}{suffix}")

    def test_a_truncated_run_id_denies(self):
        with self.assertRaises(RC.ContractError):
            self.build(f"{self.SOURCE}/actions/runs/{self.RUN_ID[:-1]}")

    def test_the_same_run_id_in_a_foreign_repository_denies(self):
        for foreign in (
            "https://github.com/attacker/site",
            "https://github.com/owner/site-mirror",
            "https://github.com/owner",
        ):
            with self.subTest(foreign=foreign), self.assertRaises(RC.ContractError):
                self.build(f"{foreign}/actions/runs/{self.RUN_ID}")

    def test_unexpected_suffixes_after_the_exact_run_deny(self):
        base = f"{self.SOURCE}/actions/runs/{self.RUN_ID}"
        for suffix in (
            "/",
            "/attempts",
            "/attempts/",
            "/attempts/0",
            "/attempts/01",
            "/attempts/-1",
            "/attempts/1.0",
            "/attempts/one",
            "/attempts/1/",
            "/attempts/1/jobs/2",
            "/attempts/1 ",
            "/ATTEMPTS/1",
            "/jobs/5",
            "?attempt=1",
            "#attempts/1",
            " ",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(RC.ContractError):
                self.build(base + suffix)

    def test_a_prefixed_or_non_string_builder_identity_denies(self):
        exact = f"{self.SOURCE}/actions/runs/{self.RUN_ID}"
        for builder_id in (
            None,
            123,
            ["", exact],
            {"url": exact},
            " " + exact,
            "\n" + exact,
            exact + "\n",
            f"https://evil.invalid/?u={exact}",
        ):
            with self.subTest(builder_id=builder_id), self.assertRaises(RC.ContractError):
                self.build(builder_id)

    def test_a_malformed_builder_run_id_argument_denies(self):
        exact = f"{self.SOURCE}/actions/runs/{self.RUN_ID}"
        for argument in (
            "",
            "0",
            "0123",
            "abc",
            "123abc",
            " 123",
            "123 ",
            "+123",
            "-123",
            "1_2",
            "1e3",
            "12.0",
            "١٢٣",
            "123\n",
            None,
            123,
            True,
        ):
            with self.subTest(argument=argument), self.assertRaises(RC.ContractError):
                self.build(exact, builder_run_id=argument)

    def test_a_run_id_argument_carrying_path_separators_denies(self):
        # The shape check on the ARGUMENT is load-bearing, not cosmetic:
        # without it this composite is escaped straight into the expected
        # string and matches the predicate exactly, so a caller could bind the
        # builder identity to any path it liked instead of to one run.
        composite = f"{self.RUN_ID}/attempts/1"
        with self.assertRaises(RC.ContractError):
            self.build(
                f"{self.SOURCE}/actions/runs/{composite}", builder_run_id=composite
            )

    def test_both_denials_name_the_builder_binding(self):
        exact = f"{self.SOURCE}/actions/runs/{self.RUN_ID}"
        with self.assertRaises(RC.ContractError) as wrong_run:
            self.build(f"{self.SOURCE}/actions/runs/32697375412")
        with self.assertRaises(RC.ContractError) as wrong_argument:
            self.build(exact, builder_run_id="not-a-run")
        self.assertIn("builder", str(wrong_run.exception))
        self.assertIn("exact Actions run", str(wrong_run.exception))
        self.assertIn("builder run ID", str(wrong_argument.exception))

    def test_the_run_identity_is_required_by_signature(self):
        # A caller that forgets the binding must fail loudly rather than fall
        # back to a repository-wide prefix match.
        with self.assertRaises(TypeError):
            RC.build_attestation_statement(
                embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM),
                image=self.IMAGE,
                digest=self.DIGEST,
                source=self.SOURCE,
                revision=self.REVISION,
                platform=self.PLATFORM,
            )


class AttestationStatementCLITests(unittest.TestCase):
    """CLI-level oracles for the `attestation-statement` subcommand.

    AttestationSetTests above builds its expectations with
    RC.build_attestation_statement and then re-wraps those SAME objects as
    the "verified" cosign records, so `_type` is only ever compared against
    itself and no input can turn that comparison red. These tests instead
    drive the real subcommand end to end through RC.main and pin the
    on-disk contract against literals independent of the module under
    test, so a reverted INTOTO_STATEMENT_TYPE, a --predicate-output that
    writes the wrong object, an optional --predicate-output, or a deleted
    write each turn a specific test here red.
    """

    IMAGE = "ghcr.io/owner/site"
    DIGEST = "sha256:" + "f" * 64
    SOURCE = "https://github.com/owner/site"
    REVISION = "c" * 40
    PLATFORM = "linux/amd64"

    def invoke(
        self,
        temporary: str,
        *,
        include_predicate_output: bool = True,
        include_builder_run_id: bool = True,
        builder_run_id: str = BUILDER_RUN_ID,
    ) -> tuple[int, Path, Path]:
        predicate_path = Path(temporary) / "predicate.json"
        predicate_path.write_text(
            json.dumps(embedded_predicate(self.SOURCE, self.REVISION, self.PLATFORM)),
            encoding="utf-8",
        )
        output_path = Path(temporary) / "statement.json"
        predicate_output_path = Path(temporary) / "modified-predicate.json"
        arguments = [
            "attestation-statement",
            "--predicate", str(predicate_path),
            "--output", str(output_path),
        ]
        if include_predicate_output:
            arguments += ["--predicate-output", str(predicate_output_path)]
        if include_builder_run_id:
            arguments += ["--builder-run-id", builder_run_id]
        arguments += [
            "--image", self.IMAGE,
            "--digest", self.DIGEST,
            "--source", self.SOURCE,
            "--revision", self.REVISION,
            "--platform", self.PLATFORM,
        ]
        self.stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(self.stderr):
            code = RC.main(arguments)
        return code, output_path, predicate_output_path

    def test_statement_type_literal_is_the_pinned_in_toto_v01_uri(self):
        # Hardcoded here rather than read from RC.INTOTO_STATEMENT_TYPE: a
        # mutant that reverts the module constant back to the broken
        # https://in-toto.io/Statement/v1 -- the exact value that shipped
        # and burned v0.1.15 -- must turn THIS literal comparison red.
        # Comparing against the module's own constant would be
        # self-referential and vacuous, exactly AttestationSetTests' gap.
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, _ = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v0.1")

    def test_predicate_output_file_is_exactly_and_only_the_statement_predicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, predicate_output_path = self.invoke(temporary)
            self.assertEqual(code, 0)
            statement = json.loads(output_path.read_text(encoding="utf-8"))
            modified_predicate = json.loads(predicate_output_path.read_text(encoding="utf-8"))
        # Exactly the predicate member -- kills a mutant that writes some
        # other object to --predicate-output.
        self.assertEqual(modified_predicate, statement["predicate"])
        # A strict subset of --output's content, never the whole statement:
        # a mutant that writes the whole statement to --predicate-output
        # (yielding the nested predicate.predicate cosign would then sign)
        # would fail the equality above, and would also carry every one of
        # the statement's own envelope keys, which the real predicate
        # object never does.
        self.assertNotEqual(modified_predicate, statement)
        for envelope_key in statement:
            self.assertNotIn(envelope_key, modified_predicate)

    def test_missing_predicate_output_flag_exits_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit) as failure:
                self.invoke(temporary, include_predicate_output=False)
            self.assertEqual(failure.exception.code, 2)

    # test_predicate_output_file_exists_and_is_non_empty_after_success stood
    # here and is subsumed, not merely similar. It ran the IDENTICAL invocation
    # -- `self.invoke(temporary)` with no keyword arguments, so every default
    # -- and asserted only exists() and st_size > 0. The sibling above runs
    # that same invocation and then json.loads() the file, which cannot
    # succeed unless it exists and is non-empty, before asserting byte
    # equality with statement["predicate"]. One honest cost, recorded rather
    # than glossed: a missing or empty file now surfaces as an ERROR
    # (FileNotFoundError / JSONDecodeError) instead of a FAILURE. The coverage
    # is identical; the message is less tidy.

    def test_missing_builder_run_id_flag_exits_two(self):
        # Issue #137: the run binding is required, never defaulted -- an
        # optional flag would let a caller silently fall back to the old
        # repository-wide prefix behaviour.
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit) as failure:
                self.invoke(temporary, include_builder_run_id=False)
            self.assertEqual(failure.exception.code, 2)

    def test_a_foreign_run_id_denies_and_writes_no_statement(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, predicate_output_path = self.invoke(
                temporary, builder_run_id="124"
            )
            self.assertEqual(code, 1)
            self.assertIn("builder", self.stderr.getvalue())
            self.assertFalse(output_path.exists())
            self.assertFalse(predicate_output_path.exists())

    def test_a_malformed_run_id_argument_denies_before_the_predicate_is_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output_path, _ = self.invoke(temporary, builder_run_id="123; rm -rf /")
            self.assertEqual(code, 1)
            self.assertIn("builder run ID", self.stderr.getvalue())
            self.assertFalse(output_path.exists())


class GitTransitionTests(SyntheticRepo, unittest.TestCase):
    # This class builds its repositories a step at a time rather than through
    # SyntheticRepo.repo(): its tests choose their own first commit, so the
    # seeded-0.1.9 composite would be wrong for them. It keeps two helpers
    # nothing else has -- metadata_commit, which stages README.md alone, and
    # remove_version, the only DELETING helper, which uses `git add -u` where
    # paths_commit's deletion branch uses `git rm --cached`. Those two stay.
    def commit(self, root: Path, version: str) -> str:
        """This class's name for release_commit; its 19 call sites read `commit`."""
        return self.release_commit(root, version)

    def metadata_commit(self, root: Path, marker: str) -> str:
        (root / "README.md").write_text(marker + "\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", marker)
        return self.git(root, "rev-parse", "HEAD")

    def remove_version(self, root: Path, marker: str) -> str:
        (root / "VERSION").unlink()
        self.git(root, "add", "-u", "VERSION")
        self.git(
            root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-m",
            marker,
        )
        return self.git(root, "rev-parse", "HEAD")

    def test_three_sequential_main_commits_and_stale_base_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.main_repo(temporary)
            commits = [self.commit(root, version) for version in ("0.1.9", "0.1.10", "0.1.11", "0.1.12")]
            for index in range(1, len(commits)):
                intent = RC.validate_transition(root, commits[index - 1], commits[index], first_parent=True)
                self.assertEqual(intent.tag, f"v0.1.{9 + index}")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[1], commits[3], first_parent=True)
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[2], commits[1], first_parent=True)

            # GitHub's enabled rebase merge can land several linear commits in
            # one push. The exact base -> final-tree patch step is the release
            # intent even when an earlier commit in the same atomic push has
            # not updated the locks yet; the final SHA is the one released.
            self.git(root, "checkout", "-q", "-b", "rebase-range", commits[0])
            intermediate = self.metadata_commit(root, "unreleased change")
            final_head = self.commit(root, "0.1.10")
            intent = RC.validate_transition(root, commits[0], final_head, first_parent=True)
            self.assertEqual(intent, RC.ReleaseIntent(final_head, RC.Version.parse("0.1.10")))
            window = RC.discover_transition_window(root, final_head)
            self.assertEqual(window.base_sha, intermediate)
            self.assertEqual(window.intent, intent)
            self.assertNotEqual(intermediate, final_head)

            # A later metadata commit that preserves the final release locks
            # is also one exact rebase-merge intent and remains discoverable.
            preserved_head = self.metadata_commit(root, "post-bump repair")
            preserved = RC.validate_transition(root, commits[0], preserved_head, first_parent=True)
            self.assertEqual(preserved, RC.ReleaseIntent(preserved_head, RC.Version.parse("0.1.10")))
            preserved_window = RC.discover_transition_window(root, preserved_head)
            self.assertEqual(preserved_window.base_sha, intermediate)
            self.assertEqual(preserved_window.intent, preserved)

            # A second patch in the same integration would collapse two
            # release intents into one tag and is rejected at the endpoint.
            self.git(root, "checkout", "-q", "-b", "double-bump", commits[0])
            self.commit(root, "0.1.10")
            double_head = self.commit(root, "0.1.11")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[0], double_head, first_parent=True)

            self.git(root, "checkout", "-q", "-b", "stale", commits[0])
            stale_head = self.commit(root, "0.1.12")
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, commits[2], stale_head, first_parent=False)

    def test_real_two_parent_commit_is_denied_in_pr_and_main_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.main_repo(temporary)
            base = self.commit(root, "0.1.9")
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.commit(root, "0.1.10")
            self.git(root, "checkout", "-q", "main")
            self.metadata_commit(root, "independent main change")
            self.git(
                root,
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release@example.invalid",
                "merge",
                "--no-ff",
                "topic",
                "-m",
                "two-parent mutant",
            )
            merge_head = self.git(root, "rev-parse", "HEAD")
            self.assertEqual(
                len(self.git(root, "rev-list", "--parents", "-n", "1", merge_head).split()),
                3,
            )
            for first_parent in (False, True):
                with self.subTest(first_parent=first_parent), self.assertRaises(RC.ContractError):
                    RC.validate_transition(root, base, merge_head, first_parent=first_parent)

    def test_every_intermediate_version_state_is_load_bearing(self):
        builders = (
            lambda root: (
                self.commit(root, "0.1.11"),
                self.commit(root, "0.1.9"),
                self.commit(root, "0.1.10"),
            )[-1],
            lambda root: (
                self.commit(root, "0.1.10"),
                self.commit(root, "0.1.9"),
                self.commit(root, "0.1.10"),
            )[-1],
            lambda root: (
                self.remove_version(root, "delete VERSION transiently"),
                self.commit(root, "0.1.10"),
            )[-1],
        )
        for index, build in enumerate(builders):
            with self.subTest(history_mutant=index), tempfile.TemporaryDirectory() as temporary:
                root = self.main_repo(temporary)
                base = self.commit(root, "0.1.9")
                head = build(root)
                for first_parent in (False, True):
                    with self.assertRaises(RC.ContractError):
                        RC.validate_transition(root, base, head, first_parent=first_parent)
                with self.assertRaises(RC.ContractError):
                    RC.discover_transition_window(root, head)

    def test_clean_endpoint_range_cannot_hide_a_poisoned_history_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.main_repo(temporary)
            self.commit(root, "0.1.9")
            self.commit(root, "0.1.10")
            base = self.commit(root, "0.1.9")
            head = self.commit(root, "0.1.10")
            for first_parent in (False, True):
                with self.assertRaises(RC.ContractError):
                    RC.validate_transition(root, base, head, first_parent=first_parent)
            with self.assertRaises(RC.ContractError):
                RC.discover_transition_window(root, head)


def ladder(*rows: tuple[str, str, str]) -> str:
    """Build a changelog from explicit `(version, date, body)` rows.

    The generated `changelog()` ladder above dates every release the same day,
    which is right for the transition fixtures and wrong for these: a flat
    ladder cannot express a date edit that leaves the ordering rule satisfied,
    so a re-dating mutant would be refused by the SHAPE rule and the
    append-only date branch would never run. These rows are dated apart on
    purpose, so each mutant below reaches the guard it is aimed at.
    """
    return "# Changelog\n\n## [Unreleased]\n\n" + "\n".join(
        f"## [{version}] - {date}\n\n{body}\n" for version, date, body in rows
    )


HISTORY_ROWS = (
    ("0.1.9", "2026-08-19", "- ninth"),
    ("0.1.8", "2026-08-18", "- eighth"),
    ("0.1.7", "2026-08-17", "- seventh"),
    ("0.1.6", "2026-08-16", "- sixth"),
)
HISTORY_BASE = ladder(*HISTORY_ROWS)
HISTORY_HEAD = ladder(("0.1.10", "2026-08-20", "- tenth"), *HISTORY_ROWS)


class ChangelogHistoryTests(SyntheticRepo, unittest.TestCase):
    """Issue #105: released changelog history is append-only, and provably so.

    Before this, `validate_snapshot` read exactly one heading -- the current
    version's -- and everything below it was deletable with every release
    control green. The gap was found by a mechanical edit, not an attack: an
    insertion that overwrote the span down to and including the heading below
    it, orphaning one shipped release's entries under the next version's name.
    """

    def test_a_pure_insertion_on_top_is_accepted(self):
        RC.require_appended_changelog(HISTORY_BASE, HISTORY_HEAD)
        # And several at once, which a rebase range legitimately produces.
        RC.require_appended_changelog(
            HISTORY_BASE,
            ladder(
                ("0.1.11", "2026-08-21", "- eleventh"),
                ("0.1.10", "2026-08-20", "- tenth"),
                *HISTORY_ROWS,
            ),
        )
        # An untouched changelog is the documentation-only case.
        RC.require_appended_changelog(HISTORY_BASE, HISTORY_BASE)

    def test_every_edit_to_released_history_is_refused(self):
        new = ("0.1.10", "2026-08-20", "- tenth")
        for label, head, expected in (
            ("deleted middle heading",
             ladder(new, HISTORY_ROWS[0], *HISTORY_ROWS[2:]), "0.1.8"),
            ("deleted tail heading",
             ladder(new, *HISTORY_ROWS[:-1]), "lost 1 released heading"),
            ("deleted every released heading",
             ladder(new), "lost 4 released heading"),
            ("one release added and one quietly deleted",
             ladder(new, *HISTORY_ROWS[:2], HISTORY_ROWS[3]), "lost 1 released heading"),
            ("reordered pair",
             ladder(new, HISTORY_ROWS[0], HISTORY_ROWS[2], HISTORY_ROWS[1], HISTORY_ROWS[3]),
             "descend"),
            ("duplicated version",
             ladder(new, HISTORY_ROWS[0], *HISTORY_ROWS), "more than once"),
            ("mutated historical date",
             ladder(new, HISTORY_ROWS[0], ("0.1.8", "2026-08-17", "- eighth"),
                    *HISTORY_ROWS[2:]),
             RC.CHANGELOG_CORRECTIONS_PATH),
            ("rewritten historical entry",
             ladder(new, HISTORY_ROWS[0], ("0.1.8", "2026-08-18", "- eighth, revised"),
                    *HISTORY_ROWS[2:]),
             "rewritten"),
            ("historical entry silently appended to",
             ladder(new, HISTORY_ROWS[0], ("0.1.8", "2026-08-18", "- eighth\n- and more"),
                    *HISTORY_ROWS[2:]),
             "rewritten"),
            ("new version reusing a released number",
             ladder(("0.1.8", "2026-08-20", "- impostor"), *HISTORY_ROWS), "descend"),
        ):
            with self.subTest(mutant=label), self.assertRaises(RC.ContractError) as denied:
                RC.require_appended_changelog(HISTORY_BASE, head)
            self.assertIn(expected, str(denied.exception))

    def test_the_shape_rules_refuse_a_ladder_no_release_sequence_can_produce(self):
        for label, text, expected in (
            ("ascending order",
             ladder(("0.1.8", "2026-08-18", "- x"), ("0.1.9", "2026-08-19", "- y")),
             "must descend"),
            ("duplicate version",
             ladder(("0.1.9", "2026-08-19", "- x"), ("0.1.9", "2026-08-19", "- y")),
             "more than once"),
            ("date increasing downward",
             ladder(("0.1.9", "2026-08-18", "- x"), ("0.1.8", "2026-08-19", "- y")),
             "is later than"),
            ("impossible calendar date",
             ladder(("0.1.9", "2026-02-30", "- x")), "not a real ISO date"),
            ("no released heading at all",
             "# Changelog\n\n## [Unreleased]\n\n- nothing shipped\n", "no released"),
            ("released heading respelled so the parse cannot see it",
             HISTORY_BASE.replace("## [0.1.8] - 2026-08-18", "## [0.1.8] -- 2026-08-18"),
             "is neither"),
            ("aggregate tail heading floated above real history",
             "# Changelog\n\n## [Unreleased]\n\n## [0.1.3] and earlier\n\n- imported\n\n"
             + ladder(*HISTORY_ROWS).split("## [Unreleased]\n\n", 1)[1],
             "only as the last"),
        ):
            with self.subTest(shape=label), self.assertRaises(RC.ContractError) as denied:
                RC.require_changelog_history(text)
            self.assertIn(expected, str(denied.exception))

    def test_the_imported_aggregate_tail_is_ordinary_body_text(self):
        tail = ladder(*HISTORY_ROWS) + "\n## [0.1.3] and earlier\n\nimported\n"
        sections = RC.require_changelog_history(tail)
        self.assertEqual([str(section.version) for section in sections],
                         [row[0] for row in HISTORY_ROWS])
        self.assertIn("## [0.1.3] and earlier", sections[-1].body)
        RC.require_appended_changelog(tail, ladder(("0.1.10", "2026-08-20", "- tenth"),
                                                  *HISTORY_ROWS)
                                      + "\n## [0.1.3] and earlier\n\nimported\n")
        with self.assertRaises(RC.ContractError):
            RC.require_appended_changelog(tail, ladder(*HISTORY_ROWS))

    def test_the_snapshot_check_reads_the_whole_ladder_not_only_the_top(self):
        """`validate_snapshot` runs on every snapshot, so the shape rules bite
        there too -- not only inside the base-to-head comparison.

        Before issue #105 this function read exactly one heading, the current
        version's, and every heading below it was unconstrained on a snapshot
        nobody was diffing.
        """
        self.assertEqual(RC.validate_snapshot(snapshot("0.1.10")).tag, "v0.1.10")
        for label, text in (
            ("a duplicate republished at the bottom",
             changelog("0.1.10") + "\n## [0.1.9] - 2026-08-13\n\n- again\n"),
            ("a historical date later than the release above it",
             changelog("0.1.10").replace(
                 "## [0.1.5] - 2026-08-13", "## [0.1.5] - 2026-08-14", 1)),
            ("a released heading respelled out of the ladder",
             changelog("0.1.10").replace(
                 "## [0.1.5] - 2026-08-13", "## [0.1.5] -- 2026-08-13", 1)),
            ("a release block sitting ABOVE the Unreleased heading",
             changelog("0.1.10").replace(
                 "## [Unreleased]",
                 "## [0.1.99] - 2026-08-14\n\n- stray\n\n## [Unreleased]", 1)),
        ):
            broken = dict(snapshot("0.1.10"))
            broken["CHANGELOG.md"] = text
            with self.subTest(ladder=label), self.assertRaises(RC.ContractError):
                RC.validate_snapshot(broken)

    def test_the_correction_lift_authorizes_one_date_and_nothing_else(self):
        corrected = ladder(
            ("0.1.10", "2026-08-20", "- tenth"),
            HISTORY_ROWS[0],
            ("0.1.8", "2026-08-17", "- eighth"),
            *HISTORY_ROWS[2:],
        )
        exact = {RC.Version.parse("0.1.8"): (dt.date(2026, 8, 18), dt.date(2026, 8, 17), "why")}
        RC.require_appended_changelog(HISTORY_BASE, corrected, exact)
        for label, corrections in (
            ("no lift at all", {}),
            ("wrong old date",
             {RC.Version.parse("0.1.8"): (dt.date(2026, 8, 19), dt.date(2026, 8, 17), "why")}),
            ("wrong new date",
             {RC.Version.parse("0.1.8"): (dt.date(2026, 8, 18), dt.date(2026, 8, 16), "why")}),
            ("some other version",
             {RC.Version.parse("0.1.7"): (dt.date(2026, 8, 18), dt.date(2026, 8, 17), "why")}),
        ):
            with self.subTest(lift=label), self.assertRaises(RC.ContractError):
                RC.require_appended_changelog(HISTORY_BASE, corrected, corrections)
        # And the lift reaches the DATE only: the same line cannot carry a
        # deletion, a reorder, or a rewritten entry through with it.
        for label, head in (
            ("deletion", ladder(("0.1.10", "2026-08-20", "- tenth"), HISTORY_ROWS[0],
                                *HISTORY_ROWS[2:])),
            ("rewritten entry", ladder(("0.1.10", "2026-08-20", "- tenth"), HISTORY_ROWS[0],
                                       ("0.1.8", "2026-08-17", "- eighth, revised"),
                                       *HISTORY_ROWS[2:])),
        ):
            with self.subTest(unliftable=label), self.assertRaises(RC.ContractError):
                RC.require_appended_changelog(HISTORY_BASE, head, exact)

    def test_the_correction_allowlist_parser_refuses_a_line_it_cannot_read(self):
        parsed = RC.parse_changelog_corrections(
            "# a comment\n\n0.1.7 | 2026-08-11 | 2026-08-10 | the tag says so\n"
        )
        self.assertEqual(
            parsed,
            {RC.Version.parse("0.1.7"): (dt.date(2026, 8, 11), dt.date(2026, 8, 10),
                                         "the tag says so")},
        )
        self.assertEqual(RC.parse_changelog_corrections(""), {})
        for label, text in (
            ("three fields", "0.1.7 | 2026-08-11 | 2026-08-10\n"),
            ("five fields", "0.1.7 | 2026-08-11 | 2026-08-10 | why | extra\n"),
            ("empty reason", "0.1.7 | 2026-08-11 | 2026-08-10 |\n"),
            ("no reason but a space", "0.1.7 | 2026-08-11 | 2026-08-10 |   \n"),
            ("unparseable version", "v0.1.7 | 2026-08-11 | 2026-08-10 | why\n"),
            ("unparseable date", "0.1.7 | 2026-08-32 | 2026-08-10 | why\n"),
            ("identical dates", "0.1.7 | 2026-08-10 | 2026-08-10 | why\n"),
            ("one version corrected twice",
             "0.1.7 | 2026-08-11 | 2026-08-10 | why\n0.1.7 | 2026-08-10 | 2026-08-09 | why\n"),
        ):
            with self.subTest(line=label), self.assertRaises(RC.ContractError):
                RC.parse_changelog_corrections(text)

    def test_the_shipped_allowlist_and_changelog_agree_with_each_other(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        sections = {section.version: section for section in RC.require_changelog_history(text)}
        allowlist = ROOT / RC.CHANGELOG_CORRECTIONS_PATH
        self.assertTrue(allowlist.is_file(), "the correction lift file must exist")
        for version, (old, new, reason) in RC.parse_changelog_corrections(
            allowlist.read_text(encoding="utf-8")
        ).items():
            with self.subTest(correction=str(version)):
                self.assertIn(version, sections, "a correction names an unreleased version")
                # The line must describe the state the repository is IN: the
                # corrected date, never the one it replaced. A line pointing at
                # a heading that never moved is a line describing a fiction.
                self.assertEqual(sections[version].date, new)
                self.assertNotEqual(old, new)
                self.assertGreater(len(reason), 40, "a correction states its evidence")

    def test_the_lift_is_read_from_the_head_commit_and_absence_denies(self):
        for carries_lift in (False, True):
            with self.subTest(lift_committed=carries_lift), tempfile.TemporaryDirectory() as tmp:
                root = self.main_repo(tmp)
                base_files = dict(snapshot("0.1.9"))
                base_files["CHANGELOG.md"] = HISTORY_BASE
                base = self.paths_commit(root, base_files, "base")
                head_files = dict(snapshot("0.1.10"))
                head_files["CHANGELOG.md"] = ladder(
                    ("0.1.10", "2026-08-20", "- tenth"),
                    HISTORY_ROWS[0],
                    ("0.1.8", "2026-08-17", "- eighth"),
                    *HISTORY_ROWS[2:],
                )
                if carries_lift:
                    head_files[RC.CHANGELOG_CORRECTIONS_PATH] = (
                        "0.1.8 | 2026-08-18 | 2026-08-17 | the annotated tag says so\n"
                    )
                head = self.paths_commit(root, head_files, "0.1.10")
                if carries_lift:
                    verdict = RC.classify_transition(root, base, head, first_parent=True)
                    self.assertEqual(verdict["class"], "artifact")
                    self.assertEqual(verdict["tag"], "v0.1.10")
                else:
                    with self.assertRaises(RC.ContractError) as denied:
                        RC.classify_transition(root, base, head, first_parent=True)
                    self.assertIn(RC.CHANGELOG_CORRECTIONS_PATH, str(denied.exception))

    def test_a_release_range_that_deletes_history_is_refused_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.main_repo(tmp)
            base_files = dict(snapshot("0.1.9"))
            base_files["CHANGELOG.md"] = HISTORY_BASE
            base = self.paths_commit(root, base_files, "base")
            head_files = dict(snapshot("0.1.10"))
            head_files["CHANGELOG.md"] = ladder(
                ("0.1.10", "2026-08-20", "- tenth"), HISTORY_ROWS[0], *HISTORY_ROWS[2:]
            )
            head = self.paths_commit(root, head_files, "0.1.10 minus one release")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("append-only", str(denied.exception))
            with self.assertRaises(RC.ContractError):
                RC.validate_transition(root, base, head, first_parent=True)

    def test_the_orphaning_edit_that_found_this_gap_is_refused(self):
        """The exact mechanical failure of issue #105, replayed.

        An edit that meant to INSERT a block above `## [0.1.8]` replaced the
        span from `## [Unreleased]` down to and including that heading. The
        result is well formed, reads like history, and leaves 0.1.8's entries
        sitting under 0.1.10's name.
        """
        orphaned = HISTORY_BASE.replace(
            "## [Unreleased]\n\n## [0.1.9] - 2026-08-19\n\n- ninth\n\n## [0.1.8] - 2026-08-18\n",
            "## [Unreleased]\n\n## [0.1.10] - 2026-08-20\n",
            1,
        )
        self.assertNotEqual(orphaned, HISTORY_BASE)
        RC.require_changelog_history(orphaned)  # the shape rules alone say nothing
        with self.assertRaises(RC.ContractError) as denied:
            RC.require_appended_changelog(HISTORY_BASE, orphaned)
        self.assertIn("append-only", str(denied.exception))


class NoArtifactClassTests(SyntheticRepo, unittest.TestCase):
    """The documentation-only class must fail closed in every direction."""

    def test_documentation_path_table_is_closed_in_both_directions(self):
        for path, expected in (
            ("AGENTS.md", True),
            ("README.md", True),
            (".gitignore", True),
            ("docs/guide.md", True),
            ("docs/deep/nested.md", True),
            ("CHANGELOG.md", False),
            ("VERSION", False),
            ("LICENSE", False),
            ("chart/Chart.yaml", False),
            ("chart/values.yaml", False),
            # Paths no shipped byte can come from (issue #16, item F):
            # workflows, CI scripts and Go test files.
            ("scripts/ci/release_contract.py", True),
            ("scripts/ci/install-tools.sh", True),
            (".github/workflows/pr-gate.yml", True),
            (".github/dependabot.yml", True),
            (".github/PULL_REQUEST_TEMPLATE.md", True),
            ("cmd/server/main_test.go", True),
            ("internal/server/server_test.go", True),
            ("internal/server/deep/x_test.go", True),
            ("site/site_test.go", True),
            # Everything that reaches the image or the chart.
            ("Dockerfile", False),
            (".dockerignore", False),
            ("go.mod", False),
            ("go.sum", False),
            ("cmd/server/main.go", False),
            ("internal/server/server.go", False),
            ("internal/server/testing.go", False),
            ("internal/server/testdata/fixture.webp", False),
            ("site/embed.go", False),
            ("site/media.go", False),
            ("site/index.html", False),
            ("site/app.js", False),
            ("site/assets/font-0.ttf", False),
            ("chart/templates/deployment.yaml", False),
            ("chart/values.schema.json", False),
            ("scripts/stage-media.sh", False),
            ("scripts/cix/a.py", False),
            ("tools/x_test.go", False),
            ("x_test.go", False),
            ("cmd/server/main_test.go/x", False),
            (".github", False),
            (".githubx/a.yml", False),
            ("scripts/ci/", False),
            ("docs/tool.py", False),
            ("docs/README", False),
            ("frontend/.gitignore", False),
            ("readme.md", False),
            ("cmd/site/main.go", False),
            ("", False),
        ):
            with self.subTest(path=path):
                self.assertIs(RC.is_documentation_path(path), expected)

    def test_docs_only_single_commit_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"AGENTS.md": "agents contract\n"}, "docs")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(
                verdict,
                {
                    "class": "no-artifact",
                    "base_sha": base,
                    "source_sha": head,
                    "version": "0.1.9",
                    "tag": "v0.1.9",
                    "commits": 1,
                },
            )

    def test_docs_only_add_edit_delete_range_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"docs/guide.md": "guide\n", ".gitignore": "*.tmp\n"}, "add")
            self.paths_commit(root, {"README.md": "edited readme\n"}, "edit")
            head = self.paths_commit(root, {"docs/guide.md": None}, "delete")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")
            self.assertEqual(verdict["commits"], 3)
            self.assertEqual(verdict["tag"], "v0.1.9")

    def test_ci_and_test_only_ranges_classify_no_artifact(self):
        # Issue #16, item F: an actions bump, a gate-script edit or a Go test
        # change ships no byte, so it advances nothing and cuts no release.
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {".github/workflows/pr-gate.yml": "name: PR gate\n"}, "workflow")
            self.paths_commit(root, {"scripts/ci/install-tools.sh": "#!/bin/sh\n"}, "ci script")
            self.paths_commit(root, {"internal/server/server_test.go": "package server\n"}, "go test")
            head = self.paths_commit(
                root,
                {"site/site_test.go": "package site\n", "cmd/server/main_test.go": "package main\n", "docs/guide.md": "guide\n"},
                "more tests and docs",
            )
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")
            self.assertEqual(verdict["commits"], 4)
            self.assertEqual(verdict["tag"], "v0.1.9")

    def test_build_inputs_without_release_patch_deny(self):
        # Every file that reaches the image or the chart still needs its one
        # exact patch, alone or beside a workflow change.
        for path in (
            "Dockerfile",
            ".dockerignore",
            "go.mod",
            "cmd/server/main.go",
            "internal/server/server.go",
            "site/index.html",
            "site/media.go",
            "chart/values.yaml",
            "chart/templates/deployment.yaml",
        ):
            for beside_workflow in (False, True):
                with self.subTest(path=path, beside_workflow=beside_workflow), tempfile.TemporaryDirectory() as temporary:
                    root, base = self.repo(temporary)
                    if beside_workflow:
                        self.paths_commit(root, {".github/workflows/pr-gate.yml": "name: PR gate\n"}, "workflow")
                    head = self.paths_commit(root, {path: "changed\n"}, "build input")
                    with self.assertRaises(RC.ContractError) as denied:
                        RC.classify_transition(root, base, head, first_parent=True)
                    self.assertIn(path, str(denied.exception))

    def test_mixed_range_without_release_patch_denies_naming_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            head = self.paths_commit(root, {"cmd/site/main.go": "package main\n"}, "code")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("without one exact release patch", str(denied.exception))
            self.assertIn("cmd/site/main.go", str(denied.exception))

    def test_artifact_only_range_without_release_patch_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"cmd/site/main.go": "package main\n"}, "code")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, head, first_parent=True)

    def test_changelog_only_edit_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            changed = (root / "CHANGELOG.md").read_text(encoding="utf-8") + "\n- stray claim\n"
            head = self.paths_commit(root, {"CHANGELOG.md": changed}, "stray")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("CHANGELOG.md", str(denied.exception))

    def test_docs_range_with_full_release_patch_stays_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            files = dict(snapshot("0.1.10"))
            files["AGENTS.md"] = "agents contract\n"
            head = self.paths_commit(root, files, "release with docs")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "artifact")
            self.assertEqual(verdict["tag"], "v0.1.10")
            self.assertEqual(verdict["source_sha"], head)
            intent = RC.validate_transition(root, base, head, first_parent=True)
            self.assertEqual(intent, RC.ReleaseIntent(head, RC.Version.parse("0.1.10")))

    def test_touch_then_revert_inside_range_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.paths_commit(root, {"cmd/site/main.go": "package main\n"}, "touch")
            self.paths_commit(root, {"cmd/site/main.go": None}, "revert")
            head = self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("cmd/site/main.go", str(denied.exception))

    def test_symlink_swap_at_documentation_path_denies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            os.symlink("AGENTS.md", root / "README.md")
            self.git(root, "add", "README.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "symlink add")
            added = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, added, first_parent=True)

            seeded = self.paths_commit(root, {"docs/real.md": "real file\n"}, "seed doc")
            (root / "docs/real.md").unlink()
            os.symlink("../CHANGELOG.md", root / "docs/real.md")
            self.git(root, "add", "docs/real.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "typechange")
            swapped = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, seeded, swapped, first_parent=True)

    def test_executable_bit_on_markdown_remains_documentation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.repo(temporary)
            base = self.paths_commit(root, {"README.md": "# readme\n"}, "seed readme")
            os.chmod(root / "README.md", 0o755)
            self.git(root, "add", "README.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "chmod")
            head = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

    def test_tree_identical_range_classifies_no_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "--allow-empty", "-m", "no-op")
            head = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, head, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

    def test_two_parent_commit_denies_in_both_classes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self.git(root, "checkout", "-q", "-b", "topic", base)
            self.paths_commit(root, {"AGENTS.md": "topic docs\n"}, "topic docs")
            self.git(root, "checkout", "-q", "main")
            self.paths_commit(root, {"README.md": "main docs\n"}, "main docs")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "merge", "--no-ff", "topic", "-m", "merge")
            head = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, base, head, first_parent=True)

    def test_cli_transition_emits_both_verdicts_and_denies_mixed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs edit\n"}, "docs")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = RC.main(["transition", "--repository", str(root), "--base", base, "--head", docs_head, "--first-parent"])
            self.assertEqual(code, 0)
            verdict = json.loads(stream.getvalue())
            self.assertEqual(verdict["class"], "no-artifact")
            self.assertEqual(verdict["source_sha"], docs_head)

            release_head = self.release_commit(root, "0.1.10")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = RC.main(["transition", "--repository", str(root), "--base", docs_head, "--head", release_head, "--first-parent"])
            self.assertEqual(code, 0)
            verdict = json.loads(stream.getvalue())
            self.assertEqual(verdict["class"], "artifact")
            self.assertEqual(verdict["tag"], "v0.1.10")

            mixed_head = self.paths_commit(root, {"cmd/site/main.go": "package main\n"}, "code only")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = RC.main(["transition", "--repository", str(root), "--base", release_head, "--head", mixed_head, "--first-parent"])
            self.assertEqual(code, 1)
            self.assertTrue(err.getvalue().startswith("DENY: "))

    def test_discovery_still_recovers_boundary_past_trailing_docs_merges(self):
        """The orchestrator's no-artifact anchor is exactly the release commit.

        The sibling delivery repository polls for the retained tag; here the
        publisher creates tags minutes after the merge, so the orchestrator
        recovers the boundary from git alone. ``release-window`` reports the
        commit BEFORE the patch boundary, so the workflow must advance to the
        first mainline commit after it. Both halves are proven here so the
        anchor cannot drift silently into an artifact-swallowing range.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            release_head = self.release_commit(root, "0.1.10")
            docs_head = self.paths_commit(root, {"AGENTS.md": "post-release docs\n"}, "docs")
            window = RC.discover_transition_window(root, docs_head)
            self.assertEqual(window.intent.version, RC.Version.parse("0.1.10"))
            self.assertEqual(window.intent.source_sha, docs_head)
            self.assertEqual(window.base_sha, base)
            mainline = self.git(root, "rev-list", "--first-parent", "--reverse", f"{window.base_sha}..{docs_head}")
            self.assertEqual(mainline.splitlines()[0], release_head)
            cumulative = RC.classify_transition(root, release_head, docs_head, first_parent=True)
            self.assertEqual(cumulative["class"], "no-artifact")
            self.assertEqual(cumulative["tag"], "v0.1.10")
            self.assertEqual(
                RC.classify_transition(root, window.base_sha, docs_head, first_parent=True)["class"],
                "artifact",
            )

    def test_rebase_release_with_trailing_code_requires_the_advanced_anchor(self):
        """A rebase-merged release [bump, code] is tagged at the code commit.

        The naive boundary anchor (the bump commit) swallows the release
        push's own trailing commit and would false-deny every later docs
        merge; the advanced anchor (the tagged release head) classifies the
        same gap no-artifact. Both directions are pinned so the workflow's
        advance-loop semantics cannot regress silently.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            bump = self.release_commit(root, "0.1.10")
            code = self.paths_commit(root, {"cmd/site/main.go": "package main\n"}, "trailing code")
            docs_head = self.paths_commit(root, {"AGENTS.md": "post-release docs\n"}, "docs")
            window = RC.discover_transition_window(root, docs_head)
            self.assertEqual(window.base_sha, base)
            mainline = self.git(root, "rev-list", "--first-parent", "--reverse", f"{window.base_sha}..{docs_head}")
            self.assertEqual(mainline.splitlines()[0], bump)
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, bump, docs_head, first_parent=True)
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, bump, code, first_parent=True)
            cumulative = RC.classify_transition(root, code, docs_head, first_parent=True)
            self.assertEqual(cumulative["class"], "no-artifact")
            self.assertEqual(cumulative["tag"], "v0.1.10")

    def test_rename_decomposes_and_denies_only_across_the_allowlist_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.repo(temporary)
            base = self.paths_commit(root, {"docs/old.md": "content\n"}, "seed")
            self.git(root, "mv", "docs/old.md", "docs/new.md")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "inside rename")
            inside = self.git(root, "rev-parse", "HEAD")
            verdict = RC.classify_transition(root, base, inside, first_parent=True)
            self.assertEqual(verdict["class"], "no-artifact")

            self.git(root, "mv", "docs/new.md", "escaped.txt")
            self.git(root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid", "commit", "-m", "crossing rename")
            crossing = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, inside, crossing, first_parent=True)
            self.assertIn("escaped.txt", str(denied.exception))

    def test_gitlink_entry_denies_even_under_an_allowlisted_path(self):
        # A submodule records mode 160000, outside the regular-file mode
        # set. The path MUST be allowlisted (docs/*.md) or this test is
        # decorative: with a non-allowlisted path the PATH guard denies and
        # the mode guard is never reached, so adding 160000 to
        # _DOCUMENTATION_DIFF_MODES would leave the suite green while a
        # gitlink at an allowlisted path classified no-artifact. That is
        # exactly the defect an adversarial review found in the first
        # version of this test.
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            pointer = self.git(root, "rev-parse", "HEAD")
            self.git(
                root, "update-index", "--add", "--cacheinfo", f"160000,{pointer},docs/vendored.md"
            )
            self.git(
                root, "-c", "user.name=Release Test",
                "-c", "user.email=release@example.invalid", "commit", "-m", "gitlink",
            )
            head = self.git(root, "rev-parse", "HEAD")
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("docs/vendored.md", str(denied.exception))

    def test_malformed_diff_entry_denies_instead_of_being_skipped(self):
        # The raw-diff parser is the one place a hostile or novel git output
        # could silently drop an entry, so its guard must deny rather than
        # ignore. Drive it directly: a real repository cannot easily emit a
        # malformed entry, and a guard nothing can reach is not a guard.
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            head = self.paths_commit(root, {"AGENTS.md": "agents\n"}, "docs")
            self.assertEqual(
                RC.classify_transition(root, base, head, first_parent=True)["class"],
                "no-artifact",
            )
            # _diff_entries shells out itself rather than going through the
            # _git helper, so the seam to stub is subprocess.run inside the
            # module under test.
            original = RC.subprocess.run
            for corrupt, reason in (
                (":100644 100644 aaaaaaa bbbbbbb\x00AGENTS.md\x00", "status field missing"),
                (":100644 100644 aaaaaaa bbbbbbb Z\x00AGENTS.md\x00", "unknown status letter"),
                (":100644 100644 zzzzzzz bbbbbbb M\x00AGENTS.md\x00", "non-hex blob id"),
                (":100644 100644 aaaaaaa bbbbbbb M\x00\x00", "empty path"),
                (":100644 M\x00AGENTS.md\x00", "truncated meta"),
            ):
                with self.subTest(reason=reason):
                    def fake(command, *args, _corrupt=corrupt, **kwargs):
                        if "diff" in command:
                            return subprocess.CompletedProcess(
                                command, 0, stdout=_corrupt.encode("utf-8"), stderr=b""
                            )
                        return original(command, *args, **kwargs)

                    RC.subprocess.run = fake
                    try:
                        with self.assertRaises(RC.ContractError) as denied:
                            RC.classify_transition(root, base, head, first_parent=True)
                    finally:
                        RC.subprocess.run = original
                    self.assertIn("malformed", str(denied.exception))
            # An unpaired stream denies on its own branch, not this one.
            RC.subprocess.run = lambda command, *args, **kwargs: (
                subprocess.CompletedProcess(command, 0, stdout=b":100644\x00", stderr=b"")
                if "diff" in command
                else original(command, *args, **kwargs)
            )
            try:
                with self.assertRaises(RC.ContractError) as unpaired:
                    RC.classify_transition(root, base, head, first_parent=True)
            finally:
                RC.subprocess.run = original
            self.assertIn("not meta/path paired", str(unpaired.exception))
            # The stub is fully reverted: the same range classifies again.
            self.assertEqual(
                RC.classify_transition(root, base, head, first_parent=True)["class"],
                "no-artifact",
            )

    def test_head_snapshot_is_revalidated_even_when_the_range_touches_no_lock(self):
        # Unchanged locks across the range do NOT imply a coherent release
        # snapshot: the range can START from an incoherent one. The head
        # validate_snapshot call is what catches that, and without it this
        # range would report a no-artifact verdict carrying a tag that
        # contradicts the chart.
        with tempfile.TemporaryDirectory() as temporary:
            root = self.main_repo(temporary)
            skewed = snapshot("0.1.9")
            skewed["chart/Chart.yaml"] = 'apiVersion: v2\nversion: 0.1.8\nappVersion: "0.1.8"\n'
            base = self.paths_commit(root, skewed, "skewed base")
            head = self.paths_commit(root, {"AGENTS.md": "agents\n"}, "docs only")
            for lock in RC.RELEASE_LOCK_PATHS:
                self.assertEqual(
                    self.git(root, "show", f"{base}:{lock}"),
                    self.git(root, "show", f"{head}:{lock}"),
                    lock,
                )
            with self.assertRaises(RC.ContractError) as denied:
                RC.classify_transition(root, base, head, first_parent=True)
            self.assertIn("chart version does not equal VERSION", str(denied.exception))


class NoArtifactClassifyShellPathTests(SyntheticRepo, unittest.TestCase):
    """Executed coverage for the release-after-main classify step's shell.

    ``NoArtifactWiringTests`` only pins substrings of this step's source; it
    never runs the ~110 lines of bash that decide whether a release happens.
    This class extracts the real step body from the real workflow file and
    runs it under real bash, real git (against a synthetic repository this
    class builds), real jq, real unzip, and the real ``release_contract.py``
    copied verbatim into that repository -- following the
    ``ExistingImageShellPathTests`` / ``MainAndCodeQLAuthorizationShellPathTests``
    house style. Only ``gh``, ``curl``, and ``python3`` are stubbed: ``gh``
    and ``curl`` because they are the two real network calls the step makes,
    and ``python3`` only to redirect to this interpreter (it still runs the
    genuine ``release_contract.py``).

    A note on the case statement's ``*)`` arm ("DENY: unknown transition
    class"): the line immediately before it,
    ``test "${rederived_class}" = "${claimed_class}"``, already denies (fails
    closed, silently, via ``set -e``) for ANY ``claimed_class`` the real
    ``classify_transition`` cannot itself emit -- and that function only ever
    returns ``"artifact"`` or ``"no-artifact"``. So a foreign claimed class
    is caught one line before the printed catch-all message can run;
    ``test_foreign_verdict_class_denies_before_reaching_the_catchall`` proves
    the fail-closed *behavior* and documents this reachability limit rather
    than silently asserting text that cannot appear.
    """

    STEP = "Classify the completed range from its authorized gate verdict"

    # --- synthetic repository helpers ------------------------------------
    #
    # git, release_commit, paths_commit and repo come from SyntheticRepo. This
    # class's own copies were identical to NoArtifactClassTests' apart from
    # line wrapping, which its section header used to say out loud ("mirroring
    # NoArtifactClassTests"). Only the composites below are its own.

    def _seed_documentation_push(self, temporary: str) -> tuple[Path, str, str, str]:
        """Build base(0.1.9) -> release_head(0.1.10) -> docs_head.

        The one real patch boundary (base -> release_head) is what every
        legitimate no-artifact scenario re-derives against; release_head
        doubles as this push's true base AND the head a real pr-gate.yml run
        history would report as the last successfully gated main commit.
        """
        root, base = self.repo(temporary)
        release_head = self.release_commit(root, "0.1.10")
        docs_head = self.paths_commit(root, {"AGENTS.md": "post-release docs\n"}, "docs")
        return root, base, release_head, docs_head

    @staticmethod
    def _install_release_contract(root: Path) -> None:
        destination = root / "scripts" / "ci"
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy(HERE / "release_contract.py", destination / "release_contract.py")

    @staticmethod
    def _pr_gate_runs(entries: list[tuple[int, str]]) -> dict[str, object]:
        return {
            "workflow_runs": [
                {
                    "id": run_id,
                    "head_branch": "main",
                    "event": "push",
                    "conclusion": "success",
                    "head_sha": sha,
                }
                for run_id, sha in entries
            ]
        }

    # --- workflow step extraction -------------------------------------------

    @staticmethod
    def workflow_run_block(step_name: str) -> str:
        """One orchestrator step's run block, verbatim from the workflow."""
        return workflow_run_block("release-after-main.yml", step_name)

    # --- execution -----------------------------------------------------------

    def execute(
        self,
        block: str,
        *,
        root: Path,
        completed_sha: str,
        main_run_id: str = "1000",
        artifacts_pages: list[dict[str, object]] | None = None,
        pr_gate_runs: dict[str, object] | None = None,
        verdict: dict[str, object] | None = None,
        zip_entries: dict[str, bytes] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        for tool in ("jq", "unzip", "find"):
            if shutil.which(tool) is None:
                raise AssertionError(
                    f"required tool is not installed on this machine: {tool} "
                    "-- refusing to skip silently"
                )
        if artifacts_pages is None:
            artifacts_pages = [
                {"artifacts": [{"id": 1, "name": "transition-verdict", "expired": False}]}
            ]
        if pr_gate_runs is None:
            pr_gate_runs = {"workflow_runs": []}
        if zip_entries is None:
            payload = json.dumps(verdict if verdict is not None else {}).encode("utf-8")
            zip_entries = {"transition-verdict.json": payload}

        with tempfile.TemporaryDirectory() as scratch:
            runner = Path(scratch)
            artifacts_json = runner / "artifacts-listing.json"
            artifacts_json.write_text(json.dumps(artifacts_pages), encoding="utf-8")
            pr_gate_json = runner / "pr-gate-runs.json"
            pr_gate_json.write_text(json.dumps(pr_gate_runs), encoding="utf-8")
            verdict_zip = runner / "verdict.zip"
            with zipfile.ZipFile(verdict_zip, "w") as archive:
                for name, data in zip_entries.items():
                    archive.writestr(name, data)
            event_path = runner / "event.json"
            event_path.write_text(json.dumps(event(completed_sha)), encoding="utf-8")
            output_path = runner / "github-output.txt"
            output_path.write_text("", encoding="utf-8")
            summary_path = runner / "github-summary.md"
            summary_path.write_text("", encoding="utf-8")
            runner_temp = runner / "runner-temp"
            runner_temp.mkdir()

            # set -x: several of this step's guards are bare `test`/`[[ ]]`
            # statements with no printed message on failure (fail closed via
            # `set -e` alone). Tracing makes the exact compared values -- the
            # "distinguishing output" -- visible on stderr without touching
            # the workflow block itself.
            prelude = r'''
set -x

python3() {
  "${TEST_PYTHON}" "$@"
}

gh() {
  local all="$*"
  case "${all}" in
    *"/artifacts?"*) cat "${ARTIFACTS_JSON}" ;;
    *"pr-gate.yml/runs?"*) cat "${PR_GATE_JSON}" ;;
    *) return 2 ;;
  esac
}

curl() {
  local output=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
      output="$2"
      shift 2
    else
      shift
    fi
  done
  cp "${VERDICT_ZIP}" "${output}"
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "GH_TOKEN": "fixture-token",
                    "COMPLETED_SHA": completed_sha,
                    "MAIN_RUN_ID": main_run_id,
                    "RUNNER_TEMP": str(runner_temp),
                    "GITHUB_OUTPUT": str(output_path),
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                    "GITHUB_REPOSITORY": "owner/site",
                    "GITHUB_API_URL": "https://api.github.example.invalid",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "ARTIFACTS_JSON": str(artifacts_json),
                    "PR_GATE_JSON": str(pr_gate_json),
                    "VERDICT_ZIP": str(verdict_zip),
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=root,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            return (
                completed,
                output_path.read_text(encoding="utf-8"),
                summary_path.read_text(encoding="utf-8"),
            )

    # --- scenario 1: documentation-only merge, both-direction happy path ---

    def test_documentation_only_merge_writes_no_artifact_class_and_summary(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            pr_gate_runs = self._pr_gate_runs([(500, release_head)])
            completed, output, summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=pr_gate_runs,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            self.assertIn("NO-ARTIFACT:", completed.stdout)
            self.assertIn("No-artifact merge", summary)

    # --- scenario 2: artifact merge, the other happy-path direction --------

    def test_artifact_merge_writes_artifact_class(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            bump_head = self.release_commit(root, "0.1.10")
            verdict = {"class": "artifact", "base_sha": base, "source_sha": bump_head}
            completed, output, summary = self.execute(
                block, root=root, completed_sha=bump_head, verdict=verdict
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=artifact\n", output)
            self.assertNotIn("NO-ARTIFACT:", completed.stdout)
            self.assertEqual(summary, "")

    # --- scenario 3: THE KEY REGRESSION -- a forged base inside the push ---

    def test_forged_base_inside_the_push_is_caught_by_the_independent_anchor(self):
        """A verdict naming base_sha AFTER the version bump must still deny.

        Push = [bump commit that changes VERSION and a code file] then
        [docs-only commit]. The true class over the whole push is artifact.
        A forged (or buggy) verdict claims base_sha = the BUMP commit itself
        and class = no-artifact: re-deriving over [bump..docs] genuinely
        reports no-artifact, because the docs commit alone changes nothing --
        the re-derivation is parameterised by claimed_base, so it is NOT
        independent of the verdict. Before the independent previous_head
        anchor existed, this verdict would have sailed through and silently
        skipped a release -- the wrong failure direction for requirement 10.
        The fix asks the Actions record for the pr-gate.yml run history
        directly, so the forged base cannot move the anchor: the four-lock
        diff against the TRUE previous gated head (`base`, before the bump)
        finds VERSION changed and denies before the parameterised
        re-derivation is ever trusted.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base = self.repo(temporary)
            self._install_release_contract(root)
            bump = self.paths_commit(
                root,
                {**snapshot("0.1.10"), "cmd/site/main.go": "package main\n"},
                "bump with trailing code",
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            verdict = {"class": "no-artifact", "base_sha": bump, "source_sha": docs_head}
            pr_gate_runs = self._pr_gate_runs([(500, base)])
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=pr_gate_runs,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("VERSION", completed.stderr)
            self.assertIn("changed since the last gated main head", completed.stderr)
            self.assertIn(base, completed.stderr)
            self.assertNotIn("class=", output)

    # --- scenarios 4-6: the transition-verdict artifact listing ------------

    def _assert_artifact_listing_denies(self, *, artifacts: list[dict[str, object]]) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            # A fully valid pr_gate_runs fixture, matching the happy-path
            # scenario exactly: this isolates the artifact-listing guard as
            # the ONLY thing that can make the run deny. Without this, a
            # mutation that silently widens the artifact selection (e.g.
            # `length == 1` -> `length >= 1`) would still be masked by the
            # unrelated empty-pr-gate-runs default and this test would stay
            # green for the wrong reason.
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                artifacts_pages=[{"artifacts": artifacts}],
                pr_gate_runs=self._pr_gate_runs([(500, release_head)]),
                verdict={"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head},
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # `set -x` traces the jq PROGRAM TEXT (a static command-line
            # argument) on every invocation, so the literal else-branch
            # message string is visible in stderr even when jq never takes
            # that branch -- that text alone is not distinguishing. jq's
            # actual runtime error is prefixed "jq: error (at FILE:LINE): ",
            # with no surrounding quotes; matching "): " immediately before
            # the message is what proves the error() call actually fired.
            self.assertIn("): expected exactly one transition-verdict artifact", completed.stderr)
            self.assertNotIn("class=", output)

    def test_missing_transition_verdict_artifact_denies(self):
        self._assert_artifact_listing_denies(artifacts=[])

    def test_duplicate_transition_verdict_artifacts_deny(self):
        self._assert_artifact_listing_denies(
            artifacts=[
                {"id": 1, "name": "transition-verdict", "expired": False},
                {"id": 2, "name": "transition-verdict", "expired": False},
            ]
        )

    def test_expired_only_transition_verdict_artifact_denies(self):
        self._assert_artifact_listing_denies(
            artifacts=[{"id": 1, "name": "transition-verdict", "expired": True}]
        )

    def test_valid_artifact_alongside_an_expired_duplicate_still_succeeds(self):
        # Parity with the sibling repository, and the positive half of the
        # `expired == false` filter. The three denials above all exercise the
        # exactly-one LENGTH check; this is the case where the filter itself
        # has to do work -- two entries named transition-verdict, one of them
        # expired -- and it must SUCCEED by picking the live one. The
        # regression this guards is only a false-deny, not a false-release,
        # which is why it is a low-severity gap rather than a hole; it is
        # closed here so the two repositories' suites do not differ.
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, _base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=self._pr_gate_runs([(500, release_head)]),
                artifacts_pages=[
                    {
                        "artifacts": [
                            {"id": 7, "name": "transition-verdict", "expired": True},
                            {"id": 1, "name": "transition-verdict", "expired": False},
                        ]
                    }
                ],
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact", output)

    # --- scenario 7: claimed_source disagrees with the completed SHA -------

    def test_claimed_source_mismatch_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            wrong_source = "b" * 40
            verdict = {
                "class": "no-artifact", "base_sha": release_head, "source_sha": wrong_source,
            }
            completed, output, _summary = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(f"test {wrong_source} = {docs_head}", completed.stderr)
            self.assertNotIn("class=", output)

    # --- scenario 8: claimed_base is not 40 lowercase hex characters -------

    def test_claimed_base_not_lowercase_hex_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            bad_base = "A" * 40
            verdict = {"class": "no-artifact", "base_sha": bad_base, "source_sha": docs_head}
            completed, output, _summary = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # `=~` alone is not distinguishing (the earlier, always-reached
            # MAIN_RUN_ID regex check also traces one); require the bad
            # value adjacent to the operator, matching the traced
            # `[[ AAAA...A =~ ... ]]` line for this exact guard.
            self.assertIn(f"[[ {bad_base} =~", completed.stderr)
            self.assertNotIn("class=", output)

    # --- scenarios 9-10: claimed_class disagrees with the re-derivation ----

    def _assert_class_mismatch_denies(self, *, claimed_class: str) -> None:
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {
                "class": claimed_class, "base_sha": release_head, "source_sha": docs_head,
            }
            completed, output, _summary = self.execute(
                block, root=root, completed_sha=docs_head, verdict=verdict
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(f"test no-artifact = {claimed_class}", completed.stderr)
            self.assertNotIn(
                "DENY: unknown transition class", completed.stdout + completed.stderr
            )
            self.assertNotIn("class=", output)

    def test_foreign_verdict_class_denies_before_reaching_the_catchall(self):
        # See the class docstring: a claimed class of "release" is denied by
        # the equality gate one line above the case statement, because the
        # real classifier can never itself produce "release" to agree with
        # it. Fail-closed is proven; the printed catch-all text is not
        # reachable here and this test does not pretend otherwise.
        self._assert_class_mismatch_denies(claimed_class="release")

    def test_claimed_class_disagrees_with_rederivation_denies(self):
        self._assert_class_mismatch_denies(claimed_class="artifact")

    # --- scenario 11: no earlier successful protected-main gate run --------

    def test_no_earlier_successful_protected_main_gate_run_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            for description, pr_gate_runs in (
                ("empty", self._pr_gate_runs([])),
                ("only later runs", self._pr_gate_runs([(1500, release_head)])),
            ):
                with self.subTest(description=description):
                    completed, output, _summary = self.execute(
                        block,
                        root=root,
                        completed_sha=docs_head,
                        verdict=verdict,
                        pr_gate_runs=pr_gate_runs,
                    )
                    self.assertNotEqual(
                        completed.returncode, 0, completed.stdout + completed.stderr
                    )
                    # See _assert_artifact_listing_denies: the jq else-branch
                    # message is traced as static program text on every
                    # invocation of this same jq command (including the
                    # happy path), so only the runtime "jq: error (at ...): "
                    # prefix immediately before the message proves the
                    # error() call actually fired here.
                    self.assertIn(
                        "): no earlier successful protected-main gate run",
                        completed.stderr,
                    )
                    self.assertNotIn("class=", output)

    # --- scenario 12: the previous gated head is not an ancestor -----------

    def test_previous_gated_head_not_an_ancestor_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            # A disconnected root commit sharing docs_head's EXACT tree, so
            # only its ancestry -- never its lock-file content -- is what
            # can make the check fail. commit-tree needs no checkout, so
            # HEAD never leaves docs_head.
            tree = self.git(root, "rev-parse", f"{docs_head}^{{tree}}")
            foreign_sha = self.git(
                root, "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
                "commit-tree", tree, "-m", "foreign root sharing the same tree",
            )
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            pr_gate_runs = self._pr_gate_runs([(500, foreign_sha)])
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=pr_gate_runs,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("merge-base --is-ancestor", completed.stderr)
            self.assertIn(foreign_sha, completed.stderr)
            self.assertIn(docs_head, completed.stderr)
            self.assertNotIn("class=", output)

    # --- scenario 13: the verdict zip carries more than one file -----------

    def test_zip_with_more_than_one_file_denies(self):
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            zip_entries = {
                "transition-verdict.json": json.dumps(verdict).encode("utf-8"),
                "unexpected-extra-file.json": b"{}",
            }
            completed, output, _summary = self.execute(
                block, root=root, completed_sha=docs_head, zip_entries=zip_entries
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            # Match the traced comparison across BOTH shells that run this
            # suite, without losing the "it was 2, not 1" evidence. `wc -l`
            # pads its output on macOS but not on GNU coreutils, and bash
            # quotes a traced word only when it needs to -- so the same
            # guard traces as `test '       2' -eq 1` locally and
            # `test 2 -eq 1` on the CI runner. Pinning either literal makes
            # the suite pass on one platform and fail on the other; this
            # regression cost one red CI run before it was caught.
            self.assertRegex(completed.stderr, r"test\s+'?\s*2'?\s+-eq\s+1")
            self.assertNotIn("class=", output)


    def test_lock_free_artifact_commit_after_the_gated_head_is_not_skipped(self):
        """An artifact change that moves no release lock must still deny.

        The four-lock equality check proves no LOCK moved; it cannot see an
        artifact change that touches none of them -- a code or workflow edit
        with no version bump. The anchor-advance walk then made that
        invisible change actively dangerous: it existed to step the anchor
        over the release push's own trailing artifact commits, and with a
        forged base it happily stepped over a LATER, unreleased one too,
        re-anchoring past it so the cumulative proof never saw it.

        History: [0.1.9] -> [M1 releases 0.1.10] -> [C changes code, no
        bump] -> [D docs]. The push is [C, D]; its true class is artifact.
        A verdict claiming base = C re-derives no-artifact, and every lock
        matches between M1 and D, so only the walk's cap can deny. It must.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, _base = self.repo(temporary)
            release_head = self.release_commit(root, "0.1.10")
            lock_free = self.paths_commit(
                root, {"cmd/site/main.go": "package main // changed\n"}, "lock-free artifact"
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": lock_free, "source_sha": docs_head}
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=self._pr_gate_runs([(500, release_head)]),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn("class=", output)
            self.assertNotIn("NO-ARTIFACT:", completed.stdout)

    def test_anchor_uses_the_newest_earlier_gated_run_not_the_oldest(self):
        """The run selection must be max_by(id); min_by would false-deny.

        Two earlier successful main runs exist: an older one at the 0.1.9
        release and a newer one at 0.1.10. Only the NEWEST is the correct
        anchor -- against it every lock matches and this documentation merge
        is allowed. Selecting the oldest instead compares 0.1.9's locks with
        0.1.10's, finds VERSION changed and denies a perfectly good merge.
        Both orderings deny the attacks, so only this success case tells
        max_by and min_by apart.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=self._pr_gate_runs([(400, base), (500, release_head)]),
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact", output)

    def test_previous_head_equal_to_the_completed_sha_denies(self):
        """The anchor must be a DIFFERENT commit, or it proves nothing.

        If the run history reports this very SHA as the newest earlier
        gated head, every downstream check passes vacuously: a commit's
        locks always equal their own, and a commit is always its own
        ancestor. The explicit inequality guard is what refuses that, and
        without a case reaching it the guard survives deletion untested.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, _base, release_head, docs_head = self._seed_documentation_push(temporary)
            self._install_release_contract(root)
            verdict = {"class": "no-artifact", "base_sha": release_head, "source_sha": docs_head}
            completed, output, _summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=self._pr_gate_runs([(500, docs_head)]),
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn("class=", output)

    #: The cumulative proof's base argument, and the one wrong value for it.
    #: Both halves are asserted present/unique before either is used, so a
    #: reworded workflow fails loudly instead of testing an unmutated block.
    CUMULATIVE_BASE = '--base "${anchor}" --head "${COMPLETED_SHA}"'
    CUMULATIVE_BASE_MUTANT = '--base "${boundary_sha}" --head "${COMPLETED_SHA}"'

    def test_rebase_release_with_trailing_artifact_commits_needs_the_advanced_anchor(self):
        """Issue #110: swapping the cumulative proof's base must go red.

        ``--base "${anchor}"`` versus ``--base "${boundary_sha}"`` is the
        entire difference between the shipped design and the one the prose
        keeps drifting back to, and until now the swap SURVIVED the whole
        suite. It survived because every other fixture here has anchor ==
        boundary_sha: their release push is a single bump commit, so the
        advance walk has nothing to step over and both arguments name the
        same commit. Only a rebase release with TRAILING artifact commits
        separates them.

        History, all first-parent:

            [0.1.9 base] -> [bump 0.1.10] -> [code] -> [docs]
                             \\____ one rebase-merged release push ____/

        The publisher tags the push HEAD, so ``code`` is both the tagged
        release commit and the last successfully gated main head. The
        advance walk must therefore land the anchor on ``code``; the
        recovered boundary stays at ``bump``. Classifying ``bump..docs``
        sees ``code``'s artifact change with no version bump and DENIES --
        a false denial of a perfectly good documentation merge -- while
        ``code..docs`` is documentation-only, which is the truth.

        The isolation this test needs is structural, not argued: the mutant
        block differs from the shipped block in exactly one argument, and
        the shipped run's exit 0 proves every preceding guard already
        passed on this same fixture. So the mutant's red can come from
        nothing else.
        """
        block = self.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory() as temporary:
            root, _base = self.repo(temporary)
            bump = self.release_commit(root, "0.1.10")
            code = self.paths_commit(
                root, {"cmd/site/main.go": "package main\n"}, "trailing code"
            )
            docs_head = self.paths_commit(root, {"AGENTS.md": "docs\n"}, "docs")
            self._install_release_contract(root)

            # The fixture genuinely discriminates: the two candidate bases
            # give OPPOSITE outcomes here. Without this the test could pass
            # for a reason unrelated to the argument under test.
            self.assertNotEqual(bump, code)
            self.assertEqual(
                RC.classify_transition(root, code, docs_head, first_parent=True)["class"],
                "no-artifact",
            )
            with self.assertRaises(RC.ContractError):
                RC.classify_transition(root, bump, docs_head, first_parent=True)

            verdict = {"class": "no-artifact", "base_sha": code, "source_sha": docs_head}
            pr_gate_runs = self._pr_gate_runs([(500, code)])
            completed, output, summary = self.execute(
                block,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=pr_gate_runs,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("class=no-artifact\n", output)
            self.assertIn("NO-ARTIFACT:", completed.stdout)
            self.assertIn("No-artifact merge", summary)
            # The shipped run never classifies from the un-advanced boundary.
            # This assertion, and the exit-0 one above, are what a WORKFLOW
            # already carrying the swap fails on -- a behavioural red, not a
            # bookkeeping one. The two below then keep the in-test mutation
            # well-defined so a reworded step cannot leave it a no-op.
            self.assertNotIn(f"--base {bump} --head {docs_head}", completed.stderr)
            self.assertEqual(
                block.count(self.CUMULATIVE_BASE),
                1,
                "the cumulative proof's base argument moved; re-anchor this test",
            )
            self.assertNotIn(self.CUMULATIVE_BASE_MUTANT, block)
            mutant = block.replace(self.CUMULATIVE_BASE, self.CUMULATIVE_BASE_MUTANT, 1)
            self.assertNotEqual(mutant, block)

            mutated, mutant_output, mutant_summary = self.execute(
                mutant,
                root=root,
                completed_sha=docs_head,
                verdict=verdict,
                pr_gate_runs=pr_gate_runs,
            )
            self.assertNotEqual(
                mutated.returncode, 0, mutated.stdout + mutated.stderr
            )
            # Red at the mutated line specifically: the trace shows the
            # boundary-based classification running, and nothing downstream
            # of it ever ran.
            self.assertIn(f"--base {bump} --head {docs_head}", mutated.stderr)
            self.assertNotIn("class=", mutant_output)
            self.assertNotIn("NO-ARTIFACT:", mutated.stdout)
            self.assertEqual(mutant_summary, "")


class ExistingImageShellPathTests(unittest.TestCase):
    @staticmethod
    def workflow_run_block(step_name: str) -> str:
        """One publisher step's run block, verbatim from the workflow."""
        return workflow_run_block("release-publisher.yml", step_name)

    @staticmethod
    def bash_executable() -> str:
        discovered = shutil.which("bash")
        if discovered:
            return discovered
        if os.name == "nt":
            candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe"
            if candidate.is_file():
                return str(candidate)
        raise AssertionError("bash is required to execute the release workflow shell path")

    @staticmethod
    def bash_path(path: str) -> str:
        normalized = Path(path).resolve().as_posix()
        if len(normalized) >= 3 and normalized[1:3] == ":/":
            return f"/{normalized[0].lower()}/{normalized[3:]}"
        return normalized

    def execute(
        self, block: str, *, arm64_builder_id: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        source = "https://github.com/owner/site"
        revision = "a" * 40
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            sbom_fixture = sbom_registry_fixture()
            (runner / "registry-index.json").write_bytes(sbom_fixture["index"])
            sbom_environment: dict[str, str] = {}
            for architecture in ("amd64", "arm64"):
                platform = f"linux/{architecture}"
                (runner / f"registry-attestation-{architecture}.json").write_bytes(
                    sbom_fixture["attestation_manifests"][platform]
                )
                (runner / f"registry-sbom-{architecture}.json").write_bytes(
                    sbom_fixture["statements"][platform]
                )
                sbom_environment[f"{architecture.upper()}_ATTESTATION_DIGEST"] = (
                    sbom_fixture["attestation_digests"][platform]
                )
                sbom_environment[f"{architecture.upper()}_SBOM_LAYER_DIGEST"] = (
                    "sha256:"
                    + hashlib.sha256(sbom_fixture["statements"][platform]).hexdigest()
                )
            for architecture in ("amd64", "arm64"):
                predicate = embedded_predicate(
                    source,
                    revision,
                    f"linux/{architecture}",
                    arm64_builder_id if architecture == "arm64" else None,
                )
                (runner / f"fixture-{architecture}.json").write_text(
                    json.dumps(predicate), encoding="utf-8"
                )
            output = runner / "github-output.txt"
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local expression='' input='' platform=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --arg)
        if [ "$2" = platform ]; then platform="$3"; fi
        shift 3
        ;;
      -*) shift ;;
      *)
        if [ -z "${expression}" ]; then
          expression="$1"
        else
          input="$1"
        fi
        shift
        ;;
    esac
  done
  case "${expression}" in
    '.token // .access_token')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); print(value.get("token") or value["access_token"])' "${input}"
      ;;
    'keys[]')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); sys.stdout.buffer.write(("\n".join(value.keys())+"\n").encode("utf-8"))' "${input}"
      ;;
    '.runDetails.builder.id')
      "${TEST_PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["runDetails"]["builder"]["id"])' "${input}"
      ;;
    '.[$platform].subject_digest'|'.[$platform].attestation_digest')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); field=sys.argv[3].rsplit(".",1)[-1]; print(value[sys.argv[2]][field])' "${input}" "${platform}" "${expression}"
      ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output='' headers='' url="${!#}"
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${url}" in
    *"/blobs/${AMD64_SBOM_LAYER_DIGEST}")
      cp "${RUNNER_TEMP}/registry-sbom-amd64.json" "${output}"
      return 0
      ;;
    *"/blobs/${ARM64_SBOM_LAYER_DIGEST}")
      cp "${RUNNER_TEMP}/registry-sbom-arm64.json" "${output}"
      return 0
      ;;
    *"/manifests/${AMD64_ATTESTATION_DIGEST}")
      cp "${RUNNER_TEMP}/registry-attestation-amd64.json" "${output}"
      ;;
    *"/manifests/${ARM64_ATTESTATION_DIGEST}")
      cp "${RUNNER_TEMP}/registry-attestation-arm64.json" "${output}"
      ;;
    *) cp "${RUNNER_TEMP}/registry-index.json" "${output}" ;;
  esac
  local digest
  digest="$(sha256sum "${output}" | awk '{print $1}')"
  printf 'docker-content-digest: sha256:%s\r\n' "${digest}" > "${headers}"
  printf '200'
}

docker() {
  case "$*" in
    *linux/amd64*) cat "${RUNNER_TEMP}/fixture-amd64.json" ;;
    *linux/arm64*) cat "${RUNNER_TEMP}/fixture-arm64.json" ;;
    *'.Provenance'*) printf '{"linux/amd64":{},"linux/arm64":{}}' ;;
    *'.SBOM'*) printf '{"linux/amd64":{},"linux/arm64":{}}' ;;
    *) return 2 ;;
  esac
}

cosign() {
  case "$1" in
    verify) return 0 ;;
    verify-attestation)
      "${TEST_PYTHON}" -c 'import base64,json,sys; [print(json.dumps({"payload":base64.b64encode(open(path,"rb").read()).decode("ascii")})) for path in sys.argv[1:]]' \
        "${RUNNER_TEMP}/existing-linux-amd64.statement.json" \
        "${RUNNER_TEMP}/existing-linux-arm64.statement.json"
      ;;
    *) return 2 ;;
  esac
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": self.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GITHUB_OUTPUT": f"{runner_relative}/github-output.txt",
                    "GITHUB_ACTOR": "release-fixture",
                    "GHCR_PASSWORD": "fixture-password",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "GITHUB_REPOSITORY": "owner/site",
                    "SOURCE_SHA": revision,
                    "GITHUB_REF": "refs/tags/v0.1.10",
                    "IMAGE": "ghcr.io/owner/site",
                    "TAG": "v0.1.10",
                }
            )
            environment.update(sbom_environment)
            completed = subprocess.run(
                [self.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            return completed, output.read_text(encoding="utf-8") if output.exists() else ""

    def test_actual_complete_image_retry_path_uses_validated_logical_count(self):
        block = self.workflow_run_block("Classify an absent, complete, or burned image tag")
        completed, output = self.execute(block)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("existing image state: complete", completed.stdout)
        self.assertIn("state=complete\n", output)
        self.assertRegex(output, r"digest=sha256:[0-9a-f]{64}\n")

        assignment = 'verified_count="${validated_count}"'
        self.assertIn(assignment, block)
        mutants = (
            block.replace(assignment, "", 1),
            block.replace(assignment, 'verified_count="${#expected_attestations[@]}"', 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(count_mutant=index):
                killed, _output = self.execute(mutant)
                self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
                self.assertIn("existing image state: burned", killed.stdout)

    def test_platform_predicates_naming_different_builder_runs_are_burned(self):
        # Issue #137, executed rather than read: the reuse path reads the run
        # identity ONCE, from the first platform's predicate, and requires it of
        # every platform. Two predicates that disagree about which run built
        # them are no longer a reusable image -- before this change both
        # satisfied the same repository-wide prefix and classified `complete`.
        block = self.workflow_run_block("Classify an absent, complete, or burned image tag")
        source = "https://github.com/owner/site"
        for name, builder_id in (
            ("different run in this repository", f"{source}/actions/runs/999"),
            ("run ID extended with more digits", f"{source}/actions/runs/{BUILDER_RUN_ID}9"),
            ("foreign repository", f"https://github.com/attacker/site/actions/runs/{BUILDER_RUN_ID}"),
            ("unexpected suffix after the run", f"{source}/actions/runs/{BUILDER_RUN_ID}/jobs/4"),
            ("attempt zero", f"{source}/actions/runs/{BUILDER_RUN_ID}/attempts/0"),
        ):
            with self.subTest(arm64_builder=name):
                killed, _output = self.execute(block, arm64_builder_id=builder_id)
                self.assertNotEqual(killed.returncode, 0, killed.stdout + killed.stderr)
                self.assertIn("existing image state: burned", killed.stdout)

    def test_the_measured_attempt_suffix_still_classifies_complete(self):
        # Both directions: BuildKit's real spelling on both platforms is the
        # accepted one, so the strengthened check cannot deny a genuine reuse.
        block = self.workflow_run_block("Classify an absent, complete, or burned image tag")
        completed, output = self.execute(
            block,
            arm64_builder_id=f"https://github.com/owner/site/actions/runs/{BUILDER_RUN_ID}/attempts/1",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("existing image state: complete", completed.stdout)
        self.assertIn("state=complete\n", output)


class ChartDigestEmbedShellPathTests(unittest.TestCase):
    """Execute the publisher's REAL chart steps over a sandboxed chart tree.

    Issue #111 acceptance 5 is a CROSS-STEP property and cannot be proven by
    reading either step alone: ONE substitution runs ahead of BOTH
    `helm package` invocations, so the classifier's reproducibility
    re-package and the publish step's archive are the same bytes. A fix that
    only edited the publish step would package the sentinel in the
    classifier, diff it against an already published chart carrying the real
    digest, and report a false `burned` on every idempotent re-run.

    The blocks are lifted verbatim from release-publisher.yml and executed in
    sequence against one sandbox, so the working-tree hand-off between steps
    is real rather than modelled. `helm`, `curl`, `jq`, and `cosign` are
    stubbed; `python3`, `tar`, `diff`, `awk`, and `sha256sum` are the real
    tools, so the release contract module, the archive round trip, and the
    tree comparison all execute for real.
    """

    SENTINEL = "sha256:" + "0" * 64
    RESOLVED = "sha256:" + "ab" * 32
    OTHER = "sha256:" + "cd" * 32
    CHART_DIGEST = "sha256:" + "ef" * 32

    EMBED_STEP = "Embed the resolved image digest into the chart values"
    CLASSIFY_STEP = "Classify an absent, complete, or burned chart version"
    PUBLISH_STEP = "Publish and sign an absent chart version"

    EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}")

    PRELUDE = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local expression='' input=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -*) shift ;;
      *)
        if [ -z "${expression}" ]; then expression="$1"; else input="$1"; fi
        shift
        ;;
    esac
  done
  case "${expression}" in
    '.token // .access_token') printf 'fixture-token\n' ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output='' headers=''
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}' > "${output}"
  printf 'docker-content-digest: sha256:%s\r\n' \
    "$(sha256sum "${output}" | awk '{print $1}')" > "${headers}"
  printf '%s' "${CHART_MANIFEST_STATUS}"
}

cosign() {
  case "$1" in
    verify) return "${COSIGN_VERIFY_STATUS}" ;;
    sign) return 0 ;;
    *) return 2 ;;
  esac
}

helm() {
  local subcommand="$1"
  shift
  case "${subcommand}" in
    package)
      local directory="$1" version='' destination='' name staging
      shift
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --version) version="$2"; shift 2 ;;
          --app-version) shift 2 ;;
          -d) destination="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      name="$(awk '/^name:/{print $2; exit}' "${directory}/Chart.yaml")"
      staging="$(mktemp -d)"
      mkdir -p "${staging}/${name}"
      cp -R "${directory}/." "${staging}/${name}/"
      tar -czf "${destination}/${name}-${version}.tgz" -C "${staging}" "${name}"
      rm -rf -- "${staging}"
      ;;
    pull)
      local destination=''
      while [ "$#" -gt 0 ]; do
        case "$1" in
          -d) destination="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cp "${PUBLISHED_CHART_ARCHIVE}" "${destination}/${PUBLISHED_CHART_NAME}"
      ;;
    push) printf 'Pushed: fixture\nDigest: %s\n' "${FIXTURE_CHART_DIGEST}" ;;
    registry) cat >/dev/null ;;
    *) return 2 ;;
  esac
}
'''

    @classmethod
    def run_block(cls, step_name: str) -> str:
        """Return one publisher step's run block, verbatim from the workflow."""
        return ExistingImageShellPathTests.workflow_run_block(step_name)

    def resolve(self, block: str, expressions: dict) -> str:
        """Replace every Actions expression, refusing to leave one behind.

        bash cannot evaluate `${{ ... }}`; an unresolved one becomes a "bad
        substitution" that would fail the step for a reason unrelated to the
        property under test, so an unmapped expression is a test error.
        """
        resolved = self.EXPRESSION_RE.sub(lambda match: expressions[match.group(0)], block)
        self.assertNotIn("${{", resolved)
        return resolved

    @contextlib.contextmanager
    def sandbox(self, published_digest: str):
        """Yield a chart working tree plus the archive `helm pull` returns."""
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".chart-digest-shell-") as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "chart", root / "chart")
            (root / "scripts" / "ci").mkdir(parents=True)
            shutil.copy2(
                ROOT / "scripts" / "ci" / "release_contract.py",
                root / "scripts" / "ci" / "release_contract.py",
            )
            (root / "runner").mkdir()
            name = RC._top_level_scalar((root / "chart" / "Chart.yaml").read_text(encoding="utf-8"), "name")
            version = RC._top_level_scalar((root / "chart" / "Chart.yaml").read_text(encoding="utf-8"), "version")
            # Built by plain text replacement, never by the function under
            # test: the fixture must be able to disagree with it.
            staging = root / "published-source" / name
            shutil.copytree(root / "chart", staging)
            values = staging / "values.yaml"
            values.write_text(
                values.read_text(encoding="utf-8").replace(self.SENTINEL, published_digest),
                encoding="utf-8",
            )
            archive = root / f"published-{name}-{version}.tgz"
            subprocess.run(
                ["tar", "-czf", str(archive), "-C", str(staging.parent), name],
                check=True,
                timeout=60,
            )
            yield {
                "root": root,
                "chart_name": name,
                "version": version,
                "archive": archive,
            }

    def execute(self, sandbox: dict, block: str, extra: dict | None = None):
        """Run one resolved run block with the publisher's own environment."""
        root = sandbox["root"]
        environment = os.environ.copy()
        environment.update(
            {
                "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                "RUNNER_TEMP": "runner",
                "GITHUB_OUTPUT": "runner/github-output.txt",
                "GITHUB_ACTOR": "release-fixture",
                "GHCR_PASSWORD": "fixture-password",
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REPOSITORY": "owner/site",
                "CHART": "ghcr.io/owner/charts/site",
                "VERSION": sandbox["version"],
                "DIGEST": self.RESOLVED,
                "CHART_MANIFEST_STATUS": "200",
                "COSIGN_VERIFY_STATUS": "0",
                "FIXTURE_CHART_DIGEST": self.CHART_DIGEST,
                "PUBLISHED_CHART_ARCHIVE": str(sandbox["archive"]),
                "PUBLISHED_CHART_NAME": f"{sandbox['chart_name']}-{sandbox['version']}.tgz",
            }
        )
        environment.update(extra or {})
        completed = subprocess.run(
            [ExistingImageShellPathTests.bash_executable()],
            cwd=root,
            env=environment,
            check=False,
            input=self.PRELUDE + "\n" + block,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        output = root / "runner" / "github-output.txt"
        return completed, output.read_text(encoding="utf-8") if output.exists() else ""

    def embed_block(self) -> str:
        return self.run_block(self.EMBED_STEP)

    def classify_block(self) -> str:
        return self.run_block(self.CLASSIFY_STEP)

    def publish_block(self, sandbox: dict) -> str:
        return self.resolve(
            self.run_block(self.PUBLISH_STEP),
            {
                "${{ steps.release.outputs.version }}": sandbox["version"],
                "${{ secrets.GITHUB_TOKEN }}": "fixture-password",
                "${{ github.actor }}": "release-fixture",
            },
        )

    def packaged_values(self, sandbox: dict) -> str:
        return (
            sandbox["root"] / "runner" / "packaged-chart-tree" / sandbox["chart_name"] / "values.yaml"
        ).read_text(encoding="utf-8")

    def test_one_substitution_serves_both_helm_package_invocations(self):
        with self.sandbox(self.RESOLVED) as sandbox:
            embed, _output = self.execute(sandbox, self.embed_block())
            self.assertEqual(embed.returncode, 0, embed.stdout + embed.stderr)
            working_tree = (sandbox["root"] / "chart" / "values.yaml").read_text(encoding="utf-8")
            self.assertNotIn(self.SENTINEL, working_tree)
            self.assertIn("\n  digest: " + self.RESOLVED + "\n", working_tree)

            classify, output = self.execute(sandbox, self.classify_block())
            self.assertEqual(classify.returncode, 0, classify.stdout + classify.stderr)
            self.assertIn("existing chart state: complete", classify.stdout)
            self.assertIn("state=complete\n", output)

            publish, output = self.execute(sandbox, self.publish_block(sandbox))
            self.assertEqual(publish.returncode, 0, publish.stdout + publish.stderr)
            self.assertIn(f"digest={self.CHART_DIGEST}\n", output)
            packaged = self.packaged_values(sandbox)
            self.assertNotIn(self.SENTINEL, packaged)
            self.assertIn("\n  digest: " + self.RESOLVED + "\n", packaged)

    def test_a_no_op_substitution_cannot_reach_a_published_chart(self):
        """The kill ladder for the mutation issue #111 names first.

        Each rung removes the guard that killed the previous one, so the
        deepest rung proves the reproducibility diff itself -- acceptance 5 --
        is load bearing rather than decorative.
        """
        embed = self.embed_block()
        neutered = re.sub(
            r"python3 -I -B scripts/ci/release_contract\.py chart-digest-embed \\\n"
            r" *--values chart/values\.yaml --digest \"\$\{DIGEST\}\"",
            "true",
            embed,
        )
        self.assertNotEqual(neutered, embed, "the substitution command must be mutable")
        self.assertNotIn("chart-digest-embed", neutered)

        classify = self.classify_block()
        assert_pattern = (
            r"python3 -I -B scripts/ci/release_contract\.py chart-digest-assert \\\n"
            r" *--values \"[^\"]+\" --digest \"\$\{DIGEST\}\"\n"
        )
        classify_unguarded = re.sub(assert_pattern, "", classify)
        self.assertNotIn("chart-digest-assert", classify_unguarded)

        # Rung 1: the substitution step re-reads what it wrote.
        with self.sandbox(self.RESOLVED) as sandbox:
            completed, _output = self.execute(sandbox, neutered)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("all-zeros fail-closed digest sentinel", completed.stderr)

        # Rung 2: with that gone, the classifier re-reads what IT packaged.
        neutered_unguarded = re.sub(
            r"\n *python3 -I -B scripts/ci/release_contract\.py chart-digest-assert \\\n"
            r" *--values chart/values\.yaml --digest \"\$\{DIGEST\}\"",
            "",
            neutered,
        )
        self.assertNotIn("chart-digest-assert", neutered_unguarded)
        with self.sandbox(self.RESOLVED) as sandbox:
            completed, _output = self.execute(sandbox, neutered_unguarded)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed, _output = self.execute(sandbox, classify)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("all-zeros fail-closed digest sentinel", completed.stderr)

        # Rung 3: with THAT gone too, the reproducibility diff still refuses
        # -- the classifier reports `burned` instead of a false `complete`.
        with self.sandbox(self.RESOLVED) as sandbox:
            completed, _output = self.execute(sandbox, neutered_unguarded)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed, output = self.execute(sandbox, classify_unguarded)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("existing chart state: burned", completed.stdout)
            self.assertNotIn("state=complete", output)

        # Rung 4: the publish path never depends on the classifier having run
        # -- an absent chart version skips it entirely, so its own re-read of
        # the archive is what stops a sentinel-bearing chart being pushed.
        with self.sandbox(self.RESOLVED) as sandbox:
            completed, _output = self.execute(sandbox, neutered_unguarded)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed, output = self.execute(sandbox, self.publish_block(sandbox))
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("all-zeros fail-closed digest sentinel", completed.stderr)
            self.assertNotIn("digest=", output)

    def test_a_malformed_digest_never_reaches_the_chart(self):
        block = self.embed_block()
        for name, digest in (
            ("63 hex characters", "sha256:" + "ab" * 31 + "a"),
            ("no sha256: prefix", "ab" * 32),
            ("upper-case hex", "sha256:" + "AB" * 32),
            ("the all-zeros sentinel", self.SENTINEL),
        ):
            with self.subTest(digest=name), self.sandbox(self.RESOLVED) as sandbox:
                before = (sandbox["root"] / "chart" / "values.yaml").read_text(encoding="utf-8")
                completed, _output = self.execute(sandbox, block, {"DIGEST": digest})
                self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(
                    (sandbox["root"] / "chart" / "values.yaml").read_text(encoding="utf-8"), before
                )

    def test_a_published_chart_carrying_another_digest_is_burned_not_complete(self):
        # Vacuity probe for the classifier: with the substitution in place,
        # the reproducibility diff must still be able to disagree.
        with self.sandbox(self.OTHER) as sandbox:
            completed, _output = self.execute(sandbox, self.embed_block())
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed, output = self.execute(sandbox, self.classify_block())
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("existing chart state: burned", completed.stdout)
            self.assertNotIn("state=complete", output)

    def test_an_absent_chart_version_never_packages_anything(self):
        with self.sandbox(self.RESOLVED) as sandbox:
            completed, _output = self.execute(sandbox, self.embed_block())
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            completed, output = self.execute(
                sandbox, self.classify_block(), {"CHART_MANIFEST_STATUS": "404"}
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("state=absent\n", output)


class MainAndCodeQLAuthorizationShellPathTests(unittest.TestCase):
    STEP = "Bind dispatch to one successful protected-main PR gate"
    SHA = "a" * 40

    @staticmethod
    def require_workflow_contract(gate: str, publisher: str) -> None:
        security = gate.split("\n  security:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
        dependency = gate.split("\n  dependency-review:\n", 1)[1].split(
            "\n  application:\n", 1
        )[0]
        container = gate.split("\n  container:\n", 1)[1]
        following = _NEXT_JOB.search(container)
        if following is not None:
            container = container[: following.start()]
        # Normalized keys, not raw text: `if :` is a live conditional the
        # runner honors, so `^    if:` would let the security job be skipped
        # (same fail-open class as the publisher gate's conditional pin).
        if "if" in normalized_keys(security, 4):
            raise ValueError("security main job may not be conditionally skipped")
        if "if: github.event_name == 'pull_request'" not in dependency:
            raise ValueError("dependency-review must be skipped only outside pull requests")
        # The container job is the other half of EXPECTED_MAIN_JOBS' two
        # `skipped` entries, and until this pin it was constrained in NEITHER
        # direction: it could gain any condition, or lose this one, without a
        # test noticing. Pin the exact declared VALUE, so an added condition,
        # a widened one (`always()`), an inverted one, a second `if`, or a
        # deletion each fail -- and a comment quoting the condition satisfies
        # nothing, because job_conditions reads keys rather than text.
        if job_conditions(container) != ["github.event_name == 'pull_request'"]:
            raise ValueError("container must build on pull requests only, by that exact condition")
        for required in (
            "main-jobs-record",
            "codeql-run-record",
            "codeql-jobs-record",
            "actions/workflows/codeql.yml/runs",
            "head_sha=\"${SOURCE_SHA}\"",
            "for attempt in {1..36}",
            "sleep 15",
            "jobs?filter=latest&per_page=100",
        ):
            if required not in publisher:
                raise ValueError(f"exact main/CodeQL authorization lost: {required}")

    def execute(
        self,
        block: str,
        *,
        main_jobs: dict[str, object] | None = None,
        codeql_run: dict[str, object] | None = None,
        codeql_jobs: dict[str, object] | None = None,
        pending_attempts: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".authorize-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            pending = codeql_run_record(self.SHA)
            pending["workflow_runs"][0]["status"] = "in_progress"
            pending["workflow_runs"][0]["conclusion"] = None
            fixtures = {
                "main-run.json": main_run_record(self.SHA),
                "main-jobs.json": main_jobs or main_jobs_record(self.SHA),
                "codeql-run.json": codeql_run or codeql_run_record(self.SHA),
                "codeql-pending.json": pending,
                "codeql-jobs.json": codeql_jobs or codeql_jobs_record(self.SHA),
            }
            for name, record in fixtures.items():
                (runner / name).write_text(json.dumps(record), encoding="utf-8")
            block = block.replace(
                "authority/scripts/ci/release_contract.py", "scripts/ci/release_contract.py"
            )
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

sleep() { :; }

gh() {
  local all="$*" count
  case "${all}" in
    *'/actions/runs/123/jobs?'*) cat "${RUNNER_TEMP}/main-jobs.json" ;;
    *'/actions/runs/123') cat "${RUNNER_TEMP}/main-run.json" ;;
    *'/actions/workflows/codeql.yml/runs'*)
      count=0
      if [ -f "${RUNNER_TEMP}/codeql-count" ]; then count="$(<"${RUNNER_TEMP}/codeql-count")"; fi
      count=$((count + 1))
      printf '%s\n' "${count}" > "${RUNNER_TEMP}/codeql-count"
      if [ "${count}" -le "${PENDING_ATTEMPTS}" ]; then
        cat "${RUNNER_TEMP}/codeql-pending.json"
      else
        cat "${RUNNER_TEMP}/codeql-run.json"
      fi
      ;;
    *'/actions/runs/456/jobs?'*) cat "${RUNNER_TEMP}/codeql-jobs.json" ;;
    *) return 2 ;;
  esac
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GITHUB_OUTPUT": f"{runner_relative}/github-output.txt",
                    "GITHUB_REPOSITORY": "owner/site",
                    "MAIN_RUN_ID": "123",
                    "SOURCE_SHA": self.SHA,
                    "PENDING_ATTEMPTS": str(pending_attempts),
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_exact_and_slow_exact_source_authorization_paths_pass(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        for pending_attempts in (0, 3):
            completed = self.execute(block, pending_attempts=pending_attempts)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_absent_failed_skipped_wrong_sha_duplicate_and_foreign_api_fixtures_fail(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        absent = {"total_count": 0, "workflow_runs": []}
        failed = codeql_run_record(self.SHA)
        failed["workflow_runs"][0]["conclusion"] = "failure"
        wrong_sha = codeql_run_record(self.SHA)
        wrong_sha["workflow_runs"][0]["head_sha"] = "b" * 40
        duplicate = codeql_run_record(self.SHA)
        duplicate["workflow_runs"].append(copy.deepcopy(duplicate["workflow_runs"][0]))
        duplicate["total_count"] = 2
        skipped_jobs = codeql_jobs_record(self.SHA)
        skipped_jobs["jobs"][0]["conclusion"] = "skipped"
        foreign_jobs = codeql_jobs_record(self.SHA)
        foreign_jobs["jobs"].append(copy.deepcopy(foreign_jobs["jobs"][0]))
        foreign_jobs["jobs"][-1]["id"] = 99
        foreign_jobs["jobs"][-1]["name"] = "foreign"
        foreign_jobs["total_count"] = 3
        skipped_security = main_jobs_record(self.SHA)
        next(job for job in skipped_security["jobs"] if job["name"] == "security")[
            "conclusion"
        ] = "skipped"
        cases = (
            {"codeql_run": absent},
            {"codeql_run": failed},
            {"codeql_run": wrong_sha},
            {"codeql_run": duplicate},
            {"codeql_jobs": skipped_jobs},
            {"codeql_jobs": foreign_jobs},
            {"main_jobs": skipped_security},
        )
        for index, kwargs in enumerate(cases):
            with self.subTest(api_mutant=index):
                completed = self.execute(block, **kwargs)
                self.assertNotEqual(completed.returncode, 0)

    def test_if_false_and_authorization_deletion_mutants_are_killed(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(
            encoding="utf-8"
        )
        self.require_workflow_contract(gate, publisher)
        # The container job's own header lines, anchored on its unique
        # 45-minute deadline so no replacement can land on dependency-review's
        # identical condition earlier in the file.
        container_head = (
            "    if: github.event_name == 'pull_request'\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 45\n"
        )
        self.assertEqual(gate.count(container_head), 1)

        def container_mutant(replacement: str) -> str:
            return gate.replace(container_head, replacement, 1)

        mutants = (
            (gate.replace("  security:\n", "  security:\n    if: false\n", 1), publisher),
            # Same fail-open spelling class as the publisher gate's
            # conditional pin: a raw `^    if:` assertion does not see these,
            # but the Actions runner honors both and skips the job.
            (gate.replace("  security:\n", "  security:\n    if : false\n", 1), publisher),
            (gate.replace("  security:\n", '  security:\n    "if": false\n', 1), publisher),
            (gate, publisher.replace("main-jobs-record", "deleted-main-jobs", 1)),
            (gate, publisher.replace("codeql-run-record", "deleted-codeql-run", 1)),
            (gate, publisher.replace("codeql-jobs-record", "deleted-codeql-jobs", 1)),
            (gate, publisher.replace('head_sha="${SOURCE_SHA}"', 'head_sha="foreign"', 1)),
            (gate, publisher.replace("for attempt in {1..36}", "for attempt in 1", 1)),
            # container rebuilds the merged tree on every main push again:
            # the condition is deleted outright.
            (
                container_mutant(
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n"
                ),
                publisher,
            ),
            # ... or survives only as prose. A raw-text pin would accept this;
            # reading declared keys refuses it.
            (
                container_mutant(
                    "    # if: github.event_name == 'pull_request'\n"
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n"
                ),
                publisher,
            ),
            # ... or is inverted, which builds on exactly the push the change
            # exists to stop building on.
            (
                container_mutant(
                    "    if: github.event_name == 'push'\n"
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n"
                ),
                publisher,
            ),
            # ... or is widened to a condition that is never false.
            (
                container_mutant(
                    "    if: always()\n    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n"
                ),
                publisher,
            ),
            # ... or gains a second declaration whose alternate spelling the
            # runner honors and which wins as the later key.
            (
                container_mutant(
                    "    if: github.event_name == 'pull_request'\n"
                    "    if : always()\n"
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n"
                ),
                publisher,
            ),
        )
        for index, (mutant_gate, mutant_publisher) in enumerate(mutants):
            with self.subTest(static_mutant=index), self.assertRaises(ValueError):
                self.require_workflow_contract(mutant_gate, mutant_publisher)


class RegistryAliasRebindShellPathTests(unittest.TestCase):
    STEP = "Re-bind both public aliases and exact platform SBOMs before sealing evidence"

    @staticmethod
    def require_step_contract(block: str) -> None:
        for required in (
            'fetch_exact_alias "${image_repository}" "${IMAGE_ALIAS}"',
            'image "${IMAGE_DIGEST}" "${image_token}"',
            'fetch_exact_alias "${chart_repository}" "${CHART_ALIAS}"',
            'chart "${CHART_DIGEST}" "${chart_token}"',
            "for attempt in 1 2 3 4 5",
            'test "${observed}" = "${expected}"',
            "sbom-index-record",
            "sbom-layer-record",
            "sbom-statement",
            "for platform in linux/amd64 linux/arm64",
        ):
            if required not in block:
                raise ValueError(f"post-push alias/SBOM binding lost: {required}")

    def execute(
        self,
        block: str,
        *,
        image_state: str = "exact",
        chart_state: str = "exact",
    ) -> subprocess.CompletedProcess[str]:
        fixture = sbom_registry_fixture()
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".alias-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            (runner / "registry-index.json").write_bytes(fixture["index"])
            chart_bytes = b'{"schemaVersion":2,"artifact":"chart"}'
            foreign_bytes = b'{"schemaVersion":2,"artifact":"foreign"}'
            (runner / "registry-chart.json").write_bytes(chart_bytes)
            (runner / "registry-foreign.json").write_bytes(foreign_bytes)
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GITHUB_ACTOR": "release-fixture",
                    "GHCR_PASSWORD": "fixture-password",
                    "IMAGE": "ghcr.io/owner/site",
                    "CHART": "ghcr.io/owner/charts/site",
                    "IMAGE_ALIAS": "v0.1.10",
                    "CHART_ALIAS": "0.1.10",
                    "IMAGE_DIGEST": fixture["image_digest"],
                    "CHART_DIGEST": "sha256:" + hashlib.sha256(chart_bytes).hexdigest(),
                    "IMAGE_ALIAS_STATE": image_state,
                    "CHART_ALIAS_STATE": chart_state,
                }
            )
            for architecture in ("amd64", "arm64"):
                platform = f"linux/{architecture}"
                (runner / f"registry-attestation-{architecture}.json").write_bytes(
                    fixture["attestation_manifests"][platform]
                )
                (runner / f"registry-sbom-{architecture}.json").write_bytes(
                    fixture["statements"][platform]
                )
                environment[f"{architecture.upper()}_ATTESTATION_DIGEST"] = fixture[
                    "attestation_digests"
                ][platform]
                environment[f"{architecture.upper()}_SBOM_LAYER_DIGEST"] = (
                    "sha256:" + hashlib.sha256(fixture["statements"][platform]).hexdigest()
                )
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local expression='' input='' platform=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --arg)
        if [ "$2" = platform ]; then platform="$3"; fi
        shift 3
        ;;
      -*) shift ;;
      *)
        if [ -z "${expression}" ]; then expression="$1"; else input="$1"; fi
        shift
        ;;
    esac
  done
  case "${expression}" in
    '.token // .access_token')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); print(value.get("token") or value["access_token"])' "${input}"
      ;;
    '.[$platform].subject_digest'|'.[$platform].attestation_digest')
      "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); field=sys.argv[3].rsplit(".",1)[-1]; print(value[sys.argv[2]][field])' "${input}" "${platform}" "${expression}"
      ;;
    *) return 2 ;;
  esac
}

sleep() { :; }

serve_manifest() {
  local source="$1" output="$2" headers="$3" digest
  cp "${source}" "${output}"
  digest="$(sha256sum "${output}" | awk '{print $1}')"
  printf 'docker-content-digest: sha256:%s\r\n' "${digest}" > "${headers}"
  printf '200'
}

curl() {
  local all="$*" output='' headers='' url="${!#}"
  if [[ "${all}" == *'https://ghcr.io/token'* ]]; then
    printf '{"token":"fixture-token"}'
    return 0
  fi
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      --dump-header) headers="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${url}" in
    *"/blobs/${AMD64_SBOM_LAYER_DIGEST}") cp "${RUNNER_TEMP}/registry-sbom-amd64.json" "${output}" ;;
    *"/blobs/${ARM64_SBOM_LAYER_DIGEST}") cp "${RUNNER_TEMP}/registry-sbom-arm64.json" "${output}" ;;
    *"/manifests/${AMD64_ATTESTATION_DIGEST}") serve_manifest "${RUNNER_TEMP}/registry-attestation-amd64.json" "${output}" "${headers}" ;;
    *"/manifests/${ARM64_ATTESTATION_DIGEST}") serve_manifest "${RUNNER_TEMP}/registry-attestation-arm64.json" "${output}" "${headers}" ;;
    *'/owner/site/manifests/v0.1.10')
      if [ "${IMAGE_ALIAS_STATE}" = absent ]; then : > "${output}"; : > "${headers}"; printf '404'
      elif [ "${IMAGE_ALIAS_STATE}" = retarget ]; then serve_manifest "${RUNNER_TEMP}/registry-foreign.json" "${output}" "${headers}"
      else serve_manifest "${RUNNER_TEMP}/registry-index.json" "${output}" "${headers}"
      fi
      ;;
    *'/owner/charts/site/manifests/0.1.10')
      if [ "${CHART_ALIAS_STATE}" = absent ]; then : > "${output}"; : > "${headers}"; printf '404'
      elif [ "${CHART_ALIAS_STATE}" = retarget ]; then serve_manifest "${RUNNER_TEMP}/registry-foreign.json" "${output}" "${headers}"
      else serve_manifest "${RUNNER_TEMP}/registry-chart.json" "${output}" "${headers}"
      fi
      ;;
    *) : > "${output}"; if [ -n "${headers}" ]; then : > "${headers}"; fi; printf '500' ;;
  esac
}
'''
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_actual_post_push_image_chart_alias_and_sbom_path_is_exact(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        self.require_step_contract(block)
        completed = self.execute(block)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_deleted_retargeted_and_foreign_aliases_are_executable_denials(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        for image_state, chart_state in (
            ("absent", "exact"),
            ("retarget", "exact"),
            ("exact", "absent"),
            ("exact", "retarget"),
        ):
            with self.subTest(image=image_state, chart=chart_state):
                completed = self.execute(
                    block, image_state=image_state, chart_state=chart_state
                )
                self.assertNotEqual(completed.returncode, 0)
        for mutant in (
            block.replace(
                '"${image_repository}" "${IMAGE_ALIAS}"',
                '"${image_repository}" "${CHART_ALIAS}"',
                1,
            ),
            block.replace(
                '"${chart_repository}" "${CHART_ALIAS}"',
                '"${chart_repository}" "${IMAGE_ALIAS}"',
                1,
            ),
        ):
            completed = self.execute(mutant)
            self.assertNotEqual(completed.returncode, 0)

    def test_deletion_inversion_and_digest_mutants_are_killed_structurally(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        mutants = (
            block.replace(
                'fetch_exact_alias "${image_repository}" "${IMAGE_ALIAS}"',
                'true # deleted image alias check',
                1,
            ),
            block.replace(
                'fetch_exact_alias "${chart_repository}" "${CHART_ALIAS}"',
                'true # deleted chart alias check',
                1,
            ),
            block.replace('test "${observed}" = "${expected}"', "true", 1),
            block.replace('"${IMAGE_ALIAS}"', '"${CHART_ALIAS}"', 1),
            block.replace('"${CHART_ALIAS}"', '"${IMAGE_ALIAS}"', 1),
            block.replace('image "${IMAGE_DIGEST}"', 'image "${CHART_DIGEST}"', 1),
            block.replace('chart "${CHART_DIGEST}"', 'chart "${IMAGE_DIGEST}"', 1),
        )
        for index, mutant in enumerate(mutants):
            with self.subTest(static_mutant=index), self.assertRaises(ValueError):
                self.require_step_contract(mutant)


class TerminalTagRebindShellPathTests(unittest.TestCase):
    SOURCE = "a" * 40
    MOVED_SOURCE = "c" * 40
    TAG_OBJECT = "b" * 40
    TAG = "v0.1.10"
    DATE = "2026-08-13T15:21:32Z"

    def execute(self, block: str, *, target: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".terminal-tag-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            manifest_record = exact_release_manifest(source=self.SOURCE)
            manifest = canonical_manifest_bytes(manifest_record)
            manifest_name = f"hospedajedonlolo-com-{self.TAG}-release-manifest.json"
            manifest_path = runner / manifest_name
            manifest_path.write_bytes(manifest)
            notes = RC.build_release_notes(manifest_record)
            (runner / "release-notes.md").write_text(notes, encoding="utf-8")
            (runner / "release-fixture.json").write_text(
                json.dumps(exact_release_record(manifest, tag=self.TAG, body=notes)),
                encoding="utf-8",
            )
            block = block.replace(
                "${{ steps.manifest.outputs.path }}", f"{runner_relative}/{manifest_name}"
            ).replace("${{ steps.manifest.outputs.name }}", manifest_name)
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local all="$*"
  case "${all}" in
    *'.object.sha'*) printf '%s\n' "${TAG_OBJECT_SHA}" ;;
    *'.assets | select(length == 1)'*) printf '%s\n' 'https://api.github.test/assets/1' ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${all}" in
    *'/releases/tags/'*)
      cp "${RUNNER_TEMP}/release-fixture.json" "${output}"
      ;;
    *'api.github.test/assets/1'*)
      cp "${RUNNER_TEMP}/hospedajedonlolo-com-v0.1.10-release-manifest.json" "${output}"
      return 0
      ;;
    *'/git/ref/tags/'*)
      printf '{"ref":"refs/tags/%s","object":{"type":"tag","sha":"%s"}}' \
        "${TAG}" "${TAG_OBJECT_SHA}" > "${output}"
      ;;
    *'/git/tags/'*)
      printf '{"sha":"%s","tag":"%s","message":"Release %s from %s","object":{"type":"commit","sha":"%s"},"tagger":{"name":"github-actions[bot]","email":"41898282+github-actions[bot]@users.noreply.github.com","date":"%s"}}' \
        "${TAG_OBJECT_SHA}" "${TAG}" "${TAG}" "${SOURCE_SHA}" \
        "${TAG_TARGET_SHA}" "${TAGGER_DATE}" > "${output}"
      ;;
    *) return 2 ;;
  esac
  printf '200'
}

git() {
  test "$1" = show
  printf '%s\n' "${TAGGER_DATE}"
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "SOURCE_SHA": self.SOURCE,
                    "TAG_TARGET_SHA": target,
                    "TAG_OBJECT_SHA": self.TAG_OBJECT,
                    "TAGGER_DATE": self.DATE,
                    "TAG": self.TAG,
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable(), "-c", prelude + "\n" + block],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def execute_concurrent_winner_transaction(
        self, *, terminal_target: str
    ) -> subprocess.CompletedProcess[str]:
        initial = ExistingImageShellPathTests.workflow_run_block(
            "Create or verify the exact annotated tag"
        )
        release = ExistingImageShellPathTests.workflow_run_block(
            "Stage, verify, and publish the exact GitHub release"
        )
        terminal = ExistingImageShellPathTests.workflow_run_block(
            "Re-bind the immutable Release to the exact annotated tag"
        )
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-race-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            manifest_record = RC.build_release_manifest(
                repository=RC.EXPECTED_REPOSITORY,
                source_sha=self.SOURCE,
                main_run_id=123,
                version="0.1.10",
                image=RC.EXPECTED_IMAGE,
                image_digest="sha256:" + "d" * 64,
                chart=RC.EXPECTED_CHART,
                chart_digest="sha256:" + "e" * 64,
            )
            manifest = canonical_manifest_bytes(manifest_record)
            manifest_name = f"hospedajedonlolo-com-{self.TAG}-release-manifest.json"
            (runner / manifest_name).write_bytes(manifest)
            notes = RC.build_release_notes(manifest_record)
            (runner / "release-fixture.json").write_text(
                json.dumps(exact_release_record(manifest, tag=self.TAG, body=notes)),
                encoding="utf-8",
            )
            replacements = {
                "${{ steps.release.outputs.tag }}": self.TAG,
                "${{ steps.release.outputs.version }}": "0.1.10",
                "${{ steps.image.outputs.digest }}": "sha256:" + "d" * 64,
                "${{ steps.chart.outputs.digest }}": "sha256:" + "e" * 64,
                "${{ steps.manifest.outputs.path }}": f"{runner_relative}/{manifest_name}",
                "${{ steps.manifest.outputs.name }}": manifest_name,
            }
            for old, new in replacements.items():
                release = release.replace(old, new)
                terminal = terminal.replace(old, new)
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local all="$*"
  case "${all}" in
    *'.object.sha'*) printf '%s\n' "${TAG_OBJECT_SHA}" ;;
    *'.assets | select(length == 1)'*) printf '%s\n' 'https://api.github.test/assets/1' ;;
    *'] | length'*)
      # The list-probe fixture below always answers empty on the calls
      # where by-tag still 404s, so nothing under this tag ever counts.
      printf '0\n'
      ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${all}" in
    *'/releases/tags/'*)
      local release_count=0
      if [ -f "${RUNNER_TEMP}/release-count" ]; then
        release_count="$(<"${RUNNER_TEMP}/release-count")"
      fi
      release_count=$((release_count + 1))
      printf '%s\n' "${release_count}" > "${RUNNER_TEMP}/release-count"
      if [ "${release_count}" -le 2 ]; then
        printf '{}' > "${output}"
        printf '404'
      else
        cp "${RUNNER_TEMP}/release-fixture.json" "${output}"
        printf '200'
      fi
      ;;
    *'releases?per_page=100'*)
      # Nothing exists under this tag yet on the calls where by-tag still
      # 404s (release_count <= 2 above); the classify_release list-probe
      # correctly reads that as absent, same as before this fixture's
      # by-tag endpoint eventually catches up on the third call.
      printf '[]' > "${output}"
      printf '200'
      ;;
    *'api.github.test/assets/1'*)
      cp "${RUNNER_TEMP}/hospedajedonlolo-com-v0.1.10-release-manifest.json" "${output}"
      return 0
      ;;
    *'/git/ref/tags/'*)
      printf '{"ref":"refs/tags/%s","object":{"type":"tag","sha":"%s"}}' \
        "${TAG}" "${TAG_OBJECT_SHA}" > "${output}"
      printf '200'
      ;;
    *'/git/tags/'*)
      local object_count=0 target="${SOURCE_SHA}"
      if [ -f "${RUNNER_TEMP}/tag-object-count" ]; then
        object_count="$(<"${RUNNER_TEMP}/tag-object-count")"
      fi
      object_count=$((object_count + 1))
      printf '%s\n' "${object_count}" > "${RUNNER_TEMP}/tag-object-count"
      if [ "${object_count}" -gt 1 ]; then
        target="${TERMINAL_TAG_TARGET_SHA}"
      fi
      printf '{"sha":"%s","tag":"%s","message":"Release %s from %s","object":{"type":"commit","sha":"%s"},"tagger":{"name":"github-actions[bot]","email":"41898282+github-actions[bot]@users.noreply.github.com","date":"%s"}}' \
        "${TAG_OBJECT_SHA}" "${TAG}" "${TAG}" "${SOURCE_SHA}" \
        "${target}" "${TAGGER_DATE}" > "${output}"
      printf '200'
      ;;
    *) return 2 ;;
  esac
}

gh() {
  test "$1" = release
  test "$2" = create
  return 1
}

git() {
  test "$1" = show
  printf '%s\n' "${TAGGER_DATE}"
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "SOURCE_SHA": self.SOURCE,
                    "MAIN_RUN_ID": "123",
                    "TERMINAL_TAG_TARGET_SHA": terminal_target,
                    "TAG_OBJECT_SHA": self.TAG_OBJECT,
                    "TAGGER_DATE": self.DATE,
                    "TAG": self.TAG,
                    "IMAGE": RC.EXPECTED_IMAGE,
                    "CHART": RC.EXPECTED_CHART,
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + initial + "\n" + release + "\n" + terminal,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def execute_staged_manifest_transaction(
        self, block: str, *, corrupt_first_download: bool
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-manifest-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            manifest_record = RC.build_release_manifest(
                repository=RC.EXPECTED_REPOSITORY,
                source_sha=self.SOURCE,
                main_run_id=123,
                version="0.1.10",
                image=RC.EXPECTED_IMAGE,
                image_digest="sha256:" + "d" * 64,
                chart=RC.EXPECTED_CHART,
                chart_digest="sha256:" + "e" * 64,
            )
            manifest = canonical_manifest_bytes(manifest_record)
            manifest_name = f"hospedajedonlolo-com-{self.TAG}-release-manifest.json"
            (runner / manifest_name).write_bytes(manifest)
            notes = RC.build_release_notes(manifest_record)
            (runner / "prepared-release.json").write_text(
                json.dumps(exact_release_record(manifest, tag=self.TAG, state="prepared", body=notes)),
                encoding="utf-8",
            )
            (runner / "staged-release.json").write_text(
                json.dumps(exact_release_record(manifest, tag=self.TAG, state="staged", body=notes)),
                encoding="utf-8",
            )
            (runner / "exact-release.json").write_text(
                json.dumps(exact_release_record(manifest, tag=self.TAG, body=notes)),
                encoding="utf-8",
            )
            replacements = {
                "${{ steps.release.outputs.tag }}": self.TAG,
                "${{ steps.release.outputs.version }}": "0.1.10",
                "${{ steps.image.outputs.digest }}": "sha256:" + "d" * 64,
                "${{ steps.chart.outputs.digest }}": "sha256:" + "e" * 64,
                "${{ steps.manifest.outputs.path }}": f"{runner_relative}/{manifest_name}",
                "${{ steps.manifest.outputs.name }}": manifest_name,
            }
            for old, new in replacements.items():
                block = block.replace(old, new)
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  local all="$*" state='absent'
  if [ -f "${RUNNER_TEMP}/release-state" ]; then
    state="$(<"${RUNNER_TEMP}/release-state")"
  fi
  case "${all}" in
    *'.assets | select(length == 1)'*) printf '%s\n' 'https://api.github.test/assets/1' ;;
    *'] | length'*)
      if [ "${state}" = absent ]; then printf '0\n'; else printf '1\n'; fi
      ;;
    *'select(.tag_name == $tag)'*) cat "${RUNNER_TEMP}/${state}-release.json" ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output='' state='absent'
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  if [ -f "${RUNNER_TEMP}/release-state" ]; then
    state="$(<"${RUNNER_TEMP}/release-state")"
  fi
  case "${all}" in
    *'/releases/tags/'*)
      # Real GitHub: by-tag finds a PUBLISHED release only. An unpublished
      # draft (prepared/staged) 404s here exactly like a genuinely absent
      # Release, so classify_release's list-probe fallback is exercised
      # the same way it is against the real API.
      if [ "${state}" = absent ] || [ "${state}" = prepared ] || [ "${state}" = staged ]; then
        printf '{}' > "${output}"
        printf '404'
      else
        cp "${RUNNER_TEMP}/${state}-release.json" "${output}"
        printf '200'
      fi
      ;;
    *'releases?per_page=100'*)
      if [ "${state}" = absent ]; then
        printf '[]' > "${output}"
      else
        printf '[' > "${output}"
        cat "${RUNNER_TEMP}/${state}-release.json" >> "${output}"
        printf ']' >> "${output}"
      fi
      printf '200'
      ;;
    *'api.github.test/assets/1'*)
      local count=0
      if [ -f "${RUNNER_TEMP}/asset-count" ]; then
        count="$(<"${RUNNER_TEMP}/asset-count")"
      fi
      count=$((count + 1))
      printf '%s\n' "${count}" > "${RUNNER_TEMP}/asset-count"
      cp "${RUNNER_TEMP}/hospedajedonlolo-com-v0.1.10-release-manifest.json" "${output}"
      if [ "${CORRUPT_FIRST_DOWNLOAD}" = true ] && [ "${state}" = staged ]; then
        printf 'foreign\n' >> "${output}"
      fi
      ;;
    *) return 2 ;;
  esac
}

gh() {
  test "$1" = release
  printf '%s\n' "$2" >> "${RUNNER_TEMP}/gh-calls"
  case "$2" in
    create)
      printf 'prepared\n' > "${RUNNER_TEMP}/release-state"
      return 1
      ;;
    upload)
      printf 'staged\n' > "${RUNNER_TEMP}/release-state"
      return 1
      ;;
    edit)
      printf 'exact\n' > "${RUNNER_TEMP}/release-state"
      return 1
      ;;
    *) return 2 ;;
  esac
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "SOURCE_SHA": self.SOURCE,
                    "MAIN_RUN_ID": "123",
                    "IMAGE": RC.EXPECTED_IMAGE,
                    "CHART": RC.EXPECTED_CHART,
                    "CORRUPT_FIRST_DOWNLOAD": "true" if corrupt_first_download else "false",
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            calls = (runner / "gh-calls").read_text(encoding="utf-8") if (runner / "gh-calls").exists() else ""
            return completed, calls

    def test_actual_terminal_step_rejects_a_tag_moved_before_immutable_publication(self):
        block = ExistingImageShellPathTests.workflow_run_block(
            "Re-bind the immutable Release to the exact annotated tag"
        )
        exact = self.execute(block, target=self.SOURCE)
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertIn("exact", exact.stdout)

        moved = self.execute(block, target=self.MOVED_SOURCE)
        self.assertNotEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertIn("annotated tag target is not the exact source commit", moved.stderr)

        marker = "python3 -I -B scripts/ci/release_contract.py tag-record"
        prefix, separator, _validator = block.partition(marker)
        self.assertEqual(separator, marker)
        deletion_mutant = prefix + "true\n"
        survived_without_rebind = self.execute(deletion_mutant, target=self.MOVED_SOURCE)
        self.assertEqual(
            survived_without_rebind.returncode,
            0,
            survived_without_rebind.stdout + survived_without_rebind.stderr,
        )

    def test_concurrent_release_winner_rebinds_after_an_initially_exact_tag(self):
        exact = self.execute_concurrent_winner_transaction(terminal_target=self.SOURCE)
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertIn("checking exact server state", exact.stderr)

        moved = self.execute_concurrent_winner_transaction(terminal_target=self.MOVED_SOURCE)
        self.assertNotEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertIn("checking exact server state", moved.stderr)
        self.assertIn("annotated tag target is not the exact source commit", moved.stderr)

    def test_actual_draft_manifest_is_verified_before_publish_and_response_loss_resumes(self):
        block = ExistingImageShellPathTests.workflow_run_block(
            "Stage, verify, and publish the exact GitHub release"
        )
        exact, calls = self.execute_staged_manifest_transaction(
            block, corrupt_first_download=False
        )
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertEqual(calls, "create\nupload\nedit\n")
        self.assertIn("draft Release create did not succeed; checking exact server state", exact.stderr)
        self.assertIn("manifest upload did not succeed; checking exact server state", exact.stderr)
        self.assertIn("draft publication did not succeed; checking exact server state", exact.stderr)

        corrupt, corrupt_calls = self.execute_staged_manifest_transaction(
            block, corrupt_first_download=True
        )
        self.assertNotEqual(corrupt.returncode, 0, corrupt.stdout + corrupt.stderr)
        self.assertEqual(corrupt_calls, "create\nupload\n")

        prepublish = '  verify_asset_bytes\n  if ! gh release edit "${tag}" --draft=false; then'
        self.assertIn(prepublish, block)
        deletion_mutant = block.replace(
            prepublish,
            '  true\n  if ! gh release edit "${tag}" --draft=false; then',
            1,
        )
        survived, survived_calls = self.execute_staged_manifest_transaction(
            deletion_mutant, corrupt_first_download=True
        )
        self.assertEqual(survived.returncode, 0, survived.stdout + survived.stderr)
        self.assertEqual(survived_calls, "create\nupload\nedit\n")

    def test_actual_ambiguous_stray_drafts_are_denied_not_guessed(self):
        # Real GitHub lets more than one draft Release share a tag_name
        # (neither is the published owner of the ref, so by-tag 404s on all
        # of them). classify_release's list-probe must refuse to guess
        # which stray draft is "the" release rather than silently picking
        # one — and must deny before ever attempting a create/upload/edit
        # that could produce a THIRD stray draft under the same tag.
        block = ExistingImageShellPathTests.workflow_run_block(
            "Stage, verify, and publish the exact GitHub release"
        )
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".ambiguous-draft-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            manifest_record = RC.build_release_manifest(
                repository=RC.EXPECTED_REPOSITORY,
                source_sha=self.SOURCE,
                main_run_id=123,
                version="0.1.10",
                image=RC.EXPECTED_IMAGE,
                image_digest="sha256:" + "d" * 64,
                chart=RC.EXPECTED_CHART,
                chart_digest="sha256:" + "e" * 64,
            )
            manifest = canonical_manifest_bytes(manifest_record)
            manifest_name = f"hospedajedonlolo-com-{self.TAG}-release-manifest.json"
            (runner / manifest_name).write_bytes(manifest)
            replacements = {
                "${{ steps.release.outputs.tag }}": self.TAG,
                "${{ steps.release.outputs.version }}": "0.1.10",
                "${{ steps.image.outputs.digest }}": "sha256:" + "d" * 64,
                "${{ steps.chart.outputs.digest }}": "sha256:" + "e" * 64,
                "${{ steps.manifest.outputs.path }}": f"{runner_relative}/{manifest_name}",
                "${{ steps.manifest.outputs.name }}": manifest_name,
            }
            for old, new in replacements.items():
                block = block.replace(old, new)
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  case "$*" in
    *'] | length'*) printf '2\n' ;;
    *) return 2 ;;
  esac
}

curl() {
  local all="$*" output=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${all}" in
    *'/releases/tags/'*)
      printf '{}' > "${output}"
      printf '404'
      ;;
    *'releases?per_page=100'*)
      printf '[{"tag_name":"v0.1.10"},{"tag_name":"v0.1.10"}]' > "${output}"
      printf '200'
      ;;
    *) return 2 ;;
  esac
}

gh() {
  printf 'unexpected gh call: %s\n' "$*" >&2
  return 2
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "SOURCE_SHA": self.SOURCE,
                    "MAIN_RUN_ID": "123",
                    "IMAGE": RC.EXPECTED_IMAGE,
                    "CHART": RC.EXPECTED_CHART,
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("DENY: 2 Releases share tag v0.1.10", completed.stderr)
        self.assertIn("a stranded draft needs operator resolution", completed.stderr)

    def test_actual_failed_list_probe_denies_rather_than_falls_through(self):
        # classify_release normally runs inside `$(...)`, where bash does
        # not apply -e to an intermediate command's failure. A bare `test`
        # on a bad list-probe response would silently fall through to an
        # empty match count rather than stop, so the guard must be an
        # explicit exit — proven here by making the list probe itself fail.
        block = ExistingImageShellPathTests.workflow_run_block(
            "Stage, verify, and publish the exact GitHub release"
        )
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".list-probe-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            manifest_record = RC.build_release_manifest(
                repository=RC.EXPECTED_REPOSITORY,
                source_sha=self.SOURCE,
                main_run_id=123,
                version="0.1.10",
                image=RC.EXPECTED_IMAGE,
                image_digest="sha256:" + "d" * 64,
                chart=RC.EXPECTED_CHART,
                chart_digest="sha256:" + "e" * 64,
            )
            manifest = canonical_manifest_bytes(manifest_record)
            manifest_name = f"hospedajedonlolo-com-{self.TAG}-release-manifest.json"
            (runner / manifest_name).write_bytes(manifest)
            replacements = {
                "${{ steps.release.outputs.tag }}": self.TAG,
                "${{ steps.release.outputs.version }}": "0.1.10",
                "${{ steps.image.outputs.digest }}": "sha256:" + "d" * 64,
                "${{ steps.chart.outputs.digest }}": "sha256:" + "e" * 64,
                "${{ steps.manifest.outputs.path }}": f"{runner_relative}/{manifest_name}",
                "${{ steps.manifest.outputs.name }}": manifest_name,
            }
            for old, new in replacements.items():
                block = block.replace(old, new)
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}

jq() {
  printf 'unexpected jq call: %s\n' "$*" >&2
  return 2
}

curl() {
  local all="$*" output=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  case "${all}" in
    *'/releases/tags/'*)
      printf '{}' > "${output}"
      printf '404'
      ;;
    *'releases?per_page=100'*)
      printf 'rate limited\n' > "${output}"
      printf '500'
      ;;
    *) return 2 ;;
  esac
}

gh() {
  printf 'unexpected gh call: %s\n' "$*" >&2
  return 2
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": runner_relative,
                    "GH_TOKEN": "fixture-token",
                    "GITHUB_API_URL": "https://api.github.com",
                    "GITHUB_REPOSITORY": RC.EXPECTED_REPOSITORY,
                    "SOURCE_SHA": self.SOURCE,
                    "MAIN_RUN_ID": "123",
                    "IMAGE": RC.EXPECTED_IMAGE,
                    "CHART": RC.EXPECTED_CHART,
                }
            )
            completed = subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=ROOT,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("DENY: releases list probe returned HTTP 500", completed.stderr)


class ReleaseSettingsShellPathTests(unittest.TestCase):
    STEP = "Require authoritative release settings before side effects"
    _native_tool_directory: tempfile.TemporaryDirectory[str] | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "nt":
            return
        go = shutil.which("go")
        if go is None:
            raise unittest.SkipTest("Go is required for the Windows-only local gh fixture")
        cls._native_tool_directory = tempfile.TemporaryDirectory(
            dir=ROOT, prefix=".release-settings-gh-"
        )
        directory = Path(cls._native_tool_directory.name)
        source = directory / "main.go"
        source.write_text(
            r'''package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func deny() {
	os.Exit(1)
}

func main() {
	if os.Getenv("GH_TOKEN") != "fixture-workflow-token" {
		deny()
	}
	args := os.Args[1:]
	if len(args) < 4 || args[0] != "api" || args[1] != "--method" || args[2] != "GET" {
		deny()
	}
	endpoint := args[len(args)-1]
	if endpoint == os.Getenv("DENIED_ENDPOINT") {
		deny()
	}
	if endpoint == os.Getenv("MALFORMED_ENDPOINT") {
		fmt.Print("{malformed")
		return
	}
	files := map[string]string{
		"repos/owner/site": "repository.json",
		"repos/owner/site/private-vulnerability-reporting": "private.json",
		"repos/owner/site/rulesets": "rulesets.json",
		"repos/owner/site/rulesets/42": "ruleset.json",
	}
	name, ok := files[endpoint]
	if !ok {
		deny()
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("SETTINGS_FIXTURES_WIN"), name))
	if err != nil {
		deny()
	}
	if endpoint == "repos/owner/site/rulesets" {
		fmt.Printf("[%s]", data)
	} else {
		_, _ = os.Stdout.Write(data)
	}
}
''',
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["CGO_ENABLED"] = "0"
        environment["GOTOOLCHAIN"] = "local"
        built = subprocess.run(
            [go, "build", "-o", str(directory / "gh.exe"), str(source)],
            cwd=directory,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._native_tool_directory is not None:
            cls._native_tool_directory.cleanup()
            cls._native_tool_directory = None

    def execute(
        self,
        records: Mapping[str, object],
        *,
        block: str | None = None,
        denied_endpoint: str = "",
        malformed_endpoint: str = "",
        gh_token: str = "fixture-workflow-token",
    ) -> subprocess.CompletedProcess[str]:
        if block is None:
            block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".release-settings-shell-") as temporary:
            runner = Path(temporary)
            runner_relative = runner.relative_to(ROOT).as_posix()
            paths = {
                "repository": "repos/owner/site",
                "private": "repos/owner/site/private-vulnerability-reporting",
                "rulesets": "repos/owner/site/rulesets",
                "ruleset": "repos/owner/site/rulesets/42",
            }
            for name, endpoint in paths.items():
                (runner / f"{name}.json").write_text(
                    json.dumps(records[endpoint]), encoding="utf-8"
                )
            gh_body = r'''#!/usr/bin/env bash
set -euo pipefail
test "${GH_TOKEN:-}" = fixture-workflow-token
if [ "${1:-}" = api ]; then
  shift
fi
test "$1" = --method
test "$2" = GET
endpoint="${!#}"
if [ "${endpoint}" = "${DENIED_ENDPOINT}" ]; then
  exit 1
fi
if [ "${endpoint}" = "${MALFORMED_ENDPOINT}" ]; then
  printf '{malformed'
  exit 0
fi
case "${endpoint}" in
  repos/owner/site) cat "${SETTINGS_FIXTURES}/repository.json" ;;
  repos/owner/site/private-vulnerability-reporting) cat "${SETTINGS_FIXTURES}/private.json" ;;
  repos/owner/site/rulesets)
    printf '['
    cat "${SETTINGS_FIXTURES}/rulesets.json"
    printf ']'
    ;;
  repos/owner/site/rulesets/42) cat "${SETTINGS_FIXTURES}/ruleset.json" ;;
  *) exit 2 ;;
esac
'''
            if os.name == "nt":
                assert self._native_tool_directory is not None
                gh_directory = Path(self._native_tool_directory.name)
            else:
                gh_stub = runner / "gh"
                gh_stub.write_text(gh_body, encoding="utf-8")
                gh_stub.chmod(0o700)
                gh_directory = runner
            prelude = r'''
python3() {
  "${TEST_PYTHON}" "$@"
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": ".",
                    "SETTINGS_FIXTURES": ExistingImageShellPathTests.bash_path(str(runner)),
                    "SETTINGS_FIXTURES_WIN": str(runner.resolve()),
                    "DENIED_ENDPOINT": denied_endpoint,
                    "MALFORMED_ENDPOINT": malformed_endpoint,
                    # The step's `env:` declares GH_TOKEN from the job's own
                    # workflow token; the run block is executed beneath it.
                    "GH_TOKEN": gh_token,
                    "GITHUB_REPOSITORY": "owner/site",
                    "PATH": str(gh_directory.resolve())
                    + os.pathsep
                    + os.environ.get("PATH", ""),
                }
            )
            contract = ExistingImageShellPathTests.bash_path(
                str(ROOT / "scripts" / "ci" / "release_contract.py")
            )
            block = block.replace("scripts/ci/release_contract.py", contract)
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable(), "-c", prelude + "\n" + block],
                cwd=runner,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_actual_full_settings_preflight_is_closed_and_load_bearing(self):
        block = ExistingImageShellPathTests.workflow_run_block(self.STEP)
        exact_records = settings_api()
        exact = self.execute(exact_records, block=block)
        self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
        self.assertEqual(exact.stdout.strip(), "exact")

        disabled = copy.deepcopy(exact_records)
        disabled["repos/owner/site/private-vulnerability-reporting"]["enabled"] = False
        foreign = copy.deepcopy(exact_records)
        foreign["repos/owner/site/rulesets/42"]["rules"].append({"type": "update"})
        for name, records in (("disabled", disabled), ("foreign", foreign)):
            with self.subTest(settings=name):
                rejected = self.execute(records, block=block)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        for endpoint in SettingsReceiptTests.TOKEN_READABLE_ENDPOINTS:
            with self.subTest(denied=endpoint):
                denied = self.execute(exact_records, block=block, denied_endpoint=endpoint)
                self.assertNotEqual(denied.returncode, 0, denied.stdout + denied.stderr)
                malformed = self.execute(exact_records, block=block, malformed_endpoint=endpoint)
                self.assertNotEqual(malformed.returncode, 0, malformed.stdout + malformed.stderr)

        # The credential is the step's own `env:`, never the run block: the
        # block reads GH_TOKEN as the runner hands it over and replaces it
        # with nothing. Without it, or with the block clobbering it, the
        # preflight is denied rather than run under some other identity.
        step = next(
            step for step in job_steps(
                (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8"),
                "repository_settings",
            )
            if step["name"] == self.STEP
        )
        self.assertIn("          GH_TOKEN: ${{ github.token }}", step["lines"])
        self.assertNotIn("GH_TOKEN", block)
        without_token = self.execute(exact_records, block=block, gh_token="")
        self.assertNotEqual(without_token.returncode, 0, without_token.stdout + without_token.stderr)
        clobbered = self.execute(exact_records, block="GH_TOKEN=''\n" + block)
        self.assertNotEqual(clobbered.returncode, 0, clobbered.stdout + clobbered.stderr)

        receipt_assignment = 'receipt="${RUNNER_TEMP}/release-settings-receipt.json"'
        self.assertIn(receipt_assignment, block)
        deletion_mutant = block.split(receipt_assignment, 1)[0] + "true\n"
        disabled_survives = self.execute(disabled, block=deletion_mutant)
        self.assertEqual(
            disabled_survives.returncode,
            0,
            disabled_survives.stdout + disabled_survives.stderr,
        )

class GovernanceParityTests(unittest.TestCase):
    # Reviewer independence is a GitHub PRINCIPAL, not a string. Verdict
    # receipts post as this App, which is granted Contents write in no
    # repository, so the reviewing identity can never push the code it
    # reviews. Its predecessor compared the signature text to the recorded
    # author context; a reviewer satisfied that rule by writing a
    # different-looking signature, which proved only that the reviewer
    # could type. The comparison — and its `author_context` parameter —
    # are retired with issue #64 rather than kept alongside the actor
    # check: keeping a rule that a keystroke satisfies invites the same
    # signature-crafting the actor makes pointless. Nothing is weakened,
    # because the replacement binds an unforgeable posting principal where
    # the old rule bound editable prose.
    REVIEW_ACTOR = "snaraj-agent-reviews[bot]"

    @staticmethod
    def adversarial_receipt_denial(
        text: str,
        expected_head: str,
        *,
        actor: str,
        resource_kind: str,
    ) -> str | None:
        if resource_kind != "pull-request":
            return "exact-head review receipts apply only to pull requests"
        if re.fullmatch(r"[0-9a-f]{40}", expected_head) is None:
            return "expected head is not one lowercase 40-hex SHA"
        # Byte-exact, deliberately: a padded, case-varied, or lookalike
        # login is not the App, and a fail-closed check never guesses.
        if actor != GovernanceParityTests.REVIEW_ACTOR:
            return "verdict receipt must be posted by the review App actor"
        lines = text.replace("\r\n", "\n").splitlines()
        heads = [line[6:] for line in lines if line.startswith("HEAD: ")]
        verdicts = [line[9:] for line in lines if line.startswith("VERDICT: ")]
        if heads != [expected_head]:
            return "receipt must bind exactly one expected HEAD line"
        if len(verdicts) != 1 or verdicts[0] not in {"APPROVE", "REQUEST-CHANGES"}:
            return "receipt must contain exactly one supported VERDICT line"
        # No "receipt is empty" arm: the two guards above each independently
        # require a non-empty line (a `HEAD: ` line and a `VERDICT: ` line),
        # so a blank receipt is denied before this point and the arm that
        # used to sit here could never run.  A branch no input can reach is
        # decorative by this repository's own review protocol, and it read
        # as protection for the indexing below that it never supplied;
        # `test_a_blank_receipt_is_denied_by_the_head_line_guard` pins the
        # guard that actually does (issue #128).
        nonempty = [line for line in lines if line.strip()]
        signature = re.fullmatch(r"- (.+?) \(adversarial reviewer\)", nonempty[-1])
        if signature is None:
            return "final non-empty line must be adversarial reviewer signature"
        # The lane must be named — provenance is still mandatory — but WHICH
        # lane is content: every current and future model name is valid, and
        # no roster is pinned here.
        if not signature.group(1).strip():
            return "adversarial reviewer signature must name the reviewing lane"
        if "mutation" not in text.casefold() or "claim" not in text.casefold():
            return "receipt must report mutation and claim audit evidence"
        return None

    @classmethod
    def require_adversarial_review_governance(cls, agents: str) -> str:
        try:
            independence = agents.split("**Reviewer independence.**", 1)[1].split(
                "**Exact-head receipt.**", 1
            )[0]
            receipt = agents.split("**Exact-head receipt.**", 1)[1].split(
                "**The review must:**", 1
            )[0]
            label = agents.split(
                "- **`requires-review` — the review-readiness signal.**", 1
            )[1].split("- **Agent labels.**", 1)[0]
            working = agents.split("## Working a change end to end", 1)[1].split(
                "## Commit identity mechanics", 1
            )[0]
        except IndexError as exc:
            raise ValueError("canonical adversarial-review governance is missing") from exc

        for token in (
            "one normal PR comment in this exact shape",
            "HEAD: <40-lowercase-hex>",
            "VERDICT: APPROVE",
            "VERDICT: REQUEST-CHANGES",
            "Mutation audit:",
            "Claim audit:",
            "Full-gate and flake evidence:",
            "Scratch cleanup:",
            "- <Agent> (adversarial reviewer)",
        ):
            if token not in receipt:
                raise ValueError(f"canonical adversarial receipt lost: {token}")
        independence_flat = " ".join(independence.split())
        for token in (
            "Independence is established by the POSTING ACTOR",
            "`snaraj-agent-reviews[bot]` GitHub App",
            "granted Contents write in no repository",
            "any current or future model name is valid there",
            "this contract pins no model roster",
            "No rule compares the reviewer's name to the author's",
        ):
            if token not in independence_flat:
                raise ValueError(f"actor-based reviewer independence lost: {token}")
        # The retired rule must not return by prose either: restating it
        # anywhere in the contract re-opens the signature-crafting path the
        # actor check exists to close (issue #64).
        agents_flat = " ".join(agents.split())
        for forbidden in (
            "differ textually from author",
            "Review identity is textual because agents share",
        ):
            if forbidden in agents_flat:
                raise ValueError(f"retired same-lane receipt rule returned: {forbidden}")
        label_flat = " ".join(label.split())
        working_flat = " ".join(working.split())
        for token in (
            "`requires-review` is PR-head-only",
            "The author applies it only when the exact PR head, body,",
            "commits, and evidence are author-complete",
            "Its absence means the author PR is in flight",
            "The reviewer removes it when posting either verdict",
            "after repairs, the author reapplies it",
            "only for the complete replacement head",
            "Never apply or interpret it on an issue",
            "an issue has no head and cannot satisfy a PR receipt or Ready gate",
            "an explicit normal comment for issue-spec review",
        ):
            if token not in label_flat:
                raise ValueError(f"PR-head-only review handoff lost: {token}")
        if "Never apply or interpret `requires-review` on the issue" not in working_flat:
            raise ValueError("issue workflow regained requires-review semantics")

        try:
            sample = receipt.split("```text\n", 1)[1].split("\n```", 1)[0]
        except IndexError as exc:
            raise ValueError("canonical adversarial receipt sample is missing") from exc
        rendered = (
            sample.replace("<40-lowercase-hex>", "a" * 40)
            .replace("<numbered finding, or explicit no-finding scope>", "No finding in scope.")
            .replace("<hostile mutation results>", "all hostile mutants killed")
            .replace("<SUPPORTED and OVERSTATED results>", "SUPPORTED: exact scope")
            .replace(
                "<commands, results, and capability boundaries>",
                "focused and full gates passed",
            )
            .replace(
                "<disposable workspace and residue result>",
                "disposable workspace removed",
            )
            .replace("<Agent>", "Fable5")
        )
        denial = cls.adversarial_receipt_denial(
            rendered,
            "a" * 40,
            actor=cls.REVIEW_ACTOR,
            resource_kind="pull-request",
        )
        if denial is not None:
            raise ValueError(f"documented adversarial receipt is invalid: {denial}")
        return rendered

    @staticmethod
    def require_manifest_scan_audit_docs(
        agents: str, readme: str, security: str, runbook: str, changelog: str
    ) -> None:
        agents_flat = " ".join(agents.split())
        readme_flat = " ".join(readme.split())
        security_flat = " ".join(security.split())
        runbook_flat = " ".join(runbook.split())
        changelog_flat = " ".join(changelog.split())
        requirements = (
            (agents_flat, "exactly one canonical evidence"),
            (agents_flat, "exact PR-gate job inventory"),
            (agents_flat, "source scanning passes `--include-dev-deps`"),
            (agents_flat, "raw per-platform SBOM binding"),
            (agents_flat, "weekly read-only audit"),
            (agents_flat, "performs no publication mutation"),
            (readme_flat, "canonical JSON evidence manifest"),
            (readme_flat, "exact-SHA successful CodeQL"),
            (readme_flat, "with `--include-dev-deps`"),
            (readme_flat, "strict raw SBOM schema"),
            (readme_flat, "pre-manifest alias and SBOM proof"),
            (readme_flat, "checksum-pinned Trivy binary"),
            (readme_flat, "weekly read-only audit"),
            (security_flat, "exact job inventory"),
            (security_flat, "strict raw platform SBOM subject"),
            (security_flat, "stages exactly one canonical"),
            (security_flat, "public semantic aliases"),
            (security_flat, "not publication authorization"),
            (runbook_flat, "Workflow-level success alone is insufficient"),
            (runbook_flat, "analyze (go, manual)"),
            (runbook_flat, "analyze (javascript-typescript, none)"),
            (runbook_flat, "direct checksum-verified Trivy v0.72.0"),
            (runbook_flat, "raw OCI attestation carriers"),
            (runbook_flat, "New publication creates a draft Release"),
            (runbook_flat, "downloads and compares the manifest again"),
            (runbook_flat, "`release-audit.yml` runs weekly and manually"),
            (runbook_flat, "scheduled detection is defense in depth"),
            (runbook_flat, "It has no settings token, OIDC, or publication"),
            (changelog_flat, "closed job inventory"),
            (changelog_flat, "strict raw two-platform SBOM schemas"),
            (changelog_flat, "one deterministic evidence manifest"),
            (changelog_flat, "weekly"),
        )
        for document, token in requirements:
            if token not in document:
                raise ValueError(f"manifest/scan/audit doctrine lost: {token}")
        combined = agents + readme + security + runbook + changelog
        for forbidden in (
            "zero-asset inventory",
            "exact metadata and zero assets",
            "only the authoritative `GET /immutable-releases` step receives it",
        ):
            if forbidden in combined:
                raise ValueError(f"obsolete release doctrine survived: {forbidden}")

    @staticmethod
    def require_owner_role_privacy(agents: str) -> None:
        try:
            requirements = agents.split("## Requirements", 1)[1].split(
                "### Deployment-provider contract", 1
            )[0]
        except IndexError as exc:
            raise ValueError("canonical Requirements section is missing") from exc
        exact = "`main`; the repository owner alone merges."
        if requirements.count(exact) != 1:
            raise ValueError("owner-only merge authority must use the exact role, not a personal name")
        privacy_flat = " ".join(requirements.split())
        for token in (
            "No secrets, no noncanonical personal data",
            "already-public owner",
            "canonical attribution exceptions",
            "never expand them or use a personal name",
            "Access control is always expressed by role",
        ):
            if token not in privacy_flat:
                raise ValueError(f"privacy/attribution boundary lost: {token}")
        if "No secrets, no personal data." in requirements:
            raise ValueError("absolute no-personal-data claim contradicts canonical public attribution")
        if "PERSON_NAME_SENTINEL alone merges" in requirements:
            raise ValueError("canonical merge authority contains a personal-name regression")

    @staticmethod
    def require_two_denial_modes(agents: str) -> str:
        """Pin requirement 10's two-denial-mode passage, positively.

        This operator-facing text has been wrong twice and corrected twice
        (issue #106): the first revision made BOTH denials sticky, and the
        correction overshot by promising the next documentation merge green.
        Nothing mechanical held the line, so every restatement was free to
        drift back onto a reader who is, by definition, staring at a red
        build and deciding whether to wait or act.

        Two deliberate design choices, both of them the point:

        * The assertions are POSITIVE and exact. A whole-file ``assertNotIn``
          of a forbidden token has already failed twice in this effort,
          because the comment written beside a guard contains the very token
          the guard forbids -- prose then satisfies or breaks the check by
          accident. Nothing here scans a file for an absent string.
        * The passage is SLICED before it is read, between two anchors that
          appear exactly once, so only requirement 10's own sentences can
          satisfy this pin. Restating the wording anywhere else in the
          contract -- or in a comment -- cannot rescue a mutated original;
          ``test_two_denial_mode_wording_is_pinned_to_requirement_ten``
          proves that by relocating the passage and requiring red anyway.

        Returns the flattened passage so callers can assert on it.
        """
        opening = "Two denial modes are deliberate"
        closing = "Successful main CI publishes that exact SHA"
        _, found_opening, tail = agents.partition(opening)
        passage, found_closing, _ = tail.partition(closing)
        # BOTH anchors are load-bearing. A missing opener has no passage to
        # read; a missing closer would silently widen the slice to the rest
        # of the document, which is the whole-file scan this pin refuses to
        # become. Neither may degrade into a wider or empty read.
        if not found_opening or not found_closing:
            raise ValueError("canonical two-denial-mode passage is missing or unbounded")
        flat = " ".join((opening + passage).split())
        for token in (
            # The pair exists on purpose, and telling them apart is the point.
            "Two denial modes are deliberate and must not be mistaken for"
            " bugs, and they behave differently",
            "conflating them misleads whoever is on the other end of the red build",
            # Boundary denial: sticky, and ordinary rather than exotic.
            "The BOUNDARY denial, from the recovered last release boundary, is STICKY",
            "every later documentation merge fails the same way until an artifact"
            " merge moves the boundary past it",
            "It is reachable under the ordinary rebase convention of a separate"
            " slot commit, not only under exotic histories",
            # Anchor denial: NOT sticky, and NOT promised green next merge.
            "The ANCHOR denial, from the four-lock comparison against the newest"
            " earlier successful protected-main gate run, does not persist the same way",
            "it needs no artifact merge to clear, because the denied merge's own"
            " gate run becomes a later anchor",
            "It is NOT, however, promised to clear on the very NEXT merge, and an"
            " earlier revision of this contract wrongly said it was",
            # The mechanism behind that second correction.
            "Main pushes each get their own concurrency group",
            "gate runs can complete out of order and `select(.id < $current)` can"
            " filter a newer run out of an older orchestration",
            "two racing documentation merges can therefore both deny, reporting"
            " the identical anchor",
            # The closing summary, which is what a hurried reader reads.
            "Both denials are the intended trade — loud and recoverable, never a"
            " wrong release",
            "only the boundary denial requires an artifact merge to clear, and"
            " neither promises green on any particular next merge",
        ):
            if token not in flat:
                raise ValueError(f"two-denial-mode wording lost: {token}")
        return flat

    @staticmethod
    def require_adversarial_signature_parity(agents: str, template: str) -> None:
        """The PR template's reviewer signature must be the contract's.

        Issue #128: the template asked for a signature shape the contract
        never defined, so an author following the template and a reviewer
        following AGENTS.md wrote different last lines. Post-#64 the
        signature is lane provenance -- CONTENT -- while independence rides
        the posting App actor, so the two documents disagreeing costs no
        security; it costs a reviewer a pointless correction round, which
        is exactly the friction this effort exists to remove.

        The Main Worker receipt and its distinct signature retired with
        issue #190; this checks the adversarial line only.
        """
        adversarial = "- <Agent> (adversarial reviewer)"
        for name, text in (("AGENTS.md", agents), ("PR template", template)):
            if adversarial not in text:
                raise ValueError(f"{name} lost the canonical reviewer signature shape")
        # Scoped to the template's own reviewer bullet, never the whole file:
        # this repository has twice been burned by whole-file token scans.
        try:
            bullet = template.split("- Independent normal-comment verdict", 1)[1].split(
                "- Base freshness and successful required checks", 1
            )[0]
        except IndexError as exc:
            raise ValueError("PR template lost its independent-verdict bullet") from exc
        if adversarial not in bullet:
            raise ValueError("PR template reviewer bullet lost the canonical signature")
        if "(adversarial reviewer)" in bullet.replace(adversarial, "", 1):
            raise ValueError("PR template reviewer bullet names a second signature shape")

    @staticmethod
    def require_ready_flip_governance(agents: str, template: str, runbook: str) -> None:
        """Issues #190/#198: the Ready flip needs approval plus green checks,
        nothing else — and the pin closes the DOCUMENTS, not a window.

        The Main Worker ceremony retired; this pins its replacement rule
        CLOSED. The AGENTS.md section and the runbook's retirement paragraph
        must equal the canonical text exactly (whitespace-normalized), so a
        contradictory permission inserted beside the rule is as red as a
        deletion — review round 1 proved a substring pin lets "may also flip
        Ready before review" survive. It also fails closed if the retired
        ceremony's canonical shapes resurface in any governance document.

        Round 2 (issue #198) proved the window itself was the hole: a
        competing Ready authority placed OUTSIDE the pinned section — a
        displaced paragraph, a second runbook paragraph, or the Merge
        readiness bullet rewritten — survived. Therefore every block in the
        three governance documents that speaks the word "ready" (word
        boundary, case-insensitive; `/readyz` and "readiness" do not match)
        must hash-match one enumerated pin below, and every pin must still
        be present, so an unenumerated Ready statement anywhere is red and a
        vanished pinned region is red. Editing a ready-bearing block is a
        conscious change: recompute its normalized SHA-256 here in the same
        commit. Honest limit, stated for the reviewer: the closure keys on
        the word "ready", so a contradiction that avoids the word evades
        this net — the canonical-rule equality above and adversarial review
        remain the outer layers.
        """
        canonical_section = (
            "Once the independent adversarial review has approved the exact "
            "final head and all required checks are green, the coordinator "
            "flips Ready and the owner merges. No third distinct-context "
            "pass is required."
        )
        try:
            section = agents.split("### After review, Ready", 1)[1].split(
                "## GitHub conventions", 1
            )[0]
        except IndexError as exc:
            raise ValueError("canonical Ready-flip section is missing") from exc
        if " ".join(section.split()) != canonical_section:
            raise ValueError("Ready-flip section is not the closed canonical rule")
        agents_flat = " ".join(agents.split())
        if "a fresh exact-head APPROVE receipt exists" not in agents_flat:
            raise ValueError("merge readiness lost the exact-head APPROVE requirement")
        canonical_runbook_paragraph = (
            "The Main Worker gate retired with issue #190. After the final "
            "author push, exact-head adversarial approval, and green required "
            "checks, no further distinct-context receipt is required: the "
            "coordinator alone changes the Draft/Ready state, and the "
            "repository owner alone merges."
        )
        runbook_paragraphs = [" ".join(block.split()) for block in runbook.split("\n\n")]
        if canonical_runbook_paragraph not in runbook_paragraphs:
            raise ValueError(
                "release runbook lost the closed Ready-flip retirement paragraph"
            )
        for retired in (
            "ROLE: MAIN-WORKER",
            "(Main Worker)",
            "Main Worker receipt",
            "MAIN-WORKER-ARCHITECTURE",
        ):
            if retired in agents + template + runbook:
                raise ValueError(f"retired Main Worker ceremony resurfaced: {retired}")
        ready_word = re.compile(r"\bready\b", re.IGNORECASE)
        ready_block_pins = {
            "AGENTS.md": (
                # Re-pinned at 0.1.49: the block now states that successful main
                # CI creates NO tag and that the PUBLISHER creates it from
                # inside the privileged job, grounded in the `actions: write` /
                # `contents: write` permission split. Its Ready sentences —
                # "The receipt is a required Ready gate" and "A failed or
                # unknown preflight leaves the PR Draft" — are unchanged; only
                # the tag-creation mechanism above them was corrected.
                # Re-pinned for this repository's first release: the source-scan
                # clause states `--include-dev-deps` over a dependency-free Go
                # module instead of frontend development dependencies, which
                # do not exist here. Its Ready sentences are unchanged.
                # Re-pinned for issue #16: "documentation-only" becomes
                # "no-artifact" twice, because requirement 10's class now also
                # holds .github/, scripts/ci/ and Go test files. Those two
                # words are the whole change; the Ready sentences are unchanged.
                ("Releases: every artifact-classified PR advances numeric",
                 "4d1cf6b8a8b606991f7fdd7210499d86cf6a5d02c488524bf209497c392a05d5"),
                ("**Verdict format** — posted as a normal PR comment",
                 "5b074e5bab48c010304cc700fc62e47d14e34769c7534255b0ed14451e09a1cd"),
                ("A green check, a peer approval, or a ready state is evidence",
                 "c174925d3033b05506dfaad7adbf36f51b0d2b14007090a38cd9ef8465e9f7f3"),
                ("### After review, Ready (the heading)",
                 "8746155dd0c815012e6a09c3f159ebe5337426c6821c1c45a26023cafa6554f6"),
                ("Once the independent adversarial review has approved (the rule)",
                 "132d86d25ffe1a7cfb0d16c26c17c2768b417ab8e5bb5c2bc4bdd5d41a43306e"),
                ("- **`requires-review` — the review-readiness signal.**",
                 "340084c93dd72dbd2f93440ccc1f68955f3ad911ff08cf2904be70e0ff5d5694"),
                # Re-pinned for issue #343: the bullet no longer names the
                # owner User's PR-only update exception, because the ruleset
                # that carried it was retired on 2026-09-22. The Ready rule
                # itself is unchanged — the owner's bypass check must still
                # report no core bypass actor, and only the coordinator flips
                # Ready.
                # Re-pinned for this repository's first release: immutable
                # releases are proven by the owner-verified commands, because
                # the settings job's read-only token cannot read that switch.
                # The Ready rule is unchanged -- every listed proof is still
                # required, and only the coordinator flips Ready.
                # Re-pinned for issue #16: "a documentation-only PR reserves no
                # patch" reads "a no-artifact PR", the class's new name. That
                # one word is the whole change; the Ready rule is unchanged.
                ("- **Merge readiness.** Draft remains Draft until",
                 "7c5f16d34d6b4fdd9c7958728ea524597993d7afcb4cc252f3dbc86cf897eddb"),
                # Re-pinned for issue #285: step 2 of the list admits the
                # `xhigh` effort to the branch grammar (owner ruling,
                # 2026-09-03). The block's Ready sentences — step 1's "Never
                # apply or interpret `requires-review` on the issue" and the
                # later Ready/merge steps — are unchanged; only the effort set
                # in the branch grammar grew by one word.
                # Re-pinned for issue #294: step 2's registered label set
                # gained `fable5.1` (owner directive, 2026-09-04, PR #295)
                # and names the longest-match rule that lets `fable5.1-high/`
                # and `fable5-high/` coexist. The block's Ready sentences —
                # step 1's "Never apply or interpret `requires-review` on
                # the issue" and the later Ready/merge steps — are unchanged.
                # Re-pinned for issue #343: step 7 drops the retired
                # `Owner-PR-Updates` sentence and states instead that
                # `Protect-Main` is the only active repository-owned branch
                # ruleset. The step's Ready condition — exact immutable and
                # strict-check state, empty core bypass list — is unchanged.
                # Re-pinned for this repository's first release: step 2's label
                # set gains `gpt-6` and `opus5.5` (with its longest-match
                # example) and drops the sibling's branch examples; step 7
                # names the owner-verified settings commands beside the bypass
                # command. The Ready sentences are unchanged.
                # Re-pinned for issue #16: step 2's "documentation-only change"
                # reads "no-artifact change", the class's new name. That one
                # word is the whole change; the Ready steps are unchanged.
                ("1. **Claim the work.** (the delivery-loop numbered list)",
                 "ee53e01f8f846f1983e12e5f844ef4a6697be3b1bfcce1322340da5d0d066201"),
                ("Comments the owner leaves on PRs ARE code reviews",
                 "e8e6f2dd0c82a28a8c280cd1705002f4faf8d2e9aa81195df5466d6db83a871c"),
                ("The full local gate does not substitute for the server boundary",
                 "f37cd9fe94b5eba97837c4498d33b9ca9e26f7a14cf4990f31eae08e0fd6a145"),
            ),
            "PR template": (
                ("- Author applies `requires-review` only after exact-head",
                 "91e45327a9619c731f57835fd77dfc1b35d39acce828080020756a2602fcd42e"),
            ),
            "release runbook": (
                # This repository's own settings-observation paragraph, which
                # replaces the sibling's dated transaction history: nothing is
                # observed yet, so the receipt remains an external Ready
                # blocker for the first automatic release.
                ("No settings of this repository have been observed yet.",
                 "42c591098238ed00e1824e4e9c440472e316d874dc1e8878ca40b4b2f3c43ad1"),
                ("Missing, extra, duplicated, name-only, foreign-integration",
                 "2d6b738ab4bf9675eb30ce44edb02b22aa15eaaf2f2e2d542739b9908fe69a16"),
                ("The property is returned only at ruleset write-access-level",
                 "fbebe47bc7dfafbe7239d6f0db9f8e661ac56527edfb4561a99525d0ad5326f1"),
                ("The Main Worker gate retired with issue #190 (the retirement paragraph)",
                 "69aa791f7a6fc8e2c92a39b0579b3306949fd10d9bb4430647770de414d0b5ab"),
            ),
        }
        for document_name, document in (
            ("AGENTS.md", agents),
            ("PR template", template),
            ("release runbook", runbook),
        ):
            found = {}
            for block in re.split(r"\n\n+|\n(?=- \*\*)", document):
                if ready_word.search(block):
                    normalized = " ".join(block.split())
                    found[hashlib.sha256(normalized.encode()).hexdigest()] = normalized
            pins = ready_block_pins[document_name]
            pinned_digests = {digest for _, digest in pins}
            for digest, block in found.items():
                if digest not in pinned_digests:
                    raise ValueError(
                        f"unenumerated Ready-authority text in {document_name}: "
                        f"{block[:100]!r} — every block that speaks of Ready must "
                        "be an enumerated pin; editing one is a conscious change "
                        "to the pin set in require_ready_flip_governance"
                    )
            for label, digest in pins:
                if digest not in found:
                    raise ValueError(
                        f"pinned Ready region lost from {document_name}: {label!r}"
                    )

    def test_owner_only_merge_requirement_rejects_the_personal_name_mutant(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.require_owner_role_privacy(agents)
        exact = "`main`; the repository owner alone merges."
        mutant = agents.replace(exact, "`main`; PERSON_NAME_SENTINEL alone merges.", 1)
        with self.assertRaises(ValueError):
            self.require_owner_role_privacy(mutant)
        for token in (
            "canonical attribution exceptions",
            "never expand them or use a personal name",
            "Access control is always expressed by role",
        ):
            with self.subTest(privacy_deletion=token), self.assertRaises(ValueError):
                self.require_owner_role_privacy(agents.replace(token, "", 1))
        with self.assertRaises(ValueError):
            self.require_owner_role_privacy(
                agents.replace(
                    "No secrets, no noncanonical personal data.",
                    "No secrets, no personal data.",
                    1,
                )
            )

    def test_adversarial_review_governance_is_pr_head_only_and_load_bearing(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.require_adversarial_review_governance(agents)
        for token in (
            "VERDICT: APPROVE",
            "Mutation audit:",
            "Claim audit:",
            "`requires-review` is\n  PR-head-only",
            "The author applies it only",
            "The reviewer\n  removes it when posting either verdict",
            "Never apply or interpret it on an\n  issue",
            "Never apply or interpret `requires-review` on the\n   issue",
        ):
            self.assertIn(token, agents)
            with self.subTest(deletion=token), self.assertRaises(ValueError):
                self.require_adversarial_review_governance(agents.replace(token, "", 1))
        for source, replacement in (
            (
                "The author applies it only",
                "The reviewer applies it only",
            ),
            (
                "The reviewer\n  removes it when posting either verdict",
                "The author\n  removes it when posting either verdict",
            ),
            (
                "Never apply or interpret it on an\n  issue",
                "Apply and interpret it on an\n  issue",
            ),
            (
                "Never apply or interpret `requires-review` on the\n   issue",
                "Apply and interpret `requires-review` on the\n   issue",
            ),
        ):
            self.assertIn(source, agents)
            with self.subTest(inversion=source), self.assertRaises(ValueError):
                self.require_adversarial_review_governance(
                    agents.replace(source, replacement, 1)
                )

    def test_documented_adversarial_receipt_rejects_invalid_samples(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        valid = self.require_adversarial_review_governance(agents)
        head = "a" * 40
        self.assertIsNone(
            self.adversarial_receipt_denial(
                valid,
                head,
                actor=self.REVIEW_ACTOR,
                resource_kind="pull-request",
            )
        )
        self.assertIsNone(
            self.adversarial_receipt_denial(
                valid.replace("VERDICT: APPROVE", "VERDICT: REQUEST-CHANGES", 1),
                head,
                actor=self.REVIEW_ACTOR,
                resource_kind="pull-request",
            )
        )
        invalid = {
            "bare verdict": valid.replace("VERDICT: APPROVE", "APPROVE", 1),
            "missing mutation evidence": valid.replace("Mutation audit:", "Evidence:", 1),
            "missing claim evidence": valid.replace("Claim audit:", "Evidence:", 1),
            "duplicate verdict": valid.replace(
                "VERDICT: APPROVE", "VERDICT: APPROVE\nVERDICT: REQUEST-CHANGES", 1
            ),
        }
        for name, sample in invalid.items():
            with self.subTest(invalid_sample=name):
                self.assertIsNotNone(
                    self.adversarial_receipt_denial(
                        sample,
                        head,
                        actor=self.REVIEW_ACTOR,
                        resource_kind="pull-request",
                    )
                )
        self.assertIsNotNone(
            self.adversarial_receipt_denial(
                valid,
                head,
                actor=self.REVIEW_ACTOR,
                resource_kind="issue",
            )
        )

    def test_reviewer_independence_binds_the_bot_actor_not_the_signature_text(self):
        """The App actor decides independence; the lane name is content."""
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        valid = self.require_adversarial_review_governance(agents)
        head = "a" * 40
        documented_signature = "- Fable5 (adversarial reviewer)"
        self.assertIn(documented_signature, valid)

        def denial(sample, *, actor=self.REVIEW_ACTOR, kind="pull-request"):
            return self.adversarial_receipt_denial(
                sample, head, actor=actor, resource_kind=kind
            )

        def signed(lane):
            return valid.replace(
                documented_signature, f"- {lane} (adversarial reviewer)", 1
            )

        self.assertIsNone(denial(valid))
        wrong_actor = "verdict receipt must be posted by the review App actor"
        for name, actor in (
            ("owner account", "snaraj"),
            ("release bot", "github-actions[bot]"),
            ("app login without the bot suffix", "snaraj-agent-reviews"),
            ("case-varied login", "Snaraj-Agent-Reviews[bot]"),
            ("leading whitespace", " snaraj-agent-reviews[bot]"),
            ("trailing whitespace", "snaraj-agent-reviews[bot] "),
            ("prefixed lookalike", "evil-snaraj-agent-reviews[bot]"),
            ("suffixed lookalike", "snaraj-agent-reviews[bot]2"),
            ("empty actor", ""),
        ):
            with self.subTest(wrong_actor=name):
                self.assertEqual(denial(valid, actor=actor), wrong_actor)
        # A wrong actor denies even when every other field is perfect, and a
        # right actor never rescues a malformed body — the two are independent.
        self.assertEqual(
            denial(valid.replace("VERDICT: APPROVE", "APPROVE", 1), actor="snaraj"),
            wrong_actor,
        )

        # No roster: lanes that do not exist yet validate exactly like Fable5.
        for lane in (
            "Fable5",
            "Opus5",
            "Sonnet5",
            "5.6 Sol",
            "Nebula 9",
            "Some-Future-Model 12.3",
            "Claude Opus 42 (fresh session)",
        ):
            with self.subTest(novel_lane=lane):
                self.assertIsNone(denial(signed(lane)))

        # Same-lane review: every textual variation of one lane's signature
        # yields the identical outcome, so crafting a distinguishing string
        # can no longer change a verdict's fate.
        crafted = {
            variant: denial(signed(variant))
            for variant in (
                "Fable5",
                "fable5",
                "FABLE5",
                "Fable5 / pr64-exact-head-review",
                "Fable5 (fresh session)",
                "Fable 5",
            )
        }
        self.assertEqual(set(crafted.values()), {None}, crafted)

        # Provenance is still mandatory: a nameless signature denies.
        self.assertEqual(
            denial(valid.replace(documented_signature, "-   (adversarial reviewer)", 1)),
            "adversarial reviewer signature must name the reviewing lane",
        )

        # Shape still fails closed under the correct actor.
        for name, sample, reason in (
            (
                "bare verdict",
                valid.replace("VERDICT: APPROVE", "APPROVE", 1),
                "receipt must contain exactly one supported VERDICT line",
            ),
            (
                "unsupported verdict",
                valid.replace("VERDICT: APPROVE", "VERDICT: LGTM", 1),
                "receipt must contain exactly one supported VERDICT line",
            ),
            (
                "duplicate head",
                valid.replace(f"HEAD: {head}", f"HEAD: {head}\nHEAD: {head}", 1),
                "receipt must bind exactly one expected HEAD line",
            ),
            (
                "foreign head",
                valid.replace(f"HEAD: {head}", "HEAD: " + "b" * 40, 1),
                "receipt must bind exactly one expected HEAD line",
            ),
            (
                "main worker signature",
                valid.replace(" (adversarial reviewer)", " (Main Worker)", 1),
                "final non-empty line must be adversarial reviewer signature",
            ),
            (
                "missing mutation evidence",
                valid.replace("Mutation audit:", "Evidence:", 1),
                "receipt must report mutation and claim audit evidence",
            ),
            ("empty receipt", "", "receipt must bind exactly one expected HEAD line"),
        ):
            with self.subTest(malformed=name):
                self.assertEqual(denial(sample), reason)
        self.assertEqual(
            denial(valid, kind="issue"),
            "exact-head review receipts apply only to pull requests",
        )
        for bad_head in ("A" * 40, "a" * 39, "a" * 41, "", "z" * 40, "a" * 40 + "\n"):
            with self.subTest(bad_head=repr(bad_head)):
                self.assertEqual(
                    self.adversarial_receipt_denial(
                        valid,
                        bad_head,
                        actor=self.REVIEW_ACTOR,
                        resource_kind="pull-request",
                    ),
                    "expected head is not one lowercase 40-hex SHA",
                )

    def test_retired_same_lane_signature_rule_cannot_return(self):
        """Neither the validator nor the contract may restate the retired rule."""
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        valid = self.require_adversarial_review_governance(agents)
        # The parameter itself is gone, so no caller can re-supply an author
        # context and no edit can quietly restore the comparison behind one.
        with self.assertRaises(TypeError):
            self.adversarial_receipt_denial(
                valid,
                "a" * 40,
                actor=self.REVIEW_ACTOR,
                author_context="Fable5",
                resource_kind="pull-request",
            )
        for anchor in (
            "POSTING",
            "`snaraj-agent-reviews[bot]` GitHub App",
            "granted Contents",
            "any current or future model name is valid there",
            "this contract pins no model roster",
            "No rule compares the reviewer's",
        ):
            self.assertIn(anchor, agents)
            with self.subTest(deletion=anchor), self.assertRaises(ValueError):
                self.require_adversarial_review_governance(agents.replace(anchor, "", 1))
        for source, replacement in (
            ("No rule compares the reviewer's", "One rule compares the reviewer's"),
            (
                "Independence is established by the POSTING",
                "Independence is established by the SIGNATURE, not the POSTING",
            ),
        ):
            self.assertIn(source, agents)
            with self.subTest(inversion=source), self.assertRaises(ValueError):
                self.require_adversarial_review_governance(
                    agents.replace(source, replacement, 1)
                )
        for restatement in (
            "The reviewer context must differ textually from author context.",
            "Review identity is textual because agents share the account.",
        ):
            with self.subTest(restatement=restatement), self.assertRaises(ValueError):
                self.require_adversarial_review_governance(
                    agents.replace("what it reviews.", "what it reviews. " + restatement, 1)
                )

    def test_two_denial_mode_wording_is_pinned_to_requirement_ten(self):
        """Issue #106: the twice-wrong denial-mode text gets a mechanical guard.

        Every mutant below is a sentence this contract has actually carried
        or been corrected away from, so none of them is hypothetical.
        """
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        flat = self.require_two_denial_modes(agents)
        self.assertIn("BOUNDARY", flat)
        self.assertIn("ANCHOR", flat)

        # Deletions: each raw fragment appears exactly once in the file, so
        # the replace below cannot silently hit a different sentence.
        for fragment in (
            "conflating them misleads whoever is",
            "is STICKY",
            "documentation merge fails the same way until an artifact merge moves the",
            "It is reachable under the ordinary rebase convention",
            "of a separate slot commit, not only under exotic histories",
            "does not persist the same way",
            "needs no artifact merge to clear, because the denied merge's own gate",
            "It is NOT, however, promised to clear on",
            "an earlier revision of this contract wrongly",
            "Main pushes each get their own concurrency group",
            "`select(.id < $current)` can filter",
            "two racing documentation",
            "reporting the identical anchor",
            "loud and recoverable, never a wrong",
            "only the boundary denial requires an artifact merge to",
            "neither promises green on any particular next merge",
        ):
            self.assertEqual(agents.count(fragment), 1, fragment)
            with self.subTest(deletion=fragment), self.assertRaises(ValueError):
                self.require_two_denial_modes(agents.replace(fragment, "", 1))

        # Inversions: the exact two regressions this issue was filed for,
        # plus their neighbours, each restated the way a drifting rewrite
        # would restate it.
        for source, replacement in (
            # Regression 1 (corrected once): stickiness attributed to both.
            (
                "only the boundary denial requires an artifact merge to",
                "both denials require an artifact merge to",
            ),
            ("is STICKY", "is not sticky"),
            ("does not persist the same way", "persists the same way"),
            # Regression 2 (corrected once): the overshoot promising green.
            (
                "It is NOT, however, promised to clear on",
                "It is, moreover, promised to clear on",
            ),
            (
                "neither promises green on any particular next merge",
                "both promise green on the next merge",
            ),
            # The exotic-history misreading that made the boundary denial
            # look like somebody else's problem.
            (
                "It is reachable under the ordinary rebase convention",
                "It is reachable only under exotic conventions",
            ),
        ):
            self.assertEqual(agents.count(source), 1, source)
            with self.subTest(inversion=source), self.assertRaises(ValueError):
                self.require_two_denial_modes(agents.replace(source, replacement, 1))

        # Anti-decoration: the pin must read requirement 10's own sentences
        # and nothing else. Relocating the intact passage elsewhere in the
        # document must NOT rescue a mutated original -- otherwise a comment
        # or an appendix could satisfy the guard, which is the exact failure
        # mode #106 warns about.
        passage = "Two denial modes are deliberate" + agents.split(
            "Two denial modes are deliberate", 1
        )[1].split("Successful main CI publishes that exact SHA", 1)[0]
        relocated = agents.replace("is STICKY", "is not sticky", 1) + "\n\n" + passage
        self.assertIn("is STICKY", relocated)
        with self.assertRaises(ValueError):
            self.require_two_denial_modes(relocated)
        # And the anchors themselves are load-bearing: losing either end of
        # the slice is a missing passage, never an empty one that passes.
        for anchor in (
            "Two denial modes are deliberate",
            "Successful main CI publishes that exact SHA",
        ):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                self.require_two_denial_modes(agents.replace(anchor, "", 1))

    def test_a_blank_receipt_is_denied_by_the_head_line_guard(self):
        """Issue #128: the removed "receipt is empty" arm was unreachable.

        Both guards ahead of it require a line that is not blank -- one
        ``HEAD: `` line and one ``VERDICT: `` line -- so no receipt could
        ever arrive at that arm with nothing to index. This pins the guard
        that actually denies a blank receipt, in the exact message it
        denies with, for every shape of blankness; deleting the HEAD-line
        guard changes the message and turns this test red, which is what
        the removed arm never did for anything.
        """
        head = "a" * 40
        for name, sample in (
            ("empty string", ""),
            ("one newline", "\n"),
            ("crlf", "\r\n"),
            ("spaces", "   "),
            ("tab", "\t"),
            ("blank lines", "\n\n\n"),
            ("mixed whitespace lines", "  \n\t\n  "),
            ("crlf blank lines", "\r\n\r\n"),
            ("verdict only, no head", "VERDICT: APPROVE\n"),
        ):
            with self.subTest(blank=name):
                self.assertEqual(
                    self.adversarial_receipt_denial(
                        sample,
                        head,
                        actor=self.REVIEW_ACTOR,
                        resource_kind="pull-request",
                    ),
                    "receipt must bind exactly one expected HEAD line",
                )
        # A head line alone is already enough to make the removed arm
        # unreachable: the receipt is non-blank by the time indexing runs,
        # and the shape checks below it are what deny from here on.
        self.assertEqual(
            self.adversarial_receipt_denial(
                f"HEAD: {head}\n",
                head,
                actor=self.REVIEW_ACTOR,
                resource_kind="pull-request",
            ),
            "receipt must contain exactly one supported VERDICT line",
        )
        self.assertEqual(
            self.adversarial_receipt_denial(
                f"HEAD: {head}\nVERDICT: APPROVE\n",
                head,
                actor=self.REVIEW_ACTOR,
                resource_kind="pull-request",
            ),
            "final non-empty line must be adversarial reviewer signature",
        )

    def test_pr_template_reviewer_signature_matches_the_contract(self):
        """Issue #128: template and contract asked for different last lines."""
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(
            encoding="utf-8"
        )
        self.require_adversarial_signature_parity(agents, template)
        canonical = "- <Agent> (adversarial reviewer)"
        # The template asks for exactly what a reviewer following AGENTS.md
        # will write, and what this suite's own receipt validator accepts.
        self.assertIn(canonical, template)
        self.assertIsNone(
            self.adversarial_receipt_denial(
                self.require_adversarial_review_governance(agents),
                "a" * 40,
                actor=self.REVIEW_ACTOR,
                resource_kind="pull-request",
            )
        )
        drifted = "- <distinct context> (adversarial reviewer)"
        self.assertEqual(template.count(canonical), 1)
        for name, changed_template in (
            ("drift back to the pre-#128 shape", template.replace(canonical, drifted, 1)),
            ("signature dropped", template.replace(canonical, "", 1)),
            # The three below keep the canonical string SOMEWHERE in the file
            # and still have to die, which is what makes the bullet-scoped
            # half of the guard load-bearing rather than decoration.
            (
                "canonical signature relocated out of the reviewer bullet",
                template.replace(canonical, drifted, 1) + "\n" + canonical + "\n",
            ),
            (
                "reviewer bullet stops naming a signature at all",
                template.replace(
                    "and final `" + canonical + "`: pending",
                    "and final signature: pending",
                    1,
                )
                + "\n"
                + canonical
                + "\n",
            ),
            (
                "second signature shape offered inside the bullet",
                template.replace(
                    canonical + "`: pending",
                    canonical + "` or `" + drifted + "`: pending",
                    1,
                ),
            ),
            (
                "reviewer bullet anchor removed",
                template.replace("- Independent normal-comment verdict", "", 1),
            ),
        ):
            with self.subTest(template_mutant=name), self.assertRaises(ValueError):
                self.require_adversarial_signature_parity(agents, changed_template)
        # AGENTS.md states the shape in three places; a partial edit leaves
        # the contract self-consistent, so these mutants replace every one.
        self.assertEqual(agents.count(canonical), 3)
        for name, changed_agents in (
            ("contract drops the signature shape", agents.replace(canonical, "")),
            (
                "contract drifts to the template's old shape",
                agents.replace(canonical, drifted),
            ),
        ):
            with self.subTest(agents_mutant=name), self.assertRaises(ValueError):
                self.require_adversarial_signature_parity(changed_agents, template)

    def test_ready_flip_rule_is_parity_pinned_and_main_worker_ceremony_stays_retired(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(
            encoding="utf-8"
        )
        runbook = (ROOT / "docs" / "release-governance.md").read_text(encoding="utf-8")
        self.require_ready_flip_governance(agents, template, runbook)
        for owner, token in (
            ("agents", "independent adversarial review"),
            ("agents", "approved the exact final head"),
            ("agents", "all required checks are green"),
            ("agents", "coordinator flips Ready"),
            ("agents", "No third distinct-context pass"),
            ("agents", "a fresh exact-head APPROVE receipt exists"),
            ("runbook", "no further"),
            ("runbook", "distinct-context receipt"),
            ("runbook", "Draft/Ready state"),
            ("runbook", "repository owner alone merges"),
        ):
            changed = {"agents": agents, "template": template, "runbook": runbook}
            if owner == "agents":
                prefix, marker, suffix = changed[owner].partition(
                    "### After review, Ready"
                )
                self.assertTrue(marker)
                self.assertIn(token, suffix)
                changed[owner] = prefix + marker + suffix.replace(token, "", 1)
            else:
                self.assertIn(token, changed[owner])
                changed[owner] = changed[owner].replace(token, "")
            with self.subTest(deletion=owner + ":" + token), self.assertRaises(ValueError):
                self.require_ready_flip_governance(
                    changed["agents"], changed["template"], changed["runbook"]
                )
        inverted = agents.replace(
            "No third distinct-context pass is required.",
            "A third distinct-context pass is required.",
            1,
        )
        self.assertNotEqual(inverted, agents)
        with self.subTest(inversion="agents"), self.assertRaises(ValueError):
            self.require_ready_flip_governance(inverted, template, runbook)
        # Review round 1: a contradictory permission INSERTED BESIDE the
        # canonical rule survived the substring pin. The closed-section pin
        # must kill exactly that mutant, in both governance documents.
        contradiction = agents.replace(
            "No third distinct-context pass is required.",
            "No third distinct-context pass is required. The coordinator may "
            "also flip Ready before review or required checks complete.",
            1,
        )
        self.assertNotEqual(contradiction, agents)
        with self.subTest(contradiction="agents"), self.assertRaises(ValueError):
            self.require_ready_flip_governance(contradiction, template, runbook)
        anchor = "Draft/Ready state, and the repository owner alone merges."
        self.assertEqual(runbook.count(anchor), 1)
        runbook_contradiction = runbook.replace(
            anchor,
            anchor + " The coordinator may publish without the owner when "
            "every check is green.",
            1,
        )
        self.assertNotEqual(runbook_contradiction, runbook)
        with self.subTest(contradiction="runbook"), self.assertRaises(ValueError):
            self.require_ready_flip_governance(agents, template, runbook_contradiction)
        for owner in ("agents", "template", "runbook"):
            for retired in (
                "ROLE: MAIN-WORKER",
                "- <distinct context> (Main Worker)",
                "Main Worker receipt",
            ):
                changed = {"agents": agents, "template": template, "runbook": runbook}
                changed[owner] = changed[owner] + "\n" + retired + "\n"
                with self.subTest(
                    reintroduction=owner + ":" + retired
                ), self.assertRaises(ValueError):
                    self.require_ready_flip_governance(
                        changed["agents"], changed["template"], changed["runbook"]
                    )
        # Issue #198 / review round 2 and the post-merge audits: the window
        # pin let a competing Ready authority survive OUTSIDE it. Every
        # surviving mutant both reviewers reproduced must now die under the
        # document-wide closure — both displacement directions, the operative
        # Merge-readiness bullet, a second runbook paragraph, the template,
        # and the lost-pin direction.
        competing = (
            "The coordinator may also flip Ready before review or required "
            "checks complete."
        )
        displaced_before = agents.replace(
            "### After review, Ready",
            competing + "\n\n### After review, Ready",
            1,
        )
        self.assertNotEqual(displaced_before, agents)
        with self.subTest(closure="displaced-before-rule"), self.assertRaises(
            ValueError
        ):
            self.require_ready_flip_governance(displaced_before, template, runbook)
        displaced_after = agents.replace(
            "## GitHub conventions",
            competing + "\n\n## GitHub conventions",
            1,
        )
        self.assertNotEqual(displaced_after, agents)
        with self.subTest(closure="displaced-after-delimiter"), self.assertRaises(
            ValueError
        ):
            self.require_ready_flip_governance(displaced_after, template, runbook)
        bullet_rewrite = agents.replace(
            "- **Merge readiness.**",
            "- **Merge readiness.** The coordinator may flip Ready before "
            "review completes.",
            1,
        )
        self.assertNotEqual(bullet_rewrite, agents)
        with self.subTest(closure="merge-readiness-bullet"), self.assertRaises(
            ValueError
        ):
            self.require_ready_flip_governance(bullet_rewrite, template, runbook)
        with self.subTest(closure="second-runbook-paragraph"), self.assertRaises(
            ValueError
        ):
            self.require_ready_flip_governance(
                agents, template, runbook + "\n\n" + competing + "\n"
            )
        with self.subTest(closure="template-addition"), self.assertRaises(ValueError):
            self.require_ready_flip_governance(
                agents, template + "\n\n" + competing + "\n", runbook
            )
        self.assertEqual(agents.count("a ready state"), 1)
        lost_pin = agents.replace("a ready state", "an approved state", 1)
        with self.subTest(closure="pinned-region-lost"), self.assertRaises(ValueError):
            self.require_ready_flip_governance(lost_pin, template, runbook)

    def test_manifest_scan_and_alias_audit_doctrine_is_truthful_and_load_bearing(self):
        paths = {
            "agents": ROOT / "AGENTS.md",
            "readme": ROOT / "README.md",
            "security": ROOT / "SECURITY.md",
            "runbook": ROOT / "docs/release-governance.md",
            "changelog": ROOT / "CHANGELOG.md",
        }
        documents = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
        self.require_manifest_scan_audit_docs(**documents)
        for owner, token in (
            ("agents", "weekly read-only audit"),
            ("agents", "raw per-platform SBOM binding"),
            ("readme", "canonical JSON evidence manifest"),
            ("readme", "strict raw SBOM schema"),
            ("security", "public semantic aliases"),
            ("security", "strict raw platform SBOM subject"),
            ("runbook", "Workflow-level success alone is insufficient"),
            ("runbook", "New publication creates a draft Release"),
            ("runbook", "downloads and compares the manifest again"),
            ("runbook", "scheduled detection is defense in depth"),
            ("changelog", "one deterministic evidence manifest"),
            ("changelog", "strict raw two-platform SBOM schemas"),
        ):
            changed = dict(documents)
            changed[owner] = changed[owner].replace(token, "", 1)
            with self.subTest(document=owner, token=token), self.assertRaises(ValueError):
                self.require_manifest_scan_audit_docs(**changed)
        changed = dict(documents)
        changed["readme"] += "\nzero-asset inventory\n"
        with self.assertRaises(ValueError):
            self.require_manifest_scan_audit_docs(**changed)

    # Issue #272: AGENTS.md hands whole topics to files under docs/ by naming
    # them in backticks, and nothing checked that a named file exists — the
    # PR #270 review deleted one and the suite stayed green. Existence only:
    # what a target says stays review's job. Names are compared entry by
    # entry, so a case-only rename fails on a case-insensitive filesystem
    # exactly as it does on CI's.
    AGENTS_DOCS_POINTER = re.compile(r"`(docs/[^`\s]+\.md)`")

    @staticmethod
    def require_agents_docs_pointers_exist(agents: str, root: Path) -> list[str]:
        pointers = sorted(set(GovernanceParityTests.AGENTS_DOCS_POINTER.findall(agents)))
        if not pointers:
            raise ValueError("AGENTS.md names no `docs/<name>.md` pointer; the walk proves nothing")

        def exists(pointer: str) -> bool:
            current = root
            for part in pointer.split("/"):
                try:
                    names = {entry.name for entry in os.scandir(current)}
                except OSError:
                    return False
                if part not in names:
                    return False
                current = current / part
            return current.is_file()

        missing = [pointer for pointer in pointers if not exists(pointer)]
        if missing:
            raise ValueError("AGENTS.md points at missing docs file(s): " + ", ".join(missing))
        return pointers

    def test_every_agents_docs_pointer_names_an_existing_file(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        pointers = self.require_agents_docs_pointers_exist(agents, ROOT)
        with self.assertRaises(ValueError):
            self.require_agents_docs_pointers_exist(agents.replace("`docs/", "`doc/"), ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            copy_root = Path(tmp)
            shutil.copytree(ROOT / "docs", copy_root / "docs")
            self.require_agents_docs_pointers_exist(agents, copy_root)
            for pointer in pointers:
                target = copy_root / pointer
                for mutation, moved in (
                    ("deleted", None),
                    ("renamed", target.with_name("relocated-" + target.name)),
                    ("case-renamed", target.with_name(target.name.upper())),
                    ("made-a-directory", target),
                ):
                    target.unlink()
                    if moved == target:
                        target.mkdir()
                    elif moved is not None:
                        shutil.copyfile(ROOT / pointer, moved)
                    with self.subTest(pointer=pointer, mutation=mutation):
                        with self.assertRaises(ValueError) as caught:
                            self.require_agents_docs_pointers_exist(agents, copy_root)
                        self.assertIn(pointer, str(caught.exception))
                    if moved == target:
                        target.rmdir()
                    elif moved is not None:
                        moved.unlink()
                    shutil.copyfile(ROOT / pointer, target)
                    self.require_agents_docs_pointers_exist(agents, copy_root)


class TrivyDevelopmentDependencyShellPathTests(unittest.TestCase):
    STEP = "Reject high or critical source dependency vulnerabilities"

    @staticmethod
    def folded_run_block() -> str:
        """The scanner step's FOLDED run scalar, joined the way YAML folds it."""
        return workflow_run_block(
            "pr-gate.yml", TrivyDevelopmentDependencyShellPathTests.STEP, fold=True
        )

    def execute(self, block: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".trivy-dev-shell-") as temporary:
            fixture = Path(temporary)
            frontend = fixture / "frontend"
            frontend.mkdir()
            (frontend / "package.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "devDependencies": {"fixture-vulnerable-dev": "1.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            (frontend / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {
                                "devDependencies": {"fixture-vulnerable-dev": "1.0.0"}
                            },
                            "node_modules/fixture-vulnerable-dev": {
                                "version": "1.0.0",
                                "dev": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            prelude = r'''
trivy() {
  if [[ " $* " != *' --include-dev-deps '* ]]; then
    return 0
  fi
  "${TEST_PYTHON}" -c 'import json,sys; value=json.load(open("frontend/package-lock.json", encoding="utf-8")); package=value["packages"].get("node_modules/fixture-vulnerable-dev"); sys.exit(42 if package == {"version":"1.0.0","dev":True} else 3)'
}
'''
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_PYTHON": ExistingImageShellPathTests.bash_path(sys.executable),
                    "RUNNER_TEMP": ".",
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=fixture,
                env=environment,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_vulnerable_frontend_dev_dependency_reaches_scanner_input(self):
        block = self.folded_run_block()
        self.assertIn("trivy fs --scanners vuln --include-dev-deps", block)
        detected = self.execute(block)
        self.assertEqual(detected.returncode, 42, detected.stdout + detected.stderr)
        suppressed = self.execute(block.replace(" --include-dev-deps", "", 1))
        self.assertEqual(suppressed.returncode, 0, suppressed.stdout + suppressed.stderr)


class GoCoverageShellPathTests(unittest.TestCase):
    """The coverage-floor step, executed as the runner executes it."""

    @staticmethod
    def run_block(step_name: str) -> str:
        """One pr-gate step's run block, verbatim from the workflow."""
        return workflow_run_block("pr-gate.yml", step_name)

    @staticmethod
    def execute(block: str, prelude: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".coverage-shell-") as temporary:
            fixture = Path(temporary)
            output = fixture / "github-output.txt"
            env = os.environ.copy()
            env.update(environment)
            env.update(
                {
                    "RUNNER_TEMP": ExistingImageShellPathTests.bash_path(fixture),
                    "GITHUB_OUTPUT": ExistingImageShellPathTests.bash_path(output),
                    "GITHUB_STEP_SUMMARY": ExistingImageShellPathTests.bash_path(fixture / "summary"),
                }
            )
            return subprocess.run(
                [ExistingImageShellPathTests.bash_executable()],
                cwd=fixture,
                env=env,
                check=False,
                input=prelude + "\n" + block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=30,
            )

    def test_go_measurement_passes_only_after_the_tool_and_floor_pass(self):
        block = self.run_block("Enforce and report Go test coverage")
        prelude = r'''
go() {
  if [ "${1-}" = test ]; then
    printf 'mode: atomic\n' > "${RUNNER_TEMP}/site.cover.out"
  else
    printf 'total: (statements) %s%%\n' "$REPORTED"
    return "${TOOL_STATUS:-0}"
  fi
}
'''
        for total, status, accepted in (("94.9", "0", True), ("94.0", "0", True),
                                        ("93.9", "0", False), ("92", "0", False),
                                        ("94.9", "47", False), ("101", "0", False),
                                        ("NaN", "0", False), ("", "0", False)):
            with self.subTest(total=total, status=status):
                result = self.execute(block, prelude, {
                    "REPORTED": total, "TOOL_STATUS": status, "GO_COVERAGE_FLOOR": "94.0",
                })
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                self.assertEqual("meets the" in result.stdout, accepted, result.stdout + result.stderr)


class NoArtifactWiringTests(unittest.TestCase):
    """The verdict artifact and orchestrator classification stay fail closed."""

    def test_gate_publishes_the_transition_verdict_on_protected_pushes_only(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        self.assertIn("name: transition-verdict", gate)
        self.assertIn("if-no-files-found: error", gate)
        self.assertIn("transition-verdict.json", gate)
        upload = gate.split("- name: Publish the transition verdict", 1)[1].split("- name: ", 1)[0]
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", upload)
        self.assertIn("overwrite: true", upload)
        self.assertRegex(gate, r"uses: actions/upload-artifact@[0-9a-f]{40}")

    def test_orchestrator_classifies_before_any_release_effect(self):
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        self.assertIn("id: classify", orchestrator)
        self.assertEqual(
            orchestrator.count("if: steps.classify.outputs.class == 'artifact'"),
            2,
            "every release-effect step must be gated on the artifact class",
        )
        self.assertIn('test "${rederived_class}" = "${claimed_class}"', orchestrator)
        self.assertIn("expected exactly one transition-verdict artifact", orchestrator)
        self.assertIn('test "${claimed_source}" = "${COMPLETED_SHA}"', orchestrator)
        # The verdict fetch must stay RUN-scoped: GitHub serves no
        # attempts/<n>/artifacts endpoint (404), so an attempt-scoped fetch
        # would fail every dispatch and end all releases. Pinned as a
        # negative assertion so the 404 shape cannot be reintroduced, with
        # the upload-side overwrite as the actual re-attempt defense.
        # Pin the single artifacts-fetch LINE rather than the whole file, so
        # prose explaining the 404 cannot satisfy or break this assertion.
        artifact_fetch = [
            line for line in orchestrator.splitlines() if "/artifacts?per_page=" in line
        ]
        self.assertEqual(len(artifact_fetch), 1, artifact_fetch)
        self.assertIn(
            "/actions/runs/${MAIN_RUN_ID}/artifacts?per_page=100", artifact_fetch[0]
        )
        self.assertNotIn("attempts", artifact_fetch[0])
        self.assertIn("overwrite: true", (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8"))
        # claimed_base is verdict-supplied and the class re-derivation is
        # parameterised by it, so the no-artifact path must anchor on a base
        # the verdict cannot choose. Pin every load-bearing piece: the shape
        # check, the Actions-record lookup, the ancestry sanity check, and
        # the four-lock equality against that independent head.
        no_artifact = orchestrator.split("no-artifact)", 1)[1].split(
            "DENY: unknown transition class", 1
        )[0]
        self.assertIn('[[ "${claimed_base}" =~ ^[0-9a-f]{40}$ ]]', orchestrator)
        self.assertIn("actions/workflows/pr-gate.yml/runs?branch=main", no_artifact)
        self.assertIn("no earlier successful protected-main gate run", no_artifact)
        self.assertIn('[[ "${previous_head}" =~ ^[0-9a-f]{40}$ ]]', no_artifact)
        self.assertIn(
            'git merge-base --is-ancestor "${previous_head}" "${COMPLETED_SHA}"', no_artifact
        )
        self.assertIn(
            'git diff --quiet "${previous_head}" "${COMPLETED_SHA}" -- "${lock}"', no_artifact
        )
        for lock in ("VERSION", "chart/Chart.yaml", "chart/values.yaml", "CHANGELOG.md"):
            self.assertIn(lock, no_artifact.split("for lock in", 1)[1].split("\n", 1)[0])
        self.assertIn("DENY: unknown transition class", orchestrator)
        self.assertIn("publisher not dispatched", orchestrator)
        self.assertLess(
            orchestrator.index("id: classify"),
            orchestrator.index("Dispatch the successful-main-bound publisher"),
        )
        cumulative = orchestrator.split("no-artifact)", 1)[1].split("*)", 1)[0]
        # The tag is created by the publisher minutes later, so the cumulative
        # gap is anchored on the tagged release HEAD recovered from the
        # validated mainline — the boundary commit advanced over the release
        # push's own trailing non-documentation commits — never on a tag that
        # may not exist yet.
        self.assertIn("release-window", cumulative)
        self.assertIn('anchor="${boundary_sha}"', cumulative)
        self.assertIn('anchor="${commit}"', cumulative)
        self.assertIn('--base "${anchor}"', cumulative)
        self.assertIn("= no-artifact", cumulative)

    @staticmethod
    def require_tests_never_reach_the_shipped_stages(dockerfile: str) -> None:
        """The classifier's Go-test allowance (release_contract.py, issue #16)
        holds only while no stage that ships is built FROM the stage the test
        battery ran in: the compile stage is reached by the battery's empty
        pass mark alone, and the image takes exactly the binary."""
        stages: dict[str, tuple[str, list[str]]] = {}
        name = ""
        # Continuation lines are joined first, so an instruction split over
        # several lines is read whole; comments say nothing.
        for line in re.sub(r"\\\n", " ", dockerfile).splitlines():
            line = " ".join(line.split())
            if not line or line.startswith("#"):
                continue
            found = re.fullmatch(r"FROM (?:--platform=\S+ )?(\S+)(?: AS (\S+))?", line)
            if found:
                name = found.group(2) or "final"
                if name in stages:
                    raise ValueError(f"the Dockerfile declares stage {name} twice")
                stages[name] = (found.group(1), [])
            elif not name:
                raise ValueError(f"the Dockerfile has an instruction before its first FROM: {line}")
            else:
                stages[name][1].append(line)
        batteries = {stage for stage, (_, body) in stages.items() if any(re.search(r"\bgo test\b", line) for line in body)}
        if batteries != {"backend-test"}:
            raise ValueError(f"the test battery runs in {sorted(batteries)}, not in backend-test alone")
        for stage, (parent, _) in stages.items():
            if parent == "backend-test":
                raise ValueError(f"stage {stage} is built FROM the tested tree")
        if stages["backend-test"][0] != "backend-source" or stages.get("backend", ("", []))[0] != "backend-source":
            raise ValueError("the battery and the compile stage must both start from backend-source")
        mentions = [line for stage in ("backend", "final") for line in stages.get(stage, ("", []))[1] if "backend-test" in line]
        if mentions != ["COPY --from=backend-test /backend-tested /backend-tested"]:
            raise ValueError(f"the shipped stages take {mentions} from the battery, not its pass mark alone")
        shipped = [line for line in stages.get("final", ("", []))[1] if line.split(" ", 1)[0] in ("ADD", "COPY", "RUN")]
        if shipped != ["COPY --from=backend --chown=65532:65532 /out/hospedajedonlolo-com /hospedajedonlolo-com"]:
            raise ValueError(f"the final image no longer takes exactly the binary from the compile stage: {shipped}")

    def test_tests_never_reach_the_shipped_stages(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.require_tests_never_reach_the_shipped_stages(dockerfile)
        for label, old, new in (
            ("compile stage built from the tested tree", "FROM backend-source AS backend\n", "FROM backend-test AS backend\n"),
            ("tests folded back into the compile", 'RUN GOOS="${TARGETOS}"', 'RUN go test ./... && GOOS="${TARGETOS}"'),
            ("tests on a continuation line of the compile", "    go build -trimpath", "    go test ./... && go build -trimpath"),
            ("the battery's tree copied in", "COPY --from=backend-test /backend-tested /backend-tested", "COPY --from=backend-test /src /src"),
            ("the battery mounted into the compile", "ARG TARGETOS\n", "RUN --mount=type=bind,from=backend-test,target=/t true\nARG TARGETOS\n"),
            ("the battery moved into the source stage", "COPY site/ site/\n", "COPY site/ site/\nRUN go test ./...\n"),
            ("the image takes the battery's mark", "COPY --from=backend --chown=65532:65532", "COPY --from=backend-test /backend-tested /x\nCOPY --from=backend --chown=65532:65532"),
            ("the image takes more than the binary", "USER 65532:65532\n", "COPY --from=backend /src /src\nUSER 65532:65532\n"),
            ("the battery dropped", "RUN go test ./... && touch /backend-tested", "RUN touch /backend-tested"),
            # The image's base swapped for the tested tree: its one COPY is
            # unchanged, so only the FROM rule can see it.
            (
                "the image built FROM the tested tree",
                "FROM gcr.io/distroless/static-debian13:nonroot@",
                "FROM backend-test\n# was gcr.io/distroless/static-debian13:nonroot@",
            ),
        ):
            self.assertEqual(dockerfile.count(old), 1, label)
            with self.subTest(mutant=label), self.assertRaises(ValueError):
                self.require_tests_never_reach_the_shipped_stages(dockerfile.replace(old, new))
        # Instructions are read whole: the compile reflowed onto one line and
        # the image's COPY split over two still pass, so the check follows
        # what Docker runs, not how the file happens to wrap.
        reflowed = dockerfile.replace('GOARCH="${TARGETARCH}" \\\n    go build', 'GOARCH="${TARGETARCH}" go build', 1).replace(
            "COPY --from=backend --chown=65532:65532 /out/", "COPY --from=backend \\\n    --chown=65532:65532 /out/", 1
        )
        self.assertIn('GOARCH="${TARGETARCH}" go build', reflowed)
        self.assertIn("COPY --from=backend \\\n    --chown", reflowed)
        self.require_tests_never_reach_the_shipped_stages(reflowed)

    def test_agents_contract_names_the_exact_code_allowlist(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for name in sorted(RC.DOCUMENTATION_FILES) + sorted(RC.NO_ARTIFACT_TREES):
            self.assertIn(f"`{name}`", agents)
        for tree in RC.GO_SOURCE_TREES:
            self.assertIn(f"`{tree}`", agents)
        self.assertIn("Go `_test.go` files", agents)
        self.assertIn("Markdown files under `docs/`", agents)
        self.assertIn("no-artifact", agents)
        self.assertIn("nothing to version, sign, scan", agents)


class WorkflowStructureTests(unittest.TestCase):
    @staticmethod
    def require_publication_identity_oracles(contract: str, publisher: str) -> None:
        contract_literals = (
            'EXPECTED_REPOSITORY = "snaraj/hospedajedonlolo.com"\n',
            'EXPECTED_IMAGE = "ghcr.io/snaraj/hospedajedonlolo-com"\n',
            'EXPECTED_CHART = "ghcr.io/snaraj/charts/hospedajedonlolo-com"\n',
            'GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"\n',
            "GITHUB_ACTIONS_BOT_ID = 41898282\n",
        )
        publisher_literals = (
            "  IMAGE: ghcr.io/snaraj/hospedajedonlolo-com\n",
            "  CHART: ghcr.io/snaraj/charts/hospedajedonlolo-com\n",
        )
        for literal in contract_literals:
            if contract.count(literal) != 1:
                raise ValueError(f"release identity oracle changed: {literal.strip()}")
        for literal in publisher_literals:
            if publisher.count(literal) != 1:
                raise ValueError(f"publisher identity oracle changed: {literal.strip()}")

    @staticmethod
    def require_gate_holds_no_write_path(gate: str, orchestrator: str) -> None:
        """The gate holds no badge job and no write grant, and the release
        path follows the PR gate alone.

        This repository publishes no coverage badge, so there is no
        `coverage-badges.yml` and no hand-off artifact: the coverage floor is
        enforced and reported in the step summary, nothing more. A write
        grant or a badge job reappearing in the gate would put a mutation
        path inside the very inventory the publisher authorizes against.
        """
        if "\n  coverage-badges:\n" in gate or re.search(r"(?m)^\s+[a-z-]+:\s*write\s*$", gate):
            raise ValueError("the PR gate must hold no badge job and no write grant")
        if (ROOT / ".github" / "workflows" / "coverage-badges.yml").exists():
            raise ValueError("this repository publishes no coverage badge")
        application = gate.split("\n  application:\n", 1)[1].split("\n  chart:\n", 1)[0]
        for retired in ("coverage-totals", "upload-artifact@"):
            if retired in application:
                raise ValueError(f"the application job hands nothing over: {retired}")
        if orchestrator.count("    workflows: [PR gate]\n") != 1:
            raise ValueError("the release orchestrator must follow exactly the PR gate")

    @staticmethod
    def require_vulnerability_and_alias_audit(
        gate: str, publisher: str, audit: str, installer: str
    ) -> None:
        installer_requirements = (
            "TRIVY_VERSION=v0.72.0",
            "TRIVY_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
            "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz",
            'test "$("${install_root}/trivy" --version | awk \'NR == 1 {print $2}\')" = "${TRIVY_VERSION#v}"',
        )
        for required in installer_requirements:
            if required not in installer:
                raise ValueError(f"checksum-verified Trivy installer changed: {required}")
        combined = gate + publisher + audit + installer
        for forbidden in ("aquasecurity/trivy-action@", "aquasecurity/setup-trivy@", "trivy:latest"):
            if forbidden in combined:
                raise ValueError(f"mutable Trivy installation path introduced: {forbidden}")

        source_scan = (
            "trivy fs --scanners vuln --include-dev-deps\n"
            "          --severity HIGH,CRITICAL --exit-code 1\n"
            '          --ignore-unfixed=false --timeout 10m\n'
            '          --cache-dir "${RUNNER_TEMP}/trivy-source-cache" .'
        )
        image_scan = (
            "trivy image --scanners vuln\n"
            "          --severity HIGH,CRITICAL --exit-code 1\n"
            '          --ignore-unfixed=false --timeout 10m\n'
            '          --cache-dir "${RUNNER_TEMP}/trivy-image-cache"\n'
            '          "${IMAGE}@${{ steps.image.outputs.digest }}"'
        )
        if source_scan not in gate or image_scan not in publisher:
            raise ValueError("source or final-digest vulnerability gate is not exact")
        # --include-dev-deps is a source/lockfile concept: valid on `trivy
        # fs` (the source_scan above), an unknown flag on `trivy image` in
        # the installed version (issue #73 — FATAL before any scan ran, on
        # both the publisher's final-digest gate and the recurring audit).
        for surface, name in ((publisher, "publisher"), (audit, "audit")):
            if "trivy image --scanners vuln --include-dev-deps" in surface:
                raise ValueError(
                    f"{name} final-image trivy invocation carries the unknown "
                    "--include-dev-deps flag; that gate never executes"
                )

        audit_requirements = (
            "schedule:",
            "cron: '17 8 * * 1'",
            "workflow_dispatch:",
            "group: release-alias-audit-${{ github.sha }}",
            "cancel-in-progress: false",
            "timeout-minutes: 45",
            "contents: read",
            "packages: read",
            "ref: main",
            "persist-credentials: false",
            "fetch-depth: 0",
            '"repos/${GITHUB_REPOSITORY}/releases/latest"',
            "manifest-record",
            "release-notes",
            "release-record",
            '"repos/${GITHUB_REPOSITORY}/actions/runs/${main_run_id}"',
            "main-run-record",
            'git merge-base --is-ancestor "${source_sha}" HEAD',
            '"repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}"',
            '"repos/${GITHUB_REPOSITORY}/git/tags/${tag_object}"',
            "tag-record",
            'manifests/${reference}',
            'test "$(registry_digest "${image_repository}" "${tag}"',
            'test "$(registry_digest "${chart_repository}" "${version}"',
            '"${IMAGE}@${image_digest}"',
            '"${CHART}@${chart_digest}"',
            "cosign verify-attestation --type slsaprovenance1 --output json",
            "attestation-statement",
            "--predicate-output",
            # Issue #137: the audit re-derives the same builder binding. It
            # audits a release built by an earlier run and the canonical
            # manifest records `main_run_id` (the PR-gate run), never the
            # publisher run, so the run identity is read once from the
            # predicate and required of every platform.
            '--builder-run-id "${builder_run_id}"',
            "jq -er '.runDetails.builder.id'",
            "attestation-set",
            'git archive "${source_sha}" chart | tar -x -C "${expected_source}"',
            'diff -ru --no-dereference "${expected_tree}/${chart_name}" "${published_tree}/${chart_name}"',
            "trivy image --scanners vuln",
            "--severity HIGH,CRITICAL --exit-code 1",
            "sbom-index-record",
            "sbom-layer-record",
            "sbom-statement",
            '"${IMAGE}@${image_digest}"',
        )
        for required in audit_requirements:
            if required not in audit:
                raise ValueError(f"recurring alias audit lost exact binding: {required}")
        # The audit's three actions are bound by behaviour, not inventory
        # (issue #16): each is a full commit SHA with a version comment, and
        # the very pin the publisher runs, so the audit re-verifies with the
        # tooling that made the release and an actions bump moves both files
        # instead of this test. It used to require three literal SHAs, which
        # reddened every Dependabot bump of a shared action.
        uses = re.compile(r"^\s*(?:-\s+)?uses:\s+([^@\s]+)@(\S*)(.*)$", re.MULTILINE)
        for action in ("actions/checkout", "docker/setup-buildx-action", "sigstore/cosign-installer"):
            audit_pins = {(ref, rest) for name, ref, rest in uses.findall(audit) if name == action}
            publisher_pins = {(ref, rest) for name, ref, rest in uses.findall(publisher) if name == action}
            if not audit_pins:
                raise ValueError(f"recurring alias audit lost {action}")
            for ref, rest in audit_pins | publisher_pins:
                if not re.fullmatch(r"[0-9a-f]{40}", ref) or not re.fullmatch(r" # v[0-9]+(\.[0-9]+)*", rest):
                    raise ValueError(f"{action}@{ref}{rest} is not a full commit SHA with a version comment")
            if audit_pins != publisher_pins:
                raise ValueError(
                    f"recurring alias audit pins {action} unlike the publisher: "
                    f"{sorted(audit_pins)} vs {sorted(publisher_pins)}"
                )
        for forbidden in (
            "contents: write",
            "packages: write",
            "id-token: write",
            "gh api --method POST",
            "gh api --method PUT",
            "gh api --method PATCH",
            "gh api --method DELETE",
            "gh release create",
            "gh release edit",
            "cosign sign",
            "cosign attest",
            "helm push",
            "docker buildx build",
            "PLATFORM_RELEASE_APP_PRIVATE_KEY",
            "IMMUTABLE_SETTINGS_TOKEN",
        ):
            if forbidden in audit:
                raise ValueError(f"read-only alias audit gained mutation or App authority: {forbidden}")

    @staticmethod
    def require_tag_partition(publisher: str) -> None:
        image = publisher.split("id: image_state", 1)[1].split("id: chart_state", 1)[0]
        chart = publisher.split("id: chart_state", 1)[1]
        if 'manifests/${TAG}' not in image or 'manifests/${VERSION}' in image:
            raise ValueError("image registry tag must be plain vX.Y.Z exactly once")
        if 'manifests/${VERSION}' not in chart or 'manifests/${TAG}' in chart:
            raise ValueError("Helm registry tag must be numeric SemVer exactly once")
        if 'helm package chart --version "${TAG}"' in publisher or '--version "v${version}"' in publisher:
            raise ValueError("Helm package version must not gain a v or double-v prefix")

    @staticmethod
    def require_chart_digest_embed(publisher: str, audit: str) -> None:
        """Pin ADR 0016 step 1: the published chart carries the released digest.

        Three properties, and the middle one is the sharp one:

        1. The substitution reads `steps.image.outputs.digest` -- the value the
           HIGH/CRITICAL gate, `cosign sign`, and the provenance attestation
           already accepted -- and runs AFTER all three.
        2. It runs BEFORE every `helm package`, exactly once, so the
           classifier's reproducibility re-package and the publish step's
           archive are the same bytes. A substitution moved into the publish
           step alone misclassifies every idempotent re-run as `burned`.
        3. Each packaging step re-reads what IT produced, so a substitution
           that became a no-op fails the run instead of publishing a chart no
           registry can resolve.

        Asserted over NORMALIZED step objects and executable run-block content
        for the same reason the gate-order pin above is: a `#` line is never
        executed, and this step's own comment names both subcommands and
        `helm package`. Counting raw occurrences would let prose satisfy --
        or break -- a side-effect property.
        """
        embed_name = "Embed the resolved image digest into the chart values"
        attest_name = "Attach the BuildKit SLSA provenance as cosign attestations"
        classify_name = "Classify an absent, complete, or burned chart version"
        publish_name = "Publish and sign an absent chart version"
        steps = job_steps(publisher, "publish")
        by_name: dict[str, list[dict]] = {}
        for step in steps:
            by_name.setdefault(step["name"], []).append(step)
        for name in (embed_name, attest_name, classify_name, publish_name):
            if len(by_name.get(name, ())) != 1:
                raise ValueError(f"publisher must carry exactly one parsed step named: {name}")
        position = {name: by_name[name][0]["position"] for name in by_name}
        if not (
            position[attest_name]
            < position[embed_name]
            < position[classify_name]
            < position[publish_name]
        ):
            raise ValueError(
                "the chart digest substitution must follow signing and attestation and "
                "precede every helm package"
            )
        embed_command = (
            "python3 -I -B scripts/ci/release_contract.py chart-digest-embed "
            '--values chart/values.yaml --digest "${DIGEST}"'
        )
        assert_command = "python3 -I -B scripts/ci/release_contract.py chart-digest-assert --values "
        every_command = [command for step in steps for command in executable_commands(step["run"])]
        packagings = [command for command in every_command if command.startswith("helm package")]
        embeds = [command for command in every_command if "chart-digest-embed" in command]
        assertions = [command for command in every_command if "chart-digest-assert" in command]
        if embeds != [embed_command]:
            raise ValueError(
                "publisher must substitute the resolved digest into the working tree exactly "
                f"once, ahead of both packagings; found {embeds}"
            )
        if len(packagings) != 2:
            raise ValueError(f"publisher must package the chart exactly twice, found {len(packagings)}")
        if len(assertions) != 3:
            raise ValueError(
                "publisher must re-read the values it wrote and both charts it packaged, "
                f"found {len(assertions)} assertions"
            )
        embed_step = by_name[embed_name][0]
        embed_commands = executable_commands(embed_step["run"])
        for required in (
            '[[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'test "${DIGEST}" != "sha256:' + "0" * 64 + '"',
            embed_command,
            assert_command + 'chart/values.yaml --digest "${DIGEST}"',
        ):
            if required not in embed_commands:
                raise ValueError(f"chart digest substitution lost exact binding: {required}")
        for name in (embed_name, classify_name, publish_name):
            step = by_name[name][0]
            if "DIGEST: ${{ steps.image.outputs.digest }}" not in "\n".join(step["lines"]):
                raise ValueError(
                    f"step {name!r} must bind the scanned, signed digest, never re-derive one"
                )
        for name, values_path in (
            (classify_name, '"${expected_tree}/${chart_name}/values.yaml"'),
            (publish_name, '"${packaged_tree}/${chart_name}/values.yaml"'),
        ):
            commands = executable_commands(by_name[name][0]["run"])
            packaged = [index for index, command in enumerate(commands) if command.startswith("helm package")]
            reread = [index for index, command in enumerate(commands) if "chart-digest-assert" in command]
            if len(packaged) != 1 or len(reread) != 1:
                raise ValueError(f"step {name!r} must package once and re-read what it packaged once")
            if reread[0] < packaged[0]:
                raise ValueError(f"step {name!r} must assert the digest AFTER packaging, not before")
            expected = assert_command + values_path + ' --digest "${DIGEST}"'
            if commands[reread[0]] != expected:
                raise ValueError(f"step {name!r} must re-read the chart it packaged: {expected}")
            if any("chart-digest-embed" in command for command in commands):
                raise ValueError(
                    f"step {name!r} must not carry its own substitution; ONE shared "
                    "substitution is what keeps the two packagings identical"
                )
        # The recurring audit repackages the RELEASE SOURCE TREE and diffs it
        # against the published chart, so it must reproduce the publisher's
        # substitution with the digest THAT RELEASE'S manifest binds, or the
        # audit reports a false mismatch on every release from now on.
        if audit.count("chart-digest-embed") != 1 or audit.count("chart-digest-assert") != 1:
            raise ValueError("recurring audit must reproduce the one substitution and re-read the published chart")
        if audit.index("chart-digest-embed") > audit.index("helm package"):
            raise ValueError("recurring audit must substitute before packaging the release source tree")
        for required in (
            '--values "${expected_source}/chart/values.yaml" --digest "${image_digest}"',
            '--values "${published_tree}/${chart_name}/values.yaml" --digest "${image_digest}"',
            'diff -ru --no-dereference "${expected_tree}/${chart_name}" "${published_tree}/${chart_name}"',
        ):
            if required not in audit:
                raise ValueError(f"recurring audit lost exact chart digest binding: {required}")

    @staticmethod
    def require_exact_release_wiring(orchestrator: str, publisher: str) -> None:
        for required in (
            "fetch-depth: 0",
            "release-window",
        ):
            if required not in orchestrator:
                raise ValueError(f"orchestrator lost exact release wiring: {required}")
        for forbidden in (
            "tag-state",
            "tag-record",
            "classify_tag",
            "git/tags",
            "git/refs",
            "gh api --method POST",
            "gh release create",
            "cosign sign",
            "helm push",
            "docker build",
        ):
            if forbidden in orchestrator:
                raise ValueError(f"orchestrator gained publication mutation: {forbidden}")
        for required in (
            "tag-record",
            "tag-state",
            "classify_tag exact >/dev/null",
            "classify_tag absent >/dev/null",
            'tagger[name]=${tagger_name}',
            'tagger[email]=${tagger_email}',
            'tagger[date]=${tagger_date}',
            "cosign attest --yes --predicate",
            '--type "https://slsa.dev/provenance/v1"',
            "cosign verify-attestation --type slsaprovenance1 --output json",
            "release-state",
            "release-manifest",
            "manifest-record",
            "release-notes",
            'state="$(classify_release)"',
            '[ "${state}" = prepared ]',
            '[ "${state}" = staged ]',
            '[ "${state}" = exact ]',
            'gh release create "${tag}" "${manifest}" --draft --verify-tag',
            'gh release upload "${tag}" "${manifest}"',
            'gh release edit "${tag}" --draft=false',
            'test "${upload_verified}" = true',
            "verify_asset_bytes",
            'cmp --silent "${manifest}" "${observed}"',
            "/releases/tags/${tag}",
            "releases?per_page=100",
            '[.[] | select(.tag_name == $tag)] | length',
            '"${releases_page}" > "${existing}"',
            "a stranded draft needs operator resolution",
            "DENY: releases list probe returned HTTP",
            "X-GitHub-Api-Version: 2026-03-10",
            "for attempt in 1 2 3 4 5",
            'test "${race_verified}" = true',
            "Re-bind the immutable Release to the exact annotated tag",
            "terminal-tag-ref.json",
            "terminal-tag-object.json",
            "terminal-release.json",
            "terminal-release-manifest.json",
            # Issue #137: the SLSA builder identity is bound to the run that
            # actually produced the bytes. The freshly built image is bound to
            # THIS run; the reused image cannot be (it was built by an earlier
            # attempt for the same source SHA, and GITHUB_RUN_ID there would
            # classify every recoverable retry `burned`), so its run identity is
            # read from the predicate and required of every platform.
            '--builder-run-id "${GITHUB_RUN_ID}"',
            '--builder-run-id "${builder_run_id}"',
            "jq -er '.runDetails.builder.id'",
        ):
            if required not in publisher:
                raise ValueError(f"publisher lost exact release wiring: {required}")
        for repeated in (
            "attestation-statement",
            "attestation-set",
            "cosign verify-attestation --type slsaprovenance1 --output json",
            "--predicate-output",
            "--builder-run-id",
        ):
            if publisher.count(repeated) < 2:
                raise ValueError(f"publisher must use {repeated} for both existing and new images")
        if publisher.count("classify_tag exact >/dev/null") < 3:
            raise ValueError("publisher must verify exact tag state before reuse, after a race, and after create")
        if publisher.count('state="$(classify_release)"') < 3:
            raise ValueError("publisher must reclassify Release state across create and publish response loss")
        if publisher.count("verify_asset_bytes") < 3:
            raise ValueError("publisher must verify manifest bytes before and after publication")
        if publisher.count("tag-state") < 1 or publisher.count("tag-record") < 1:
            raise ValueError("publisher must bind the tag both before artifacts and after immutable Release state")
        if publisher.count("X-GitHub-Api-Version: 2026-03-10") < 5:
            raise ValueError(
                "publisher must version the main-run, Release, the draft-visible "
                "releases list, and both terminal tag REST reads"
            )
        build_heading = "      - name: Build and publish both production architectures"
        image_resolver_heading = "      - name: Resolve the one image digest for later stages"
        if publisher.count(build_heading) != 1 or publisher.count(image_resolver_heading) != 1:
            raise ValueError("publisher must have one exact Buildx step and image resolver")
        build_step = publisher.split(build_heading, 1)[1].split(image_resolver_heading, 1)[0]
        tags = re.search(
            r"(?m)^          tags: \|\n((?:            .*\n)+?)          labels: \|$",
            build_step,
        )
        exact_image_tag = "            ${{ env.IMAGE }}:${{ steps.release.outputs.tag }}\n"
        if tags is None or tags.group(1) != exact_image_tag:
            raise ValueError("Buildx must push only the intended semantic image alias")
        sbom_values = re.findall(r"(?m)^          sbom:\s*(.*?)\s*$", build_step)
        if sbom_values != ["true"]:
            raise ValueError("Buildx must produce exactly one enabled SBOM source")
        chart_heading = "      - name: Publish and sign an absent chart version"
        chart_resolver_heading = "      - name: Resolve the one chart digest for release notes"
        if publisher.count(chart_heading) != 1 or publisher.count(chart_resolver_heading) != 1:
            raise ValueError("publisher must have one exact Helm push step and chart resolver")
        chart_step = publisher.split(chart_heading, 1)[1].split(chart_resolver_heading, 1)[0]
        exact_chart_push = (
            'helm push "${RUNNER_TEMP}/${chart_name}-${version}.tgz" '
            '"oci://${CHART%/*}"'
        )
        if chart_step.count("helm push") != 1 or exact_chart_push not in chart_step:
            raise ValueError("Helm must push only the intended numeric chart alias")
        alias_heading = (
            "      - name: Re-bind both public aliases and exact platform SBOMs before sealing evidence"
        )
        if publisher.count(alias_heading) != 1:
            raise ValueError("publisher must have exactly one terminal registry-alias rebind")
        alias_step = publisher.split(alias_heading, 1)[1].split(
            "      - name: Build the deterministic release evidence manifest", 1
        )[0]
        for required in (
            'fetch_exact_alias "${image_repository}" "${IMAGE_ALIAS}"',
            'image "${IMAGE_DIGEST}" "${image_token}"',
            'fetch_exact_alias "${chart_repository}" "${CHART_ALIAS}"',
            'chart "${CHART_DIGEST}" "${chart_token}"',
            'test "${observed}" = "${expected}"',
            "sbom-index-record",
            "sbom-layer-record",
            "sbom-statement",
        ):
            if required not in alias_step:
                raise ValueError(f"terminal registry-alias rebind lost exact proof: {required}")
        tag_index = publisher.index("      - name: Create or verify the exact annotated tag")
        registry_index = publisher.index("      - name: Classify an absent, complete, or burned image tag")
        if tag_index >= registry_index:
            raise ValueError("exact tag transaction must precede registry side effects")
        # Issue #69: this chain pinned the scan's position relative to the
        # alias/manifest/Release stages but said NOTHING about signing, so a
        # publisher that signed the digest and gated it afterwards satisfied
        # every assertion -- and did, leaving a HIGH-vulnerable v0.1.15 image
        # in GHCR carrying this repository's release identity. The gate now
        # stands between digest resolution and the signing pair, and both
        # signing steps carry pinned positions so the order cannot silently
        # revert.
        scan_heading = (
            "      - name: Reject high or critical vulnerabilities in the final image digest"
        )
        sign_heading = "      - name: Sign the immutable image digest"
        attest_heading = (
            "      - name: Attach the BuildKit SLSA provenance as cosign attestations"
        )
        for heading in (scan_heading, sign_heading, attest_heading):
            if publisher.count(heading) != 1:
                raise ValueError(f"publisher must carry exactly one step named:{heading.split(':', 1)[1]}")
        digest_index = publisher.index(image_resolver_heading)
        scan_index = publisher.index(scan_heading)
        sign_index = publisher.index(sign_heading)
        attest_index = publisher.index(attest_heading)
        alias_index = publisher.index(alias_heading)
        manifest_index = publisher.index(
            "      - name: Build the deterministic release evidence manifest"
        )
        release_index = publisher.index(
            "      - name: Stage, verify, and publish the exact GitHub release"
        )
        terminal_index = publisher.index(
            "      - name: Re-bind the immutable Release to the exact annotated tag"
        )
        if not (
            registry_index
            < digest_index
            < scan_index
            < sign_index
            < attest_index
            < alias_index
            < manifest_index
            < release_index
            < terminal_index
        ):
            raise ValueError(
                "digest resolution, HIGH/CRITICAL gate, signing, attestation, alias "
                "rebind, manifest, Release, and terminal binding order is not exact"
            )
        # The heading chain above pins where the CANONICAL names sit; it does
        # not constrain what any other step does. A step named anything at all
        # could run `cosign sign` over the resolved digest before the gate and
        # satisfy every index comparison -- issue #69's failure mode restored
        # under a new name, reproduced live against the full suite. The real
        # property is a side-effect property, so it is asserted over normalized
        # step objects and executable run-block content in execution order.
        steps = job_steps(publisher, "publish")
        by_name: dict[str, list[dict]] = {}
        for step in steps:
            by_name.setdefault(step["name"], []).append(step)
        gate_name = scan_heading.split(": ", 1)[1]
        sign_name = sign_heading.split(": ", 1)[1]
        for name in (gate_name, sign_name, attest_heading.split(": ", 1)[1]):
            if len(by_name.get(name, ())) != 1:
                raise ValueError(f"publisher must carry exactly one parsed step named: {name}")
        gate_position = by_name[gate_name][0]["position"]
        sign_position = by_name[sign_name][0]["position"]
        signings = signing_invocations(steps)
        early = [entry for entry in signings if entry[0] <= gate_position]
        if early:
            raise ValueError(
                "no signing-capable command may run at or before the HIGH/CRITICAL "
                f"image gate: {early[0][2]} in step {early[0][1]}"
            )
        for step in steps:
            if step["position"] > gate_position or not step["uses"]:
                continue
            action = step["uses"].split("@", 1)[0].strip()
            if action in SIGNING_TOOL_INSTALLERS:
                continue
            if SIGNING_CAPABLE_ACTION.search(action):
                raise ValueError(
                    f"signing-capable action before the HIGH/CRITICAL image gate: {action}"
                )
        image_signatures = [
            entry
            for entry in signings
            if "${IMAGE}@" in entry[2] and IMAGE_SIGNATURE.search(entry[2])
        ]
        if len(image_signatures) != 1:
            raise ValueError(
                "publisher must sign the resolved image digest exactly once, found "
                f"{len(image_signatures)}"
            )
        if image_signatures[0][0] != sign_position:
            raise ValueError(
                f"the one image-signing command must belong to the pinned step: {sign_name}"
            )
        if len([entry for entry in signings if entry[0] == sign_position]) != 1:
            raise ValueError("the pinned image-signing step must carry exactly one signing command")
        # The gate covers the reused `complete` digest as well as the freshly
        # built one: an image published by an earlier run is rescanned against
        # today's vulnerability database before it can be released. A build-only
        # condition here would restore exactly that hole. Asserted over
        # NORMALIZED keys: `if :` and `"if":` are live conditionals the runner
        # honors and a `^        if:` regex does not see.
        if "if" in by_name[gate_name][0]["keys"]:
            raise ValueError(
                "the final-digest vulnerability gate must stay unconditional"
            )
        if terminal_index <= release_index or publisher.rfind("      - name:") != terminal_index:
            raise ValueError("the post-immutable tag rebind must be the terminal publisher step")
        terminal = publisher[terminal_index:]
        for required in (
            "/git/ref/tags/${TAG}",
            "/git/tags/${tag_object}",
            "/releases/tags/${TAG}",
            "release-record",
            "terminal-release-manifest.json",
            'cmp --silent "${manifest}" "${observed_manifest}"',
            '--source-sha "${SOURCE_SHA}"',
            '--message "Release ${TAG} from ${SOURCE_SHA}"',
            "--tagger-name 'github-actions[bot]'",
            "--tagger-email '41898282+github-actions[bot]@users.noreply.github.com'",
            '--tagger-date "$(git show -s --format=%cI "${SOURCE_SHA}")"',
        ):
            if required not in terminal:
                raise ValueError(f"terminal post-immutable tag binding lost: {required}")
        for forbidden in (
            "gh release create",
            "gh api --method POST",
            "cosign sign",
            "helm push",
            "docker build",
            "git push",
            "git tag",
        ):
            if forbidden in terminal:
                raise ValueError(f"publication mutation follows terminal tag binding: {forbidden}")
        for forbidden in ("cosign download attestation", 'git rev-list -n 1 "${tag}"'):
            if forbidden in publisher:
                raise ValueError(f"publisher contains unauthenticated or local-ref verifier: {forbidden}")
        if "--clobber" in publisher:
            raise ValueError("manifest retry must never replace an existing Release asset")

    @staticmethod
    def require_successful_main_privilege_boundary(orchestrator: str, publisher: str) -> None:
        for expected in (
            f"  IMAGE: {RC.EXPECTED_IMAGE}\n",
            f"  CHART: {RC.EXPECTED_CHART}\n",
        ):
            if publisher.count(expected) != 1:
                raise ValueError(f"publisher package destination is not exact: {expected.strip()}")
        if any(marker not in publisher for marker in (
            '\n  authorize:\n', '\n  repository_settings:\n', '\n  publish:\n'
        )):
            raise ValueError("publisher must separate authorization, settings, and publication")
        authorize = publisher.split('\n  authorize:\n', 1)[1].split('\n  repository_settings:\n', 1)[0]
        settings = publisher.split('\n  repository_settings:\n', 1)[1].split('\n  publish:\n', 1)[0]
        publish = publisher.split('\n  publish:\n', 1)[1]
        authorize_exact_counts = {
            'actions/runs/${MAIN_RUN_ID}': 2,
            '--run-id "${MAIN_RUN_ID}"': 2,
            '--repository "${GITHUB_REPOSITORY}"': 2,
            '--source-sha "${SOURCE_SHA}"': 4,
        }
        for required, expected_count in authorize_exact_counts.items():
            actual_count = authorize.count(required)
            if actual_count != expected_count:
                raise ValueError(
                    "read-only authorization binding count changed: "
                    f"{required} expected {expected_count}, got {actual_count}"
                )
        for required in (
            "actions: read",
            "contents: read",
            "main-run-record",
            'actions/runs/${MAIN_RUN_ID}',
            "authority/scripts/ci/release_contract.py",
            "ref: ${{ github.sha }}",
            "path: authority",
            '--run-id "${MAIN_RUN_ID}"',
            '--repository "${GITHUB_REPOSITORY}"',
            '--source-sha "${SOURCE_SHA}"',
            'test "${authorized_sha}" = "${SOURCE_SHA}"',
            'source_sha=%s\\n',
        ):
            if required not in authorize:
                raise ValueError(f"read-only main-run authorization lost: {required}")
        for forbidden in ("contents: write", "packages: write", "id-token: write"):
            if forbidden in authorize:
                raise ValueError(f"authorization job gained privilege: {forbidden}")
        for required in (
            "needs: authorize",
            "if: needs.authorize.result == 'success'",
            "environment: platform-release",
            "timeout-minutes: 10",
            "contents: read",
            "ref: ${{ needs.authorize.outputs.source_sha }}",
            "persist-credentials: false",
            "Require authoritative release settings before side effects",
            "          GH_TOKEN: ${{ github.token }}\n",
            "release_contract.py settings-preflight",
            "release_contract.py settings-receipt",
            '--repository "${GITHUB_REPOSITORY}"',
        ):
            if required not in settings:
                raise ValueError(f"authoritative settings boundary lost: {required}")
        for forbidden in (
            "contents: write", "packages: write", "id-token: write", "actions: write",
            "secrets.", "vars.", "create-github-app-token", "uses: actions/create-",
        ):
            if forbidden in settings:
                raise ValueError(f"settings job gained authority beyond its read-only token: {forbidden}")
        # The job's grants are exactly `contents: read`: its token reads the
        # public settings surface and nothing more.
        if re.findall(r"(?m)^      [a-z-]+: (?:read|write)$", settings) != ["      contents: read"]:
            raise ValueError("settings job permissions must be exactly contents: read")
        # Normalized keys, not raw text: `outputs :` would export a value
        # past this job's boundary while `^    outputs:` saw nothing (same
        # fail-open class as the publisher gate's conditional pin).
        if "outputs" in normalized_keys(settings, 4):
            raise ValueError("settings job must not export its token or any output")
        # The token reaches exactly the one preflight step, through that
        # step's own env, and appears nowhere else in the release path.
        if publisher.count("GH_TOKEN: ${{ github.token }}") != 1 or settings.count(
            "GH_TOKEN: ${{ github.token }}"
        ) != 1:
            raise ValueError("the settings token must be declared once, in the preflight step")
        if "${{ github.token }}" in orchestrator or "${{ github.token }}" in publish or "${{ github.token }}" in authorize:
            raise ValueError("the settings token spelling crossed into another job")
        for required in (
            "needs: [authorize, repository_settings]",
            "needs.authorize.result == 'success' &&",
            "needs.repository_settings.result == 'success'",
            "ref: ${{ needs.authorize.outputs.source_sha }}",
            "fetch-depth: 0",
            "persist-credentials: false",
            "SOURCE_SHA: ${{ needs.authorize.outputs.source_sha }}",
            'workflow-ref "${GITHUB_WORKFLOW_REF}"',
            '--image "${IMAGE}"',
            '--chart "${CHART}"',
            "@refs/heads/main",
        ):
            if required not in publish:
                raise ValueError(f"privileged publication lost main-run dependency: {required}")
        bind_heading = "      - name: Bind protected workflow, authorized checkout, and committed locks"
        install_heading = "      - name: Install checksum-verified tools"
        tag_heading = "      - name: Create or verify the exact annotated tag"
        if publish.count(bind_heading) != 1 or publish.count(install_heading) != 1:
            raise ValueError("publisher pre-side-effect binding step is not exact")
        binding = publish.split(bind_heading, 1)[1].split(install_heading, 1)[0]
        for required in (
            '--repository "${GITHUB_REPOSITORY}"',
            '--workflow-ref "${GITHUB_WORKFLOW_REF}"',
            '--image "${IMAGE}"',
            '--chart "${CHART}"',
        ):
            if binding.count(required) != 1:
                raise ValueError(f"pre-side-effect package identity binding lost: {required}")
        if publish.index(bind_heading) >= publish.index(tag_heading):
            raise ValueError("package identities must bind before the first publication side effect")
        for required in (
            "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}",
            "--ref main",
            '-f main_run_id="${MAIN_RUN_ID}"',
        ):
            if required not in orchestrator:
                raise ValueError(f"orchestrator lost exact main-run dispatch binding: {required}")
        orchestrator_exact_counts = {
            # Three: the classify step (which fetches the gate's verdict
            # artifact from that exact run), the binding step, and the
            # dispatch step. Every one of them names the same event run ID.
            "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}": 3,
            "--ref main": 1,
            '-f main_run_id="${MAIN_RUN_ID}"': 1,
        }
        for required, expected_count in orchestrator_exact_counts.items():
            actual_count = orchestrator.count(required)
            if actual_count != expected_count:
                raise ValueError(
                    "orchestrator dispatch binding count changed: "
                    f"{required} expected {expected_count}, got {actual_count}"
                )
        if '--ref "${TAG}"' in orchestrator:
            raise ValueError("publisher workflow must never be selected from a mutable tag ref")
        for required in ("main_run_id:", "source_sha:", "release-${{ inputs.source_sha }}"):
            if required not in publisher:
                raise ValueError(f"publisher dispatch interface lost: {required}")
        for forbidden in ("GITHUB_SHA", "GITHUB_REF_NAME", "@${GITHUB_REF}"):
            if forbidden in publisher:
                raise ValueError(f"publisher retained tag-selected or event-SHA authority: {forbidden}")

    @staticmethod
    def require_deadlines_and_concurrency(
        gate: str, codeql: str, orchestrator: str, publisher: str
    ) -> None:
        expected_deadlines = (
            (gate, (20, 10, 30, 15, 45)),
            (codeql, (30,)),
            (orchestrator, (15,)),
            (publisher, (10, 10, 90)),
        )
        for workflow, minutes in expected_deadlines:
            actual = tuple(
                int(value)
                for value in re.findall(r"(?m)^    timeout-minutes: ([0-9]+)$", workflow)
            )
            if actual != minutes:
                raise ValueError(f"job deadlines changed: expected {minutes}, got {actual}")
        requirements = (
            (gate, "group: pr-gate-${{ github.event.pull_request.number || github.run_id }}"),
            (gate, "cancel-in-progress: true"),
            (codeql, "group: codeql-${{ github.event.pull_request.number || github.sha }}"),
            # TIGHTENED, not relaxed. The SHA-keyed group already stops one
            # main push cancelling another, which is what this test is named
            # for. It cannot stop the weekly SCHEDULE run, which resolves
            # `github.sha` to the same default-branch head and so lands in the
            # same group as a push run still analysing that commit. The
            # publisher requires a CodeQL run with event=push at that exact
            # SHA and conclusion=success, and CodeQL fires on push once per
            # push, so one cancellation makes the version permanently
            # unreleasable. Pinning the guarded expression admits strictly
            # fewer workflows than `cancel-in-progress: true` did: reverting
            # to the bare `true` now fails this contract. Matches the sibling
            # repository, which already pins this exact string.
            (codeql, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}"),
            (orchestrator, "group: release-after-main-${{ github.event.workflow_run.head_sha }}"),
            (orchestrator, "cancel-in-progress: false"),
            (publisher, "group: release-${{ inputs.source_sha }}"),
            (publisher, "cancel-in-progress: false"),
        )
        for workflow, required in requirements:
            if required not in workflow:
                raise ValueError(f"source-SHA concurrency contract changed: {required}")
        if "github.ref" in codeql:
            raise ValueError("CodeQL main runs must not share a branch-ref cancellation key")

    def test_no_distinct_main_sha_can_be_canceled_or_share_release_identity(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        orchestrator = (ROOT / ".github/workflows/release-after-main.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        contract = (ROOT / "scripts/ci/release_contract.py").read_text(encoding="utf-8")
        self.require_publication_identity_oracles(contract, publisher)
        tuple_contract_mutant = contract.replace(
            'EXPECTED_IMAGE = "ghcr.io/snaraj/hospedajedonlolo-com"',
            'EXPECTED_IMAGE = "ghcr.io/snaraj/hospedajedonlolo.com"',
            1,
        ).replace(
            'EXPECTED_CHART = "ghcr.io/snaraj/charts/hospedajedonlolo-com"',
            'EXPECTED_CHART = "ghcr.io/snaraj/charts/hospedajedonlolo.com"',
            1,
        )
        tuple_publisher_mutant = publisher.replace(
            "  IMAGE: ghcr.io/snaraj/hospedajedonlolo-com",
            "  IMAGE: ghcr.io/snaraj/hospedajedonlolo.com",
            1,
        ).replace(
            "  CHART: ghcr.io/snaraj/charts/hospedajedonlolo-com",
            "  CHART: ghcr.io/snaraj/charts/hospedajedonlolo.com",
            1,
        )
        bot_contract_mutant = contract.replace(
            'GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"',
            'GITHUB_ACTIONS_BOT_LOGIN = "foreign-writer"',
            1,
        ).replace(
            "GITHUB_ACTIONS_BOT_ID = 41898282",
            "GITHUB_ACTIONS_BOT_ID = 1",
            1,
        )
        for name, changed_contract, changed_publisher in (
            ("paired package config", tuple_contract_mutant, tuple_publisher_mutant),
            ("paired bot login and ID", bot_contract_mutant, publisher),
        ):
            with self.subTest(identity_oracle_mutant=name), self.assertRaises(ValueError):
                self.require_publication_identity_oracles(
                    changed_contract, changed_publisher
                )
        self.require_gate_holds_no_write_path(gate, orchestrator)
        old_badge_job = (
            "\n  coverage-badges:\n    needs: application\n    runs-on: ubuntu-24.04\n"
            "    permissions:\n      contents: write\n    steps:\n      - run: git push\n"
        )
        handoff = (
            "      - name: Upload the measured totals\n"
            "        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n"
            "        with:\n          name: coverage-totals\n"
        )
        for name, changed_gate, changed_orchestrator in (
            ("badge job back in the gate", gate + old_badge_job, orchestrator),
            ("write grant in the gate", gate.replace(
                "    permissions:\n      contents: read\n", "    permissions:\n      contents: write\n", 1), orchestrator),
            ("hand-off artifact back in application", gate.replace(
                "\n  chart:\n", "\n" + handoff + "\n  chart:\n", 1), orchestrator),
            ("release follows badges", gate, orchestrator.replace(
                "workflows: [PR gate]", "workflows: [PR gate, Coverage badges]", 1)),
        ):
            self.assertNotEqual((changed_gate, changed_orchestrator), (gate, orchestrator), name)
            with self.subTest(write_path_mutant=name), self.assertRaises(ValueError):
                self.require_gate_holds_no_write_path(changed_gate, changed_orchestrator)
        self.assertIn("github.event.pull_request.number || github.run_id", gate)
        self.assertNotIn("queue:", gate + orchestrator + publisher)
        self.assertIn("workflow_run:", orchestrator)
        self.assertIn("github.event.workflow_run.head_sha", orchestrator)
        self.assertIn("actions: write", orchestrator)
        self.assertIn("workflow_dispatch:", publisher)
        self.assertIn("source_sha:", publisher)
        self.assertNotRegex(publisher, r"(?ms)^\s+push:\s*\n\s+tags:")
        self.require_successful_main_privilege_boundary(orchestrator, publisher)
        package_mutants = (
            publisher.replace(
                f"  IMAGE: {RC.EXPECTED_IMAGE}",
                "  IMAGE: ghcr.io/snaraj/hospedajedonlolo.com",
                1,
            ),
            publisher.replace(
                f"  CHART: {RC.EXPECTED_CHART}",
                "  CHART: ghcr.io/snaraj/charts/hospedajedonlolo.com",
                1,
            ),
            publisher.replace('--image "${IMAGE}"', "", 1),
            publisher.replace('--chart "${CHART}"', "", 1),
        )
        for index, mutant in enumerate(package_mutants):
            with self.subTest(package_identity_mutant=index), self.assertRaises(ValueError):
                self.require_successful_main_privilege_boundary(orchestrator, mutant)
        self.require_deadlines_and_concurrency(gate, codeql, orchestrator, publisher)
        self.assertGreaterEqual(publisher.count("registry-state --http-status"), 2)
        self.assertGreaterEqual(publisher.count("--data-urlencode \"scope=repository:"), 2)
        self.assertGreaterEqual(publisher.count("docker-content-digest:"), 2)
        self.assertNotIn("if ! docker buildx imagetools inspect \"${IMAGE}:${TAG}\"", publisher)
        self.assertNotIn("if ! helm show chart", publisher)
        self.require_tag_partition(publisher)
        for mutation in (
            publisher.replace('manifests/${VERSION}', 'manifests/${TAG}'),
            publisher.replace('manifests/${VERSION}', 'manifests/v${VERSION}'),
            publisher.replace('--version "${version}"', '--version "v${version}"'),
        ):
            with self.assertRaises(ValueError):
                self.require_tag_partition(mutation)
        self.assertIn('helm package chart --version "${version}" --app-version "${version}"', publisher)
        self.assertNotIn("targetCommitish", publisher)
        self.assertIn('gh release create "${tag}" "${manifest}" --draft --verify-tag', publisher)
        self.require_exact_release_wiring(orchestrator, publisher)
        for value in ("false", "null", "enabled", ""):
            mutant = publisher.replace(
                "          sbom: true",
                f"          sbom: {value}" if value else "",
                1,
            )
            with self.subTest(sbom_producer_mutant=value or "removed"), self.assertRaises(
                ValueError
            ):
                self.require_exact_release_wiring(orchestrator, mutant)
        for owner, token in (
            ("orchestrator", "MAIN_RUN_ID: ${{ github.event.workflow_run.id }}"),
            ("orchestrator", "--ref main"),
            ("orchestrator", '-f main_run_id="${MAIN_RUN_ID}"'),
            ("publisher", "actions: read"),
            ("publisher", "main-run-record"),
            ("publisher", 'actions/runs/${MAIN_RUN_ID}'),
            ("publisher", '--run-id "${MAIN_RUN_ID}"'),
            ("publisher", '--repository "${GITHUB_REPOSITORY}"'),
            ("publisher", '--source-sha "${SOURCE_SHA}"'),
            ("publisher", 'test "${authorized_sha}" = "${SOURCE_SHA}"'),
            ("publisher", "needs: [authorize, repository_settings]"),
            ("publisher", "needs.repository_settings.result == 'success'"),
            ("publisher", "ref: ${{ needs.authorize.outputs.source_sha }}"),
            ("publisher", 'workflow-ref "${GITHUB_WORKFLOW_REF}"'),
            ("publisher", '--image "${IMAGE}"'),
            ("publisher", '--chart "${CHART}"'),
            ("publisher", "environment: platform-release"),
            ("publisher", "          GH_TOKEN: ${{ github.token }}\n"),
            ("publisher", "release_contract.py settings-preflight"),
            ("publisher", "release_contract.py settings-receipt"),
        ):
            changed_orchestrator = orchestrator.replace(token, "", 1) if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "", 1) if owner == "publisher" else publisher
            with self.subTest(main_run_mutation=token), self.assertRaises(ValueError):
                self.require_successful_main_privilege_boundary(changed_orchestrator, changed_publisher)
        with self.assertRaises(ValueError):
            self.require_successful_main_privilege_boundary(
                orchestrator.replace("--ref main", '--ref "${TAG}"', 1),
                publisher,
            )
        token_line = "          GH_TOKEN: ${{ github.token }}\n"
        for name, mutant in (
            ("write grant", publisher.replace(
                "    environment: platform-release\n    permissions:\n      contents: read\n",
                "    environment: platform-release\n    permissions:\n      contents: write\n", 1)),
            ("second grant", publisher.replace(
                "    environment: platform-release\n    permissions:\n      contents: read\n",
                "    environment: platform-release\n    permissions:\n      contents: read\n      actions: read\n", 1)),
            ("App token step", publisher.replace(
                "      - name: Require authoritative release settings before side effects\n",
                "      - name: Mint\n        uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0\n"
                "      - name: Require authoritative release settings before side effects\n", 1)),
            ("stored secret", publisher.replace(token_line, "          GH_TOKEN: ${{ secrets.SETTINGS_TOKEN }}\n", 1)),
            ("variable", publisher.replace(token_line, "          GH_TOKEN: ${{ vars.SETTINGS_TOKEN }}\n", 1)),
            ("token crosses into publish", publisher.replace(
                "\n  publish:\n", "\n  publish:\n    env:\n      SETTINGS: ${{ github.token }}\n", 1)),
            ("token declared twice", publisher.replace(token_line, token_line + token_line, 1)),
            ("token removed", publisher.replace(token_line, "", 1)),
        ):
            self.assertNotEqual(mutant, publisher, name)
            with self.subTest(settings_privilege_poison=name), self.assertRaises(ValueError):
                self.require_successful_main_privilege_boundary(orchestrator, mutant)
        workflow_mutants = (
            (gate.replace("    timeout-minutes: 20\n", "", 1), codeql, orchestrator, publisher),
            (gate, codeql.replace("github.sha", "github.ref", 1), orchestrator, publisher),
            (gate, codeql, orchestrator.replace("cancel-in-progress: false", "cancel-in-progress: true", 1), publisher),
            (gate, codeql, orchestrator, publisher.replace("group: release-${{ inputs.source_sha }}", "group: release-main", 1)),
            (gate, codeql, orchestrator, publisher.replace("    timeout-minutes: 90\n", "", 1)),
        )
        for mutation in workflow_mutants:
            with self.subTest(deadline_or_concurrency_mutant=True), self.assertRaises(ValueError):
                self.require_deadlines_and_concurrency(*mutation)
        for owner, token in (
            ("orchestrator", "fetch-depth: 0"),
            ("orchestrator", "release-window"),
            ("publisher", "tag-state"),
            ("publisher", "classify_tag exact >/dev/null"),
            ("publisher", "classify_tag absent >/dev/null"),
            ("publisher", 'tagger[name]=${tagger_name}'),
            ("publisher", 'tagger[email]=${tagger_email}'),
            ("publisher", 'tagger[date]=${tagger_date}'),
            ("publisher", "tag-record"),
            ("publisher", "      - name: Re-bind both public aliases and exact platform SBOMs before sealing evidence"),
            ("publisher", "            ${{ env.IMAGE }}:${{ steps.release.outputs.tag }}"),
            ("publisher", 'helm push "${RUNNER_TEMP}/${chart_name}-${version}.tgz" "oci://${CHART%/*}"'),
            ("publisher", 'test "${observed}" = "${expected}"'),
            ("publisher", "cosign attest --yes --predicate"),
            ("publisher", '--type "https://slsa.dev/provenance/v1"'),
            ("publisher", "cosign verify-attestation --type slsaprovenance1 --output json"),
            ("publisher", "release-state"),
            ("publisher", "release-manifest"),
            ("publisher", "manifest-record"),
            ("publisher", "release-notes"),
            ("publisher", 'state="$(classify_release)"'),
            ("publisher", '[ "${state}" = prepared ]'),
            ("publisher", '[ "${state}" = staged ]'),
            ("publisher", 'gh release create "${tag}" "${manifest}" --draft --verify-tag'),
            ("publisher", 'gh release upload "${tag}" "${manifest}"'),
            ("publisher", 'gh release edit "${tag}" --draft=false'),
            ("publisher", 'test "${upload_verified}" = true'),
            ("publisher", "verify_asset_bytes"),
            ("publisher", 'cmp --silent "${manifest}" "${observed}"'),
            ("publisher", "/releases/tags/${tag}"),
            ("publisher", "releases?per_page=100"),
            ("publisher", '[.[] | select(.tag_name == $tag)] | length'),
            ("publisher", '"${releases_page}" > "${existing}"'),
            ("publisher", "a stranded draft needs operator resolution"),
            ("publisher", "DENY: releases list probe returned HTTP"),
            ("publisher", "X-GitHub-Api-Version: 2026-03-10"),
            ("publisher", "for attempt in 1 2 3 4 5"),
            ("publisher", 'test "${race_verified}" = true'),
            ("publisher", "Re-bind the immutable Release to the exact annotated tag"),
            ("publisher", "terminal-tag-ref.json"),
            ("publisher", "terminal-tag-object.json"),
            ("publisher", "terminal-release.json"),
            ("publisher", "terminal-release-manifest.json"),
            ("publisher", 'cmp --silent "${manifest}" "${observed_manifest}"'),
            ("publisher", "attestation-statement"),
            ("publisher", "attestation-set"),
            ("publisher", "--predicate-output"),
        ):
            changed_orchestrator = orchestrator.replace(token, "") if owner == "orchestrator" else orchestrator
            changed_publisher = publisher.replace(token, "") if owner == "publisher" else publisher
            with self.subTest(wiring_mutation=token), self.assertRaises(ValueError):
                self.require_exact_release_wiring(changed_orchestrator, changed_publisher)
        exact_image_tag = "            ${{ env.IMAGE }}:${{ steps.release.outputs.tag }}"
        exact_chart_target = '"oci://${CHART%/*}"'
        alias_heading = (
            "      - name: Re-bind both public aliases and exact platform SBOMs before sealing evidence"
        )
        manifest_heading = "      - name: Build the deterministic release evidence manifest"
        displaced_alias = publisher.replace(alias_heading, "      - name: Displaced alias proof", 1)
        displaced_alias = displaced_alias.replace(
            manifest_heading, manifest_heading + "\n" + alias_heading, 1
        )
        for mutant_name, mutation in (
            (
                "foreign image alias",
                publisher.replace(exact_image_tag, "            ghcr.io/foreign/repo:latest", 1),
            ),
            (
                "extra image alias",
                publisher.replace(
                    exact_image_tag,
                    exact_image_tag + "\n            ghcr.io/foreign/repo:latest",
                    1,
                ),
            ),
            (
                "foreign chart alias",
                publisher.replace(exact_chart_target, '"oci://ghcr.io/foreign/charts"', 1),
            ),
            ("alias proof moved after manifest", displaced_alias),
        ):
            with self.subTest(registry_alias_mutant=mutant_name), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator, mutation)
        # Issue #69's exact regression, rebuilt from the live publisher text:
        # lift the whole gate step out from between digest resolution and
        # signing, and drop it back where it used to live -- after the SLSA
        # attestation step, immediately before the chart classifier. That is
        # byte-for-byte the sign-then-gate publisher that signed a HIGH image.
        scan_heading = (
            "      - name: Reject high or critical vulnerabilities in the final image digest"
        )
        sign_heading = "      - name: Sign the immutable image digest"
        chart_state_heading = "      - name: Classify an absent, complete, or burned chart version"
        gate_block = scan_heading + publisher.split(scan_heading, 1)[1].split(sign_heading, 1)[0]
        gate_removed = publisher.replace(gate_block, "", 1)
        for mutant_name, mutation in (
            (
                "gate restored below signing and attestation",
                gate_removed.replace(chart_state_heading, gate_block + chart_state_heading, 1),
            ),
            ("gate deleted outright", gate_removed),
            (
                "gate skipped for a reused digest",
                publisher.replace(
                    scan_heading + "\n",
                    scan_heading
                    + "\n        if: steps.image_state.outputs.state == 'absent'\n",
                    1,
                ),
            ),
            (
                "second gate copy added so one can drift",
                publisher.replace(chart_state_heading, gate_block + chart_state_heading, 1),
            ),
            # Both bypasses the independent security review reproduced against
            # the complete suite while every heading assertion stayed green.
            # They are permanent rows because each is a live regression, not a
            # hypothetical: the first signs the resolved digest before the gate
            # under a name the chain never mentions, the second makes the gate
            # conditional in a spelling `^        if:` cannot see.
            (
                "renamed step signs the resolved digest before the gate",
                publisher.replace(
                    scan_heading,
                    "      - name: Prime the release signature cache\n"
                    "        if: steps.image_state.outputs.state == 'absent'\n"
                    '        run: cosign sign --yes "${IMAGE}@${{ steps.image.outputs.digest }}"\n'
                    + scan_heading,
                    1,
                ),
            ),
            (
                "gate made conditional in the `if :` spelling",
                publisher.replace(
                    scan_heading + "\n",
                    scan_heading
                    + "\n        if : steps.image_state.outputs.state == 'absent'\n",
                    1,
                ),
            ),
            (
                "gate made conditional in the quoted `\"if\":` spelling",
                publisher.replace(
                    scan_heading + "\n",
                    scan_heading
                    + "\n        \"if\": steps.image_state.outputs.state == 'absent'\n",
                    1,
                ),
            ),
            (
                "attestation hoisted above the gate under another name",
                publisher.replace(
                    scan_heading,
                    "      - name: Warm the provenance cache\n"
                    '        run: cosign attest --yes --predicate p.json "${IMAGE}@${DIGEST}"\n'
                    + scan_heading,
                    1,
                ),
            ),
            (
                "second image signature added outside the pinned step",
                publisher.replace(
                    chart_state_heading,
                    "      - name: Re-sign the image for good measure\n"
                    '        run: cosign sign --yes "${IMAGE}@${{ steps.image.outputs.digest }}"\n'
                    + chart_state_heading,
                    1,
                ),
            ),
        ):
            with self.subTest(gate_order_mutant=mutant_name), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator, mutation)
        # Issue #137: the builder-identity binding is wiring, not decoration.
        # Deleting it from either call site, or pointing the freshly built
        # image at a run that did not build it, must be caught here.
        for mutant_name, mutation in (
            (
                "new-image binding deleted",
                publisher.replace(' \\\n              --builder-run-id "${GITHUB_RUN_ID}"', "", 1),
            ),
            (
                "reused-image binding deleted",
                publisher.replace(' \\\n              --builder-run-id "${builder_run_id}"', "", 1),
            ),
            (
                "reused-image run identity never read from the predicate",
                publisher.replace("jq -er '.runDetails.builder.id'", "jq -er '.buildDefinition'", 1),
            ),
            (
                "new image bound to the PR-gate run instead of its own",
                publisher.replace(
                    '--builder-run-id "${GITHUB_RUN_ID}"',
                    '--builder-run-id "${MAIN_RUN_ID}"',
                    1,
                ),
            ),
        ):
            with self.subTest(builder_run_mutant=mutant_name), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator, mutation)
        for forbidden in (
            "tag-state",
            "gh api --method POST",
            "gh release create",
            "cosign sign",
            "helm push",
        ):
            with self.subTest(orchestrator_mutation=forbidden), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator + forbidden, publisher)
        for forbidden in ("cosign download attestation", 'git rev-list -n 1 "${tag}"'):
            with self.subTest(forbidden_mutation=forbidden), self.assertRaises(ValueError):
                self.require_exact_release_wiring(orchestrator, publisher + forbidden)
        template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        for required in (
            "Closes #",
            "Protected base",
            "Exact head",
            "Next patch release",
            "Exact PR-gate jobs + exact-SHA CodeQL run/jobs and manual/unmerged dispatch denial",
            "Post-push image/chart alias rebind + strict raw platform SBOM hostile suite",
            "Deterministic manifest, dev-dependency vulnerability policy, and recurring alias-audit hostile suite",
            "Author applies `requires-review`",
            "reviewer removes it with either verdict",
            "VERDICT: APPROVE",
            "mutation and claim-audit",
            "(adversarial reviewer)",
        ):
            self.assertIn(required, template)

    def test_the_published_chart_carries_the_scanned_signed_image_digest(self):
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/release-audit.yml").read_text(encoding="utf-8")
        self.require_chart_digest_embed(publisher, audit)

        embed_heading = "      - name: Embed the resolved image digest into the chart values"
        classify_heading = "      - name: Classify an absent, complete, or burned chart version"
        publish_heading = "      - name: Publish and sign an absent chart version"
        resolver_heading = "      - name: Resolve the one chart digest for release notes"
        embed_block = embed_heading + publisher.split(embed_heading, 1)[1].split(classify_heading, 1)[0]
        classify_block = classify_heading + publisher.split(classify_heading, 1)[1].split(publish_heading, 1)[0]
        publish_block = publish_heading + publisher.split(publish_heading, 1)[1].split(resolver_heading, 1)[0]

        def rewrite(block: str, old: str, new: str) -> str:
            mutated = block.replace(old, new, 1)
            self.assertNotEqual(mutated, block, f"mutation target is missing: {old}")
            return publisher.replace(block, mutated, 1)

        publish_assert = (
            "          python3 -I -B scripts/ci/release_contract.py chart-digest-assert \\\n"
            '            --values "${packaged_tree}/${chart_name}/values.yaml" --digest "${DIGEST}"\n'
        )
        publish_package = (
            '          helm package chart --version "${version}" '
            '--app-version "${version}" -d "${RUNNER_TEMP}"\n'
        )
        self.assertIn(publish_assert, publish_block)
        self.assertIn(publish_package, publish_block)
        reordered_publish = publisher.replace(
            publish_block,
            publish_block.replace(publish_assert, "", 1).replace(
                publish_package, publish_assert + publish_package, 1
            ),
            1,
        )
        self.assertNotEqual(reordered_publish, publisher)

        # The regression issue #111 names as the sharpest: the substitution
        # written into the publish step alone. The classifier then packages the
        # sentinel, diffs it against a published chart carrying the real
        # digest, and reports `burned` for a version that is in fact complete.
        publish_only = publisher.replace(embed_block, "", 1).replace(
            publish_heading, embed_block + publish_heading, 1
        )
        for name, mutation in (
            ("substitution moved into the publish step alone", publish_only),
            ("substitution step deleted", publisher.replace(embed_block, "", 1)),
            (
                "substitution turned into a no-op",
                rewrite(embed_block, "chart-digest-embed", "chart-digest-noop"),
            ),
            (
                "digest re-derived from a step the gate never bound",
                rewrite(
                    embed_block,
                    "DIGEST: ${{ steps.image.outputs.digest }}",
                    "DIGEST: ${{ steps.image_state.outputs.digest }}",
                ),
            ),
            (
                "digest format assertion dropped",
                rewrite(embed_block, '[[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]', "true"),
            ),
            (
                "sentinel refusal dropped",
                rewrite(embed_block, 'test "${DIGEST}" != "sha256:' + "0" * 64 + '"', "true"),
            ),
            (
                "classifier stops re-reading what it packaged",
                rewrite(classify_block, "chart-digest-assert", "true #"),
            ),
            (
                "publish step stops re-reading the archive it pushes",
                rewrite(publish_block, "chart-digest-assert", "true #"),
            ),
            ("publish step asserts before packaging instead of after", reordered_publish),
            (
                "a second substitution added so the two packagings can drift",
                publisher.replace(
                    publish_block,
                    publish_block.replace(
                        "          helm package chart",
                        "          python3 -I -B scripts/ci/release_contract.py chart-digest-embed \\\n"
                        '            --values chart/values.yaml --digest "${DIGEST}"\n'
                        "          helm package chart",
                        1,
                    ),
                    1,
                ),
            ),
            (
                "the substitution renamed so a prose mention could stand in for it",
                rewrite(embed_block, "release_contract.py chart-digest-embed", "true # chart-digest-embed"),
            ),
        ):
            with self.subTest(publisher_mutant=name), self.assertRaises(ValueError):
                self.require_chart_digest_embed(mutation, audit)

        for name, mutation in (
            ("audit stops reproducing the substitution", audit.replace("chart-digest-embed", "true #", 1)),
            (
                "audit substitutes after packaging instead of before",
                audit.replace(
                    "          python3 -I -B scripts/ci/release_contract.py chart-digest-embed \\\n"
                    '            --values "${expected_source}/chart/values.yaml" --digest "${image_digest}"\n',
                    "",
                    1,
                )
                + "\n          python3 -I -B scripts/ci/release_contract.py chart-digest-embed \\\n"
                '            --values "${expected_source}/chart/values.yaml" --digest "${image_digest}"\n',
            ),
            (
                "audit stops re-reading the published chart",
                audit.replace("chart-digest-assert", "true #", 1),
            ),
            (
                "audit binds a digest the release manifest never named",
                audit.replace(
                    '--values "${expected_source}/chart/values.yaml" --digest "${image_digest}"',
                    '--values "${expected_source}/chart/values.yaml" --digest "${chart_digest}"',
                    1,
                ),
            ),
            (
                "audit drops the reproducibility diff",
                audit.replace(
                    'diff -ru --no-dereference "${expected_tree}/${chart_name}" "${published_tree}/${chart_name}"',
                    "true",
                    1,
                ),
            ),
        ):
            with self.subTest(audit_mutant=name), self.assertRaises(ValueError):
                self.require_chart_digest_embed(publisher, mutation)

    def test_vulnerability_policy_and_recurring_alias_audit_are_closed_and_load_bearing(self):
        gate = (ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/release-publisher.yml").read_text(encoding="utf-8")
        audit = (ROOT / ".github/workflows/release-audit.yml").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/ci/install-tools.sh").read_text(encoding="utf-8")
        self.require_vulnerability_and_alias_audit(gate, publisher, audit, installer)
        mutants = (
            (gate.replace("--severity HIGH,CRITICAL", "--severity CRITICAL", 1), publisher, audit, installer),
            (gate.replace(" --include-dev-deps", "", 1), publisher, audit, installer),
            # Issue #73: --include-dev-deps is unknown to `trivy image` on the
            # installed version and FATALs before any scan runs. The old pair
            # of mutants here asserted the backwards claim (that REMOVING the
            # flag was the regression); now that both real image-scan
            # invocations are flag-free, prove REINTRODUCING it is caught.
            (
                gate,
                publisher.replace(
                    "trivy image --scanners vuln",
                    "trivy image --scanners vuln --include-dev-deps",
                    1,
                ),
                audit,
                installer,
            ),
            (
                gate,
                publisher,
                audit.replace(
                    "trivy image --scanners vuln",
                    "trivy image --scanners vuln --include-dev-deps",
                    1,
                ),
                installer,
            ),
            (gate, publisher.replace("--ignore-unfixed=false", "--ignore-unfixed=true", 1), audit, installer),
            (gate, publisher, audit.replace("cron: '17 8 * * 1'", "cron: '17 8 * * 0'", 1), installer),
            (gate, publisher, audit.replace("packages: read", "packages: write", 1), installer),
            (gate, publisher, audit.replace('"${IMAGE}@${image_digest}"', '"${IMAGE}:${tag}"'), installer),
            (gate, publisher, audit.replace('"${CHART}@${chart_digest}"', '"${CHART}:${version}"'), installer),
            (gate, publisher, audit.replace("release-record", "", 1), installer),
            (gate, publisher, audit.replace("main-run-record", "", 1), installer),
            (gate, publisher, audit.replace("tag-record", "", 1), installer),
            (gate, publisher, audit.replace("attestation-set", "", 1), installer),
            # Issue #70: this pin used to require attestation-statement for
            # the audit workflow but not the --predicate-output flag that
            # makes it write the exact object cosign signs, so deleting the
            # flag from release-audit.yml survived the full suite even
            # though the identical deletion on the publisher side was
            # already caught (see the "publisher" --predicate-output pin
            # above). Proven closed: this mutant must now go red too.
            (gate, publisher, audit.replace("--predicate-output", "", 1), installer),
            # Issue #137: the same closure for the builder-run binding -- the
            # audit must keep re-deriving it, and must keep reading it from the
            # predicate rather than inventing one.
            (gate, publisher, audit.replace("--builder-run-id", "", 1), installer),
            (
                gate,
                publisher,
                audit.replace("jq -er '.runDetails.builder.id'", "jq -er '.buildDefinition'", 1),
                installer,
            ),
            (gate, publisher, audit.replace("diff -ru --no-dereference", "true #", 1), installer),
            (gate, publisher, audit + "\n      contents: write\n", installer),
            (gate, publisher, audit + "\n      gh api --method POST foreign\n", installer),
            (gate, publisher, audit, installer.replace("TRIVY_SHA256=", "TRIVY_SHA256_MUTATED=", 1)),
            (gate, publisher, audit, installer + "\n# aquasecurity/trivy-action@v0.36.0\n"),
            # The audit's action pins (issue #16): a tag instead of a SHA, a
            # SHA without its version comment, a short SHA, and a pin the
            # publisher does not run, on either side or in the comment alone.
            (gate, publisher, re.sub(r"sigstore/cosign-installer@\S+ # ", "sigstore/cosign-installer@v4 # ", audit), installer),
            (gate, publisher, re.sub(r"(docker/setup-buildx-action@[0-9a-f]{40}) # \S+", r"\1", audit), installer),
            (gate, publisher, re.sub(r"actions/checkout@([0-9a-f]{12})[0-9a-f]{28}", r"actions/checkout@\1", audit), installer),
            (gate, publisher, re.sub(r"sigstore/cosign-installer@[0-9a-f]{40}", "sigstore/cosign-installer@" + "0" * 40, audit), installer),
            (gate, re.sub(r"docker/setup-buildx-action@[0-9a-f]{40}", "docker/setup-buildx-action@" + "1" * 40, publisher), audit, installer),
            (gate, publisher, re.sub(r"(actions/checkout@[0-9a-f]{40}) # v[0-9.]+", r"\1 # v0.0.0", audit), installer),
            (gate, re.sub(r"sigstore/cosign-installer@\S+ # ", "sigstore/cosign-installer@v4 # ", publisher), re.sub(r"sigstore/cosign-installer@\S+ # ", "sigstore/cosign-installer@v4 # ", audit), installer),
            (gate, publisher, re.sub(r"\n\s*(?:-\s+)?uses: sigstore/cosign-installer@[^\n]*", "", audit), installer),
            # Made on both sides, a tag or a missing version comment passes
            # the equality above, so only the shape rule can refuse it.
            (gate, re.sub(r"(docker/setup-buildx-action@[0-9a-f]{40}) # \S+", r"\1", publisher), re.sub(r"(docker/setup-buildx-action@[0-9a-f]{40}) # \S+", r"\1", audit), installer),
            # And the action gone from both: equal, but the audit lost it.
            (gate, re.sub(r"\n\s*(?:-\s+)?uses: sigstore/cosign-installer@[^\n]*", "", publisher), re.sub(r"\n\s*(?:-\s+)?uses: sigstore/cosign-installer@[^\n]*", "", audit), installer),
        )
        for index, mutant in enumerate(mutants):
            self.assertNotEqual(mutant, (gate, publisher, audit, installer), f"hostile mutant {index} changed nothing")
            with self.subTest(hostile_mutant=index), self.assertRaises(ValueError):
                self.require_vulnerability_and_alias_audit(*mutant)
        # The same bump made on both sides passes: the binding is equality,
        # not a remembered SHA.
        moved = {
            side: re.sub(
                r"sigstore/cosign-installer@[0-9a-f]{40} # \S+",
                "sigstore/cosign-installer@" + "a" * 40 + " # v9.9.9",
                text,
            )
            for side, text in (("publisher", publisher), ("audit", audit))
        }
        self.assertNotEqual(moved["audit"], audit)
        self.require_vulnerability_and_alias_audit(gate, moved["publisher"], moved["audit"], installer)


if __name__ == "__main__":
    unittest.main()
