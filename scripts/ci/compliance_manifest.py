"""The site's compliance manifest, validated, and the live site judged by it.

WHY THIS EXISTS. The origin keeps strong privacy properties by construction --
`default-src 'self'`, no cookie of its own, no client address in its logs --
and every one of them is pinned by a Go test against the binary. None of those
tests can see what a visitor actually receives, because an edge sits between
the binary and the visitor and can add headers, scripts and reporting
endpoints of its own. On 2026-10-08 it was doing all three (issue #355). And
nothing kept the facts a privacy notice must state -- what the site stores on
a visitor's device, which third parties a page contacts, which legal pages
exist -- written down in one place a gate could hold the site to.

`compliance.json` at the repository root is that place. This file has two
subcommands:

  check  validate the manifest's closed schema, and hold two of its lists to
         the shipped script under `site/` in both directions. Storage: a
         declared cookie or storage key that no file WRITES as that kind is
         stale, and a write the manifest does not declare is refused
         (`storage_writes` states the write grammar). Hand-offs: every https
         origin, `mailto:` or `tel:` the script builds a URL with must be a
         declared third party or a declared hand-off, and a declared hand-off
         the script never builds is stale (`built_targets` states what counts
         as building one). A data-collection entry whose evidence file is gone
         is stale too.
  live   GET the production URL and judge what the edge actually serves: the
         answer must be complete (never a prefix past the byte cap, never
         short of its Content-Length), the CSP must admit no origin the
         manifest does not declare (and none at all through a wildcard or a
         bare scheme), script directives must not admit 'unsafe-inline' or
         eval'd code, a declared injected script passes only while a policy
         blocks every inline script, a declared injected script origin passes
         only while a policy blocks scripts from that origin, framing must be
         denied, HSTS must last a
         year, nosniff and a Referrer-Policy must be present, the document must
         set no cookie, every reporting endpoint and every script, stylesheet
         or embedded resource in the served HTML must be this origin's or
         declared, and every published legal page must answer 200. A declared
         third party or edge observation that no longer occurs is refused as
         stale, so an exemption never outlives its case. Hand-offs are not
         loads, so live mode only notes them, and it notes every third party
         whose consent question is still pending with the issue that holds it.

THIRD PARTIES AND CONSENT. A third party is an origin the page itself makes
the browser contact (it appears in the CSP). Its `consent` is `not-required`
or `pending`. `pending` means the owner has not yet ruled whether that third
party needs the visitor's consent; it is admitted only with a `decision` issue
URL that holds the ruling, and a `not-required` entry may carry no `decision`,
so the two states can never blur. Nothing here admits a third party that is
known to need consent: that needs a consent mechanism first, a code change.

HAND-OFFS. A hand-off is a URL the script builds to send the visitor ELSEWHERE
with something they composed (a booking message to a messaging service, or to
their own mail client). Nothing is sent to this origin and nothing leaves until
the visitor clicks or submits, but what the visitor typed then reaches the
target, which is exactly what a privacy notice has to say. Each entry names
its `target` (a bare https origin, or exactly `mailto:` or `tel:`), what it
`carries`, its `purpose` and the `reason` it exists.

PIN BEHAVIOUR, NOT INVENTORY. Nothing here asserts "the site has exactly these
headers" or "these are all the scripts". Each rule refuses one construct that
changes what a visitor is exposed to, and a legitimate addition either passes
untouched or needs one declared line.

LIFT. A refusal a manifest line can admit prints that exact line, and every
entry needs a written reason (and, for an edge observation, the issue that
holds the decision). Adding a declared third party is a normal, reviewed
one-line change; it is also exactly the line a privacy notice has to mention,
which is the point. The rest print no line because none exists: a missing CSP,
allowed framing, short HSTS, a missing header, a cookie on the document, a
write on load, an injected script the CSP can let run, or an incomplete answer
needs a code, policy or owner decision, never a declaration.

Logging follows the repository's failure-visibility rule: one START line with
the budget, one line per refusal, one SUMMARY with the decision and duration.
"""

from __future__ import annotations

import argparse
import html.parser
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "compliance.json"
SOURCE_ROOT = ROOT / "site"
# How refusals name the source root, independent of where a test points it.
SOURCE_LABEL = "site"
SCHEMA = "compliance/v1"

TOP_KEYS = {
    "schema",
    "liveUrl",
    "dataCollected",
    "storage",
    "thirdParties",
    "legalPages",
    "edgeObservations",
    "handOffs",
}
ENTRY_KEYS = {
    "dataCollected": ({"what", "where", "purpose", "evidence"}, set()),
    "storage": ({"name", "kind", "writtenWhen", "purpose"}, set()),
    "thirdParties": ({"origin", "purpose", "consent", "reason"}, {"decision"}),
    "legalPages": ({"id", "status"}, {"path", "decision"}),
    "edgeObservations": ({"kind", "reason", "issue"}, {"marker", "origin"}),
    "handOffs": ({"target", "carries", "purpose", "reason"}, set()),
}
STORAGE_KINDS = {"cookie", "localStorage", "sessionStorage"}
# Only a write the visitor causes is admitted. Writing on load is the
# consent question itself; admitting it needs a consent mechanism this site
# does not have, which is a code change and not a manifest line.
WRITTEN_WHEN = {"visitor-action"}
# `pending` records an open owner decision and is admitted only together with
# the issue URL that holds it; see THIRD PARTIES AND CONSENT above.
CONSENT = {"not-required", "pending"}
PAGE_STATUS = {"published", "pending"}
OBSERVATION_KINDS = {"injected-inline-script", "injected-script-origin", "reporting-endpoint"}
ISSUE_URL = re.compile(r"\Ahttps://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+\Z")
ORIGIN = re.compile(r"\Ahttps://[a-z0-9.-]+(?::[0-9]{1,5})?\Z")
# The only non-origin hand-off targets: each opens the visitor's own app.
HANDOFF_SCHEMES = {"mailto:", "tel:"}
# What `built_targets` reads inside a string or template literal as the start
# of a URL the script builds: an http(s) origin, or a mail or phone link.
BUILT_URL = re.compile(r"(?i)(https?://[^\s/?#'\"`\\]+|mailto:|tel:)")

# Fetch directives: every directive that decides where a page may load or
# connect. `default-src` is the fallback for the ones a policy omits.
FETCH_DIRECTIVES = (
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "font-src",
    "connect-src",
    "media-src",
    "object-src",
    "frame-src",
    "child-src",
    "worker-src",
    "manifest-src",
)
SCRIPT_DIRECTIVES = ("default-src", "script-src", "script-src-elem", "script-src-attr")
# Keywords that admit no origin at all. Hash and nonce sources are matched
# separately; they name bytes, not places.
NEUTRAL_KEYWORDS = {"'self'", "'none'", "'report-sample'"}
INLINE_KEYWORDS = {"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'"}
HASH_OR_NONCE = re.compile(r"\A'(?:sha256|sha384|sha512|nonce)-[A-Za-z0-9+/=_-]+'\Z")
# `data:` and `blob:` name no host. They stay legal where they are ordinary.
SCHEME_SOURCES = {
    "data:": {"img-src", "font-src", "media-src"},
    "blob:": {"img-src", "media-src", "worker-src"},
}
# The storage-write grammar `check` reads. It runs on the source as code
# alone (`code_only`): a write that exists only in a comment, or only as the
# text of a string, template or regular-expression literal, never executes,
# so it is no write. The patterns below match that code; a key or cookie name
# is then read from the source at the same offset, because the code keeps
# only a literal's delimiters.
SOURCE_SUFFIXES = {".ts", ".js", ".mjs", ".svelte"}
TEST_FILE = re.compile(r"\.(?:test|spec)\.")
COOKIE_WRITE = re.compile(r"""\bdocument\.cookie\s*=(?!=)\s*["'`]""")
COOKIE_NAME = re.compile(r"""([^"'`=;\s]+)=""")
STORE_NAME = re.compile(r"\b(localStorage|sessionStorage)\b")
# Every `.setItem(` call; a first argument that is neither a literal nor a
# name, each followed by the comma, leaves both groups empty and is refused.
STORE_WRITE = re.compile(
    r"""(?:\b(localStorage|sessionStorage)\s*)?\.\s*setItem\s*\(\s*(?:(?:((["'`])[^"'`]*\3)|([A-Za-z_$][\w$]*))\s*,)?"""
)
BOUND_CONSTANT = r"""\b(?:const|let|var)\s+{}\s*(?::[^=;]+)?=\s*((["'`])[^"'`]*\2)"""
CODE_STOPS = re.compile(r"""[/'"`{}<]""")
MARKUP_STOPS = re.compile(r"[{<]")
TEMPLATE_STOPS = re.compile(r"[\\`$]")
QUOTED = {
    "'": re.compile(r"""'(?:\\.|[^'\\\n])*'""", re.DOTALL),
    '"': re.compile(r'''"(?:\\.|[^"\\\n])*"''', re.DOTALL),
}
REGEX_LITERAL = re.compile(r"/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/")
# A `/` starts a regular expression where an operand may begin: after one of
# these characters, after one of these words (each wants an expression next or
# ends a statement, as `debugger`, `break` and `continue` do), after a label on
# the same line as its `break` or `continue`, or at the very start. After a
# name, a property (whatever it is called), a number, `]` or a closing quote it
# divides. After `)`, `}`, `++`, `--` or `of`, or a `!` that follows one of
# them or follows an operand across a line break, it can do either, and only a
# parser knows which, so `storage_writes` reads the file both ways.
REGEX_AFTER = frozenset("(,=:[!&|?{;+-*%<>~^")
REGEX_AFTER_WORDS = frozenset(
    "return typeof case do else in new delete void throw instanceof yield await"
    " debugger break continue default extends".split()
)
OPERAND_OR_KEYWORD = frozenset(("of",))
# JavaScript's line terminators: each ends a `//` comment and a statement.
LINE_TERMINATOR = re.compile("[\n\r\u2028\u2029]")
SVELTE_ELEMENT = re.compile(r"<(script|style)\b[^>]*>", re.IGNORECASE)
HSTS_FLOOR_SECONDS = 31_536_000
REFERRER_POLICIES = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
FETCH_TIMEOUT_SECONDS = 20
BODY_CAP_BYTES = 2 * 1024 * 1024
USER_AGENT = "compliance-live-check/1 (read-only GET)"
LOADING_LINK_RELS = {
    "stylesheet",
    "preload",
    "modulepreload",
    "preconnect",
    "dns-prefetch",
    "prefetch",
    "icon",
    "apple-touch-icon",
    "manifest",
}
EMBED_TAGS = {"img", "iframe", "embed", "object", "source", "video", "audio", "track"}


@dataclass
class Fetched:
    """One HTTP answer, reduced to what the judge reads."""

    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def first(self, name: str) -> str | None:
        values = self.all(name)
        return values[0] if values else None


@dataclass
class Verdict:
    refusals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def refuse(self, message: str, lift: str | None = None) -> None:
        self.refusals.append(message if lift is None else f"{message} (lift: {lift})")


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


# ---------------------------------------------------------------- check mode


def _text(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate(manifest: object, source_root: Path = SOURCE_ROOT, repo_root: Path = ROOT) -> list[str]:
    """Every way the manifest fails its closed schema or has gone stale."""
    refusals: list[str] = []
    if not isinstance(manifest, dict):
        return ["compliance.json must be one JSON object"]
    keys = set(manifest)
    for missing in sorted(TOP_KEYS - keys):
        refusals.append(f"compliance.json lacks the required key {missing!r}")
    for unknown in sorted(keys - TOP_KEYS):
        refusals.append(f"compliance.json carries the unknown key {unknown!r}; the schema is closed so a typo cannot pass silently")
    if manifest.get("schema") != SCHEMA:
        refusals.append(f"compliance.json schema must be {SCHEMA!r}")
    live = manifest.get("liveUrl")
    if not (isinstance(live, str) and live.startswith("https://") and urlsplit(live).netloc):
        refusals.append("liveUrl must be the site's https:// URL")

    for section, (required, optional) in ENTRY_KEYS.items():
        # An absent section is refused above; a present one, null included,
        # must be a list, or `_entries` would read it as an empty disclosure.
        if section not in manifest:
            continue
        entries = manifest[section]
        if not isinstance(entries, list):
            refusals.append(f"{section} must be a list")
            continue
        for index, entry in enumerate(entries):
            where = f"{section}[{index}]"
            if not isinstance(entry, dict):
                refusals.append(f"{where} must be an object")
                continue
            for missing in sorted(required - set(entry)):
                refusals.append(f"{where} lacks {missing!r}")
            for unknown in sorted(set(entry) - required - optional):
                refusals.append(f"{where} carries the unknown key {unknown!r}")
            for key in sorted(set(entry) & (required | optional)):
                if not _text(entry[key]):
                    refusals.append(f"{where}.{key} must be a non-empty string")

    for index, entry in enumerate(_entries(manifest, "dataCollected")):
        evidence = entry.get("evidence")
        if _text(evidence) and not (repo_root / evidence).exists():
            refusals.append(f"dataCollected[{index}].evidence {evidence!r} no longer exists: the entry is stale")

    writes, unread = storage_writes(source_root)
    declared: set[tuple[str, str]] = set()
    for index, entry in enumerate(_entries(manifest, "storage")):
        where = f"storage[{index}]"
        kind, name = entry.get("kind"), entry.get("name")
        if kind not in STORAGE_KINDS:
            refusals.append(f"{where}.kind must be one of {sorted(STORAGE_KINDS)}")
        if entry.get("writtenWhen") not in WRITTEN_WHEN:
            refusals.append(
                f"{where}.writtenWhen must be one of {sorted(WRITTEN_WHEN)}: a write on load needs consent, "
                "and consent needs a mechanism this site does not have"
            )
        if _text(name):
            declared.add((kind, name))
            if (kind, name) not in writes:
                refusals.append(
                    f"{where} declares {kind} {name!r}, which no file under {SOURCE_LABEL}/ writes: the entry is stale"
                )
    for (kind, name), where in sorted(writes.items()):
        if (kind, name) not in declared:
            refusals.append(
                f"{SOURCE_LABEL}/{where} writes {kind} {name!r}, which compliance.json does not declare (lift: add to "
                f'storage {{"name": "{name}", "kind": "{kind}", "writtenWhen": "visitor-action", "purpose": "..."}})'
            )
    refusals.extend(unread)

    for index, entry in enumerate(_entries(manifest, "thirdParties")):
        where = f"thirdParties[{index}]"
        if not (isinstance(entry.get("origin"), str) and ORIGIN.match(entry["origin"])):
            refusals.append(f"{where}.origin must be a bare https origin such as https://host.example")
        consent = entry.get("consent")
        if consent not in CONSENT:
            refusals.append(
                f"{where}.consent must be one of {sorted(CONSENT)}: a third party that needs consent needs "
                "a consent mechanism first, which is a code change"
            )
        if consent == "pending" and not (isinstance(entry.get("decision"), str) and ISSUE_URL.match(entry["decision"])):
            refusals.append(
                f"{where}.consent is pending, so it needs the issue URL that holds the decision as its decision"
            )
        if consent == "not-required" and "decision" in entry:
            refusals.append(
                f"{where}.consent is not-required, so it carries no decision: a decision belongs only to a "
                "pending consent question"
            )

    built = built_targets(source_root)
    handed: set[str] = set()
    for index, entry in enumerate(_entries(manifest, "handOffs")):
        where = f"handOffs[{index}]"
        target = entry.get("target")
        if not (isinstance(target, str) and (ORIGIN.match(target) or target in HANDOFF_SCHEMES)):
            refusals.append(
                f"{where}.target must be a bare https origin such as https://host.example, or exactly one of "
                f"{sorted(HANDOFF_SCHEMES)}"
            )
            continue
        if target in handed:
            refusals.append(f"{where}.target {target!r} is declared twice")
        handed.add(target)
        if target not in built:
            refusals.append(
                f"{where} declares the hand-off {target!r}, which no file under {SOURCE_LABEL}/ builds a URL "
                "with: the entry is stale"
            )
    origins = {
        entry["origin"] for entry in _entries(manifest, "thirdParties") if isinstance(entry.get("origin"), str)
    }
    for target, where in sorted(built.items()):
        if target in handed or target in origins:
            continue
        lift = (
            f' (lift: add to handOffs {{"target": "{target}", "carries": "...", "purpose": "...", "reason": "..."}})'
            if ORIGIN.match(target) or target in HANDOFF_SCHEMES
            else ""
        )
        refusals.append(
            f"{SOURCE_LABEL}/{where} builds a URL with {target!r}, which compliance.json declares neither as a "
            f"third party nor as a hand-off{lift}"
        )

    seen_ids: set[str] = set()
    for index, entry in enumerate(_entries(manifest, "legalPages")):
        where = f"legalPages[{index}]"
        page_id = entry.get("id")
        if page_id in seen_ids:
            refusals.append(f"{where}.id {page_id!r} is declared twice")
        if isinstance(page_id, str):
            seen_ids.add(page_id)
        status = entry.get("status")
        if status not in PAGE_STATUS:
            refusals.append(f"{where}.status must be one of {sorted(PAGE_STATUS)}")
        if status == "published" and not (isinstance(entry.get("path"), str) and entry["path"].startswith("/")):
            refusals.append(f"{where} is published, so it needs the absolute path it is served at")
        if status == "pending" and not (isinstance(entry.get("decision"), str) and ISSUE_URL.match(entry["decision"])):
            refusals.append(f"{where} is pending, so it needs the issue URL that holds the decision")

    for index, entry in enumerate(_entries(manifest, "edgeObservations")):
        where = f"edgeObservations[{index}]"
        kind = entry.get("kind")
        if kind not in OBSERVATION_KINDS:
            refusals.append(f"{where}.kind must be one of {sorted(OBSERVATION_KINDS)}")
        if kind == "injected-inline-script" and not _text(entry.get("marker")):
            refusals.append(f"{where} needs the marker text that identifies the injected script")
        if kind == "reporting-endpoint" and not (isinstance(entry.get("origin"), str) and ORIGIN.match(entry["origin"])):
            refusals.append(f"{where} needs the bare https origin the reports go to")
        if kind == "injected-script-origin" and not (isinstance(entry.get("origin"), str) and ORIGIN.match(entry["origin"])):
            refusals.append(f"{where} needs the bare https origin the injected script loads from")
        if not (isinstance(entry.get("issue"), str) and ISSUE_URL.match(entry["issue"])):
            refusals.append(f"{where}.issue must be the issue URL that holds the decision")
    return refusals


def _entries(manifest: dict, section: str) -> list[dict]:
    value = manifest.get(section)
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _script_files(source_root: Path) -> list[Path]:
    """Every shipped script file under the source root, tests excluded."""
    if not source_root.is_dir():
        return []
    return [
        path
        for path in sorted(source_root.rglob("*"))
        if path.is_file() and path.suffix in SOURCE_SUFFIXES and not TEST_FILE.search(path.name)
    ]


def built_targets(source_root: Path) -> dict[str, str]:
    """Every target the site's script builds a URL with, and the file that builds it.

    A URL is built when a string or template literal in CODE (`code_only`:
    never a comment, never markup, never a regular expression) holds an
    http(s) origin, `mailto:` or `tel:` (`BUILT_URL`). The target is the
    lowercased origin, or the scheme itself. Each file is read both ways an
    ambiguous `/` allows and the union is kept, so a URL either reading sees
    must be declared; a file the storage scan cannot read is refused there.
    A plain `http://` target is reported like any other and can never be
    declared, because no manifest line admits an insecure origin.
    """
    built: dict[str, str] = {}
    for path in _script_files(source_root):
        where = path.relative_to(source_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for ambiguous_regex in (False, True):
            code, _ = code_only(text, path.suffix == ".svelte", ambiguous_regex)
            for start, end in literal_spans(code):
                for match in BUILT_URL.finditer(text, start, end):
                    found = match.group(1).lower()
                    target = found if found in HANDOFF_SCHEMES else origin_of(found)
                    built.setdefault(target, where)
    return built


def literal_spans(code: str) -> list[tuple[int, int]]:
    """The content offsets of every string literal and template text in `code`.

    `code_only` keeps a literal's delimiters and a template's `${...}` code and
    blanks everything else that is not code, so in its output every quote is a
    literal's delimiter and every backtick a template's. The offsets returned
    index the original text, whose bytes at those offsets are the literal's.
    """
    spans: list[tuple[int, int]] = []

    def expression(at: int, nested: bool) -> int:
        depth = 0
        while at < len(code):
            character = code[at]
            if character in "'\"":
                close = code.find(character, at + 1)
                if close < 0:
                    return len(code)
                spans.append((at + 1, close))
                at = close + 1
            elif character == "`":
                at = template(at + 1)
            elif character == "}" and nested and depth == 0:
                return at
            else:
                depth += {"{": 1, "}": -1}.get(character, 0)
                at += 1
        return at

    def template(at: int) -> int:
        start = at
        while at < len(code):
            if code[at] == "`":
                spans.append((start, at))
                return at + 1
            if code.startswith("${", at):
                spans.append((start, at))
                at = expression(at + 2, nested=True) + 1
                start = at
                continue
            at += 1
        spans.append((start, len(code)))
        return len(code)

    expression(0, nested=False)
    return spans


def storage_writes(source_root: Path) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Every (kind, name) the site's script source WRITES, with the file that writes it,
    and a refusal for every write this grammar sees but cannot attribute.

    A write is `document.cookie = '<name>=...'`, or a `.setItem(<key>, ...)`
    call whose key is a string literal or a constant the same file binds to
    one, in a file whose code names the store; a call whose key is anything
    else is refused. Only code counts (`code_only`): reads, literals however
    write-shaped, comments, markup and test files are not writes, so none of
    them keeps a declaration alive.

    Each file is read twice, every ambiguous `/` taken first as a division
    and then as a regular expression. The file counts only when both
    readings find the same writes and refusals and neither meets more than
    one ambiguous `/` that could open a regular expression: with one, the
    real reading is one of the two; with more, it can be a mix of them that
    neither shows. Otherwise the file is refused until it is rewritten.
    """
    writes: dict[tuple[str, str], str] = {}
    unread: list[str] = []
    for path in _script_files(source_root):
        where = path.relative_to(source_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        (found, refused, slashes), (other, other_refused, other_slashes) = (
            file_writes(text, where, path.suffix == ".svelte", regex) for regex in (False, True)
        )
        if (found, refused) != (other, other_refused) or max(len(slashes), len(other_slashes)) > 1:
            lines = ", ".join(str(text.count("\n", 0, at) + 1) for at in sorted(set(slashes + other_slashes)))
            unread.append(
                f"{SOURCE_LABEL}/{where}: the storage scan cannot tell whether the `/` on line {lines} divides or "
                "opens a regular expression (after `)`, `}`, `++`, `--` or `of`, or a `!` that follows one or a "
                "line break, it can do either), and what this file writes may depend on it, so its writes are "
                "not counted; write it unambiguously, for example by wrapping a regular expression in "
                "parentheses or putting a division's operands in variables"
            )
            continue
        for key, value in found.items():
            writes.setdefault(key, value)
        unread.extend(refused)
    return writes, unread


def file_writes(
    text: str, where: str, svelte: bool, ambiguous_regex: bool
) -> tuple[dict[tuple[str, str], str], list[str], list[int]]:
    """One reading of one file: its writes, its refusals, and its ambiguous slashes."""
    writes: dict[tuple[str, str], str] = {}
    unread: list[str] = []
    code, slashes = code_only(text, svelte, ambiguous_regex)
    # Outside literals and comments a backslash can only open a Unicode
    # escape in a name, and an escape can spell `localStorage`, `setItem`,
    # `cookie` or a label this scan would misread, so it is refused, not
    # decoded.
    escape = code.find("\\")
    if escape >= 0:
        line = text.count("\n", 0, escape) + 1
        unread.append(f"{SOURCE_LABEL}/{where} spells a name with a Unicode escape on line {line}; write the name plainly")
    for match in COOKIE_WRITE.finditer(code):
        name = COOKIE_NAME.match(text, match.end())
        if name:
            writes.setdefault(("cookie", name.group(1)), where)
    # A store is named by code, not by a sentence or a string about it.
    stores = set(STORE_NAME.findall(code))
    for match in STORE_WRITE.finditer(code):
        receiver, literal, identifier = match.group(1), match.group(2), match.group(4)
        if literal is not None:
            literal = text[match.start(2) + 1 : match.end(2) - 1]
        elif identifier is not None:
            bound = re.search(BOUND_CONSTANT.format(re.escape(identifier)), code)
            literal = text[bound.start(1) + 1 : bound.end(1) - 1] if bound else None
        if not literal or "${" in literal:
            literal = None
        kinds = {receiver} if receiver else stores
        if literal is None or not kinds:
            missing = "key this gate cannot read" if literal is None else "storage this gate cannot name"
            unread.append(f"{SOURCE_LABEL}/{where} makes a storage write whose {missing} "
                          f"({text[match.start() : match.end()]!r}); "
                          "write it with a literal key, or a constant bound to one, on a named store")
            continue
        for kind in kinds:
            writes.setdefault((kind, literal), where)
    return writes, unread, slashes


def js_space(character: str) -> bool:
    """JavaScript white space or a line terminator. Python's isspace also
    takes U+001C-U+001F and U+0085, which JavaScript does not, but in code
    those are syntax errors, so no valid program reads differently."""
    return character.isspace() or character == "\ufeff"


def name_character(character: str) -> bool:
    """Part of a JavaScript name. Every punctuator is ASCII, so in code a
    non-ASCII character that is not white space can only belong to a name
    (anything else there is a syntax error). isalnum is not ASCII-only, so
    the ASCII test is spelled out."""
    if character.isascii():
        return character.isalnum() or character in "_$"
    return not js_space(character)


def code_only(text: str, svelte: bool = False, ambiguous_regex: bool = False) -> tuple[str, list[int]]:
    """`text` with every comment, and the contents of every string, template
    and regular-expression literal, blanked to spaces; and the offset of
    every ambiguous `/` (see REGEX_AFTER) that could open a
    regular expression, which this reading takes as one when
    `ambiguous_regex` is set and as a division otherwise.

    Delimiters, newlines and the code inside a template's `${...}` are kept, so
    an offset here is the same offset in `text`. In a Svelte component only
    `<script>` bodies and `{...}` expressions are code; markup, `<style>` and
    HTML comments are blanked whole, so an apostrophe in a sentence cannot
    open a string that hides the code after it.
    """
    out = list(text)
    ambiguous: list[int] = []

    def blank(start: int, end: int) -> None:
        for at in range(start, end):
            if out[at] != "\n":
                out[at] = " "

    def comment(at: int, end: int, closer: str) -> int:
        close = text.find(closer, at + 2, end)
        close = end if close < 0 else close + len(closer)
        blank(at, close)
        return close

    def ends_operand(at: int) -> bool | None:
        """Whether the code before `at` ends an operand, begins one, or None: either."""
        before = at - 1
        while before >= 0 and js_space(out[before]):
            before -= 1
        if before < 0:
            return False
        word = before
        while word >= 0 and name_character(out[word]):
            word -= 1
        name = "".join(out[word + 1 : before + 1])
        if name:
            dot = word
            while dot >= 0 and js_space(out[dot]):
                dot -= 1
            if dot >= 0 and out[dot] == ".":
                return True  # a property, whatever it is called
            if name in OPERAND_OR_KEYWORD:
                return None
            if name in REGEX_AFTER_WORDS:
                return False
            # A label ends `break` or `continue` when it is on their line.
            keyword = dot
            while keyword >= 0 and name_character(out[keyword]):
                keyword -= 1
            return not (
                "".join(out[keyword + 1 : dot + 1]) in ("break", "continue")
                and not LINE_TERMINATOR.search(text, dot + 1, word + 1)
            )
        last = out[before]
        if last in ")}" or (before > 0 and out[before - 1] + last in ("++", "--")):
            return None
        if last == "!":
            # `x!` asserts non-null and `!x` negates, but a line terminator
            # between `x` and `!` ends `x`'s statement, comments included,
            # which the source shows and this buffer may not.
            ends = ends_operand(before)
            prior = before - 1
            while prior >= 0 and js_space(out[prior]):
                prior -= 1
            return None if ends and LINE_TERMINATOR.search(text, prior + 1, before) else ends
        return last not in REGEX_AFTER

    def regex_or_division(at: int, end: int) -> int:
        literal = REGEX_LITERAL.match(text, at, end)
        ends = ends_operand(at)
        if ends is None and literal is not None:
            ambiguous.append(at)
        regex = ambiguous_regex if ends is None else not ends
        if not regex or literal is None:
            return at + 1  # division
        blank(at + 1, literal.end() - 1)
        return literal.end()

    def template(at: int, end: int) -> int:
        while at < end:
            stop = TEMPLATE_STOPS.search(text, at, end)
            if stop is None:
                break
            blank(at, stop.start())
            at = stop.start()
            if text[at] == "`":
                return at + 1
            if text.startswith("${", at):
                at = scan(at + 2, end, nested=True) + 1
            else:  # an escape, or a `$` that opens nothing
                step = 2 if text[at] == "\\" else 1
                blank(at, min(at + step, end))
                at += step
        blank(at, end)
        return end

    def scan(at: int, end: int, nested: bool) -> int:
        """Code from `at`; a nested scan returns at the `}` that closes it."""
        depth = 0
        while True:
            stop = CODE_STOPS.search(text, at, end)
            if stop is None:
                return end
            at = stop.start()
            character = text[at]
            if text.startswith("//", at):
                terminator = LINE_TERMINATOR.search(text, at, end)
                blank(at, terminator.start() if terminator else end)
                at = terminator.start() if terminator else end
            elif text.startswith("/*", at):
                at = comment(at, end, "*/")
            elif text.startswith("<!--", at):
                at = comment(at, end, "-->")
            elif character == "/":
                at = regex_or_division(at, end)
            elif character in QUOTED:
                quoted = QUOTED[character].match(text, at, end)
                if quoted:
                    blank(at + 1, quoted.end() - 1)
                at = quoted.end() if quoted else at + 1
            elif character == "`":
                at = template(at + 1, end)
            elif character == "}" and nested and depth == 0:
                return at
            else:
                depth += {"{": 1, "}": -1}.get(character, 0)
                at += 1

    def markup(at: int, end: int) -> None:
        while at < end:
            stop = MARKUP_STOPS.search(text, at, end)
            if stop is None:
                break
            blank(at, stop.start())
            at = stop.start()
            element = SVELTE_ELEMENT.match(text, at, end)
            if text.startswith("<!--", at):
                at = comment(at, end, "-->")
            elif element:
                closing = re.compile(rf"</{element.group(1)}\s*>", re.IGNORECASE).search(text, element.end(), end)
                body_end, after = (closing.start(), closing.end()) if closing else (end, end)
                blank(at, element.end())
                if element.group(1).lower() == "script":
                    scan(element.end(), body_end, nested=False)
                else:
                    blank(element.end(), body_end)
                blank(body_end, after)
                at = after
            elif text[at] == "{":
                # `{/if}` closes a block; its slash starts no expression.
                at = scan(at + (2 if text.startswith("{/", at) else 1), end, nested=True) + 1
            else:
                blank(at, at + 1)
                at += 1
        blank(at, end)

    if svelte:
        markup(0, len(text))
    else:
        scan(0, len(text), nested=False)
    return "".join(out), ambiguous


# ----------------------------------------------------------------- live mode


def parse_csp(value: str) -> dict[str, list[str]]:
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # The first occurrence of a directive wins (CSP3 section 2.2.1).
        policy.setdefault(name, tokens[1:])
    return policy


class _Resources(html.parser.HTMLParser):
    """Collect every load the served HTML asks a browser to make."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.loads: list[tuple[str, str]] = []
        self.inline_scripts: list[str] = []
        self._inline: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "script":
            if values.get("src"):
                self.loads.append(("script", values["src"]))
            else:
                self._inline = []
        elif tag == "link":
            rels = set(values.get("rel", "").lower().split())
            if rels & LOADING_LINK_RELS and values.get("href"):
                self.loads.append(("link " + " ".join(sorted(rels)), values["href"]))
        elif tag in EMBED_TAGS:
            for attribute in ("src", "data", "poster"):
                if values.get(attribute):
                    self.loads.append((tag, values[attribute]))
            for candidate in values.get("srcset", "").split(","):
                url = candidate.strip().split(" ")[0]
                if url:
                    self.loads.append((tag + " srcset", url))

    def handle_data(self, data: str) -> None:
        if self._inline is not None:
            self._inline.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inline is not None:
            body = "".join(self._inline)
            if body.strip():
                self.inline_scripts.append(body)
            self._inline = None


def inline_scripts_blocked(policies: list[str]) -> bool:
    """Whether one enforced policy refuses every inline <script> element.

    A script runs only if every policy admits it, so one blocking policy is
    enough. A policy blocks inline elements when the list governing them --
    `script-src-elem`, else `script-src`, else `default-src` -- exists and
    carries no 'unsafe-inline', nonce or hash: whether a nonce or hash matches
    THIS script is not asked, because it only has to be able to. The
    `script-src` list is read too, for engines without `script-src-elem`.
    """
    for raw in policies:
        policy = parse_csp(raw)
        governing = [
            next((policy[name] for name in chain if name in policy), None)
            for chain in (("script-src-elem", "script-src", "default-src"), ("script-src", "default-src"))
        ]
        if all(
            sources is not None
            and not any(source.lower() == "'unsafe-inline'" or HASH_OR_NONCE.match(source) for source in sources)
            for sources in governing
        ):
            return True
    return False


# Sources known never to admit an external script from another origin. Every
# other source -- that origin's host, a scheme, a wildcard, a nonce or hash
# (an injected tag can carry either), 'strict-dynamic' or a keyword this gate
# does not know -- is read as admitting it.
_INERT_FOR_EXTERNAL = {
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'", "'report-sample'", "'unsafe-hashes'",
}


def script_origin_blocked(policies: list[str], origin: str) -> bool:
    """Whether one enforced policy refuses <script src> from `origin`.

    The counterpart of `inline_scripts_blocked` for a script the edge injects
    from another origin. A policy blocks it when the list governing <script>
    elements -- `script-src-elem`, else `script-src`, else `default-src` --
    exists and no source in it can admit that origin's host, whatever the
    scheme. The `script-src` list is read too, for engines without
    `script-src-elem`, and one blocking policy is enough.
    """
    host = urlsplit(origin).hostname

    def admits(sources: list[str]) -> bool:
        for source in sources:
            lowered = source.lower()
            if lowered in _INERT_FOR_EXTERNAL:
                continue
            if lowered.startswith("'") or "*" in lowered or lowered.endswith(":"):
                return True
            if urlsplit(lowered if "://" in lowered else "https://" + lowered).hostname == host:
                return True
        return False

    for raw in policies:
        policy = parse_csp(raw)
        governing = [
            next((policy[name] for name in chain if name in policy), None)
            for chain in (("script-src-elem", "script-src", "default-src"), ("script-src", "default-src"))
        ]
        if all(sources is not None and not admits(sources) for sources in governing):
            return True
    return False


def reporting_origins(document: Fetched) -> set[str]:
    origins: set[str] = set()
    for value in document.all("report-to"):
        try:
            groups = json.loads("[" + value + "]")
        except json.JSONDecodeError:
            origins.add("<unparseable Report-To>")
            continue
        for group in groups:
            for endpoint in group.get("endpoints", []) if isinstance(group, dict) else []:
                url = endpoint.get("url") if isinstance(endpoint, dict) else None
                if isinstance(url, str):
                    origins.add(origin_of(url))
    for value in document.all("reporting-endpoints"):
        for match in re.finditer(r'"([^"]+)"', value):
            origins.add(origin_of(match.group(1)))
    for value in document.all("content-security-policy"):
        for url in parse_csp(value).get("report-uri", []):
            origins.add(origin_of(urljoin(document.url, url)))
    return origins


def judge(manifest: dict, document: Fetched, pages: dict[str, Fetched]) -> Verdict:
    verdict = Verdict()
    site = origin_of(manifest["liveUrl"])
    declared = {entry["origin"].lower() for entry in _entries(manifest, "thirdParties")}
    observations = _entries(manifest, "edgeObservations")
    markers = {entry["marker"]: False for entry in observations if entry.get("kind") == "injected-inline-script"}
    reporters = {
        entry["origin"].lower(): False for entry in observations if entry.get("kind") == "reporting-endpoint"
    }
    injected_origins = {
        entry["origin"].lower(): False for entry in observations if entry.get("kind") == "injected-script-origin"
    }

    if document.status != 200:
        verdict.refuse(
            f"the document answered {document.status}, not 200; an edge challenge or an outage is "
            "not a compliance pass, and the rest of the headers below may not be the site's"
        )

    policies = document.all("content-security-policy")
    referenced: set[str] = set()
    if not policies:
        verdict.refuse("no Content-Security-Policy header: nothing bounds which origins a page may load")
    for raw in policies:
        policy = parse_csp(raw)
        if "default-src" not in policy:
            verdict.refuse("the CSP has no default-src, so every fetch directive it omits admits any origin")
        for directive in FETCH_DIRECTIVES:
            for source in policy.get(directive, []):
                lowered = source.lower()
                if lowered in NEUTRAL_KEYWORDS or HASH_OR_NONCE.match(source):
                    continue
                if lowered in INLINE_KEYWORDS:
                    if directive in SCRIPT_DIRECTIVES:
                        verdict.refuse(f"the CSP {directive} admits {source}, which runs code no file of this repository shipped")
                    continue
                if lowered.startswith("'"):
                    # 'strict-dynamic' and any keyword this judge does not
                    # know: each can widen what loads, so none passes unread.
                    verdict.refuse(f"the CSP {directive} carries {source}, a keyword this gate does not admit")
                    continue
                if lowered in SCHEME_SOURCES:
                    if directive not in SCHEME_SOURCES[lowered]:
                        verdict.refuse(f"the CSP {directive} admits the bare scheme {source}")
                    continue
                if "*" in lowered or lowered.endswith(":"):
                    verdict.refuse(f"the CSP {directive} admits {source}, which names no single origin")
                    continue
                candidate = lowered if "://" in lowered else "https://" + lowered
                candidate = origin_of(candidate)
                referenced.add(candidate)
                if candidate != site and candidate not in declared:
                    verdict.refuse(
                        f"the CSP {directive} admits the undeclared origin {candidate}",
                        f'add to compliance.json thirdParties {{"origin": "{candidate}", "purpose": "...", '
                        '"consent": "not-required", "reason": "..."}',
                    )
        ancestors = policy.get("frame-ancestors")
        if ancestors is not None and set(a.lower() for a in ancestors) - {"'none'", "'self'"}:
            verdict.refuse(f"the CSP frame-ancestors admits {' '.join(ancestors)}")
    framing_denied = any(
        set(a.lower() for a in parse_csp(raw).get("frame-ancestors", ["*"])) <= {"'none'", "'self'"}
        for raw in policies
    ) or (document.first("x-frame-options") or "").strip().upper() in {"DENY", "SAMEORIGIN"}
    if not framing_denied:
        verdict.refuse("neither frame-ancestors nor X-Frame-Options denies framing by other sites")

    for origin in sorted(declared - referenced):
        verdict.refuse(
            f"thirdParties declares {origin}, which the live CSP no longer admits: the entry is stale",
            "delete that thirdParties entry",
        )

    hsts = document.first("strict-transport-security") or ""
    match = re.search(r"max-age\s*=\s*\"?([0-9]+)", hsts, re.IGNORECASE)
    if not match or int(match.group(1)) < HSTS_FLOOR_SECONDS:
        verdict.refuse(f"Strict-Transport-Security must carry max-age >= {HSTS_FLOOR_SECONDS}; got {hsts or 'nothing'}")
    if (document.first("x-content-type-options") or "").strip().lower() != "nosniff":
        verdict.refuse("X-Content-Type-Options: nosniff is missing")
    referrer = [token.strip().lower() for token in (document.first("referrer-policy") or "").split(",") if token.strip()]
    if not referrer or referrer[-1] not in REFERRER_POLICIES:
        verdict.refuse(f"Referrer-Policy must be one of {sorted(REFERRER_POLICIES)}; got {', '.join(referrer) or 'nothing'}")
    for cookie in document.all("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        verdict.refuse(f"the document sets the cookie {name!r} before the visitor has done anything")

    for origin in sorted(reporting_origins(document)):
        if origin == site:
            continue
        if origin in reporters:
            reporters[origin] = True
            verdict.notes.append(f"declared reporting endpoint seen: {origin}")
            continue
        verdict.refuse(
            f"browsers are told to send reports to the undeclared origin {origin}",
            f'add to compliance.json edgeObservations {{"kind": "reporting-endpoint", "origin": "{origin}", '
            '"reason": "...", "issue": "<issue URL>"}',
        )

    resources = _Resources()
    resources.feed(document.body.decode("utf-8", errors="replace"))
    resources.close()
    for kind, url in resources.loads:
        target = urlsplit(urljoin(document.url, url))
        if target.scheme not in {"http", "https"}:
            continue
        origin = origin_of(urljoin(document.url, url))
        if origin != site and origin not in declared and kind == "script" and origin in injected_origins:
            injected_origins[origin] = True
            if script_origin_blocked(policies, origin):
                verdict.notes.append(f"declared injected script origin seen: {origin}")
            else:
                # As for an injected inline script, the declaration rests on
                # the block, so no manifest line lifts this.
                verdict.refuse(
                    f"the served HTML loads script from the declared injected origin {origin}, which this CSP can "
                    "let run: no enforced policy blocks scripts from it, and the declaration rests on that block"
                )
            continue
        if origin != site and origin not in declared:
            verdict.refuse(
                f"the served HTML loads {kind} from the undeclared origin {origin}",
                f'add to compliance.json thirdParties {{"origin": "{origin}", "purpose": "...", '
                '"consent": "not-required", "reason": "..."}',
            )
    blocked = inline_scripts_blocked(policies)
    for body in resources.inline_scripts:
        hit = next((marker for marker in markers if marker in body), None)
        if hit is None:
            verdict.refuse(
                "the served HTML carries an inline script this repository did not build "
                f"(starts {body.strip()[:60]!r})",
                'add to compliance.json edgeObservations {"kind": "injected-inline-script", "marker": "<text unique '
                'to that script>", "reason": "...", "issue": "<issue URL>"}',
            )
            continue
        markers[hit] = True
        if blocked:
            verdict.notes.append(f"declared injected script seen: {hit}")
        else:
            # The declaration's reason is that the CSP blocks the script, so
            # no manifest line lifts this: the decision goes back to its issue.
            verdict.refuse(
                f"the served HTML carries the declared injected script marked {hit!r}, which this CSP can let "
                "run: no enforced policy blocks every inline script, and the declaration rests on that block"
            )

    for marker, seen in sorted(markers.items()):
        if not seen:
            verdict.refuse(
                f"edgeObservations declares an injected script marked {marker!r} that no longer occurs: the entry is stale",
                "delete that edgeObservations entry",
            )
    for origin, seen in sorted(reporters.items()):
        if not seen:
            verdict.refuse(
                f"edgeObservations declares the reporting endpoint {origin}, which no longer occurs: the entry is stale",
                "delete that edgeObservations entry",
            )
    for origin, seen in sorted(injected_origins.items()):
        if not seen:
            verdict.refuse(
                f"edgeObservations declares the injected script origin {origin}, which no longer occurs: the entry is stale",
                "delete that edgeObservations entry",
            )

    for entry in _entries(manifest, "thirdParties"):
        if entry.get("consent") == "pending":
            verdict.notes.append(f"third party {entry.get('origin')} consent pending: {entry.get('decision')}")
    for entry in _entries(manifest, "handOffs"):
        verdict.notes.append(f"hand-off {entry.get('target')} (a visitor-started navigation, not a load): {entry.get('carries')}")

    for entry in _entries(manifest, "legalPages"):
        if entry.get("status") != "published":
            verdict.notes.append(f"legal page {entry.get('id')!r} pending: {entry.get('decision')}")
            continue
        answer = pages.get(entry["path"])
        if answer is None or answer.status != 200:
            status = "no answer" if answer is None else str(answer.status)
            verdict.refuse(f"the published legal page {entry['path']} answered {status}, not 200")
        elif not (answer.first("content-type") or "").lower().startswith("text/html"):
            verdict.refuse(f"the published legal page {entry['path']} is not served as text/html")
    return verdict


def _whole(answer) -> bytes:
    """The complete body, or ValueError: judging a prefix as the page is a false pass."""
    body = answer.read(BODY_CAP_BYTES + 1)
    if len(body) > BODY_CAP_BYTES:
        raise ValueError(f"the answer is larger than the {BODY_CAP_BYTES}-byte cap, and a prefix is not the page")
    # read() returns short, without raising, when the connection closes early.
    declared = answer.headers.get("Content-Length")
    if declared is not None and declared.strip() != str(len(body)):
        raise ValueError(f"the answer declared {declared.strip()} bytes and delivered {len(body)}, and a part is not the page")
    return body


def fetch(url: str) -> Fetched:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            return Fetched(response.geturl(), response.status, list(response.headers.items()), _whole(response))
    except urllib.error.HTTPError as error:
        with error:
            return Fetched(url, error.code, list(error.headers.items()), _whole(error))


def _log(line: str) -> None:
    print(f"compliance: {line}", flush=True)


def _read(manifest_path: Path) -> tuple[object, list[str]]:
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8")), []
    except (OSError, json.JSONDecodeError) as error:
        return None, [f"cannot read {manifest_path.name}: {error}"]


def run_check(manifest_path: Path) -> int:
    started = time.monotonic()
    _log(f"START mode=check manifest={manifest_path.name}")
    manifest, refusals = _read(manifest_path)
    if not refusals:
        refusals = validate(manifest)
    for refusal in refusals:
        _log(f"REFUSE {refusal}")
    decision = "fail" if refusals else "pass"
    _log(f"SUMMARY mode=check decision={decision} refusals={len(refusals)} duration_ms={int((time.monotonic() - started) * 1000)}")
    return 1 if refusals else 0


def run_live(manifest_path: Path, fetcher=fetch) -> int:
    started = time.monotonic()
    manifest, problems = _read(manifest_path)
    if not problems:
        problems = validate(manifest)
    pages_budget = len(_entries(manifest, "legalPages")) if isinstance(manifest, dict) else 0
    live_url = manifest.get("liveUrl") if isinstance(manifest, dict) else None
    _log(f"START mode=live url={live_url} budget_s={FETCH_TIMEOUT_SECONDS * (1 + pages_budget)}")
    if problems:
        for problem in problems:
            _log(f"REFUSE {problem}")
        _log(f"SUMMARY mode=live decision=fail refusals={len(problems)} duration_ms={int((time.monotonic() - started) * 1000)}")
        return 1
    try:
        document = fetcher(manifest["liveUrl"])
        pages = {
            entry["path"]: fetcher(urljoin(manifest["liveUrl"], entry["path"]))
            for entry in _entries(manifest, "legalPages")
            if entry.get("status") == "published"
        }
    except (OSError, ValueError, http.client.HTTPException) as error:
        _log(f"REFUSE the live site could not be read: {error!r}")
        _log(f"SUMMARY mode=live decision=fail refusals=1 duration_ms={int((time.monotonic() - started) * 1000)}")
        return 1
    verdict = judge(manifest, document, pages)
    for note in verdict.notes:
        _log(f"NOTE {note}")
    for refusal in verdict.refusals:
        _log(f"REFUSE {refusal}")
    decision = "fail" if verdict.refusals else "pass"
    _log(
        f"SUMMARY mode=live decision={decision} refusals={len(verdict.refusals)} "
        f"status={document.status} duration_ms={int((time.monotonic() - started) * 1000)}"
    )
    return 1 if verdict.refusals else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("check", "live"))
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check(args.manifest)
    return run_live(args.manifest)


if __name__ == "__main__":
    sys.exit(main())
