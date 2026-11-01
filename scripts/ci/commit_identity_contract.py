"""Refuse a commit whose identity or message body breaks requirements 3 and 12.

WHY THIS EXISTS. `gitleaks git` and `gitleaks dir` are the repository's enforced
secret scans, and both read BLOB CONTENT. A commit's author and committer
identity, and the text of its message body, are not blobs -- they live in the
commit object. So the enforced scan surface has structurally ZERO coverage over
the two things requirements 3 and 12 actually say about a commit:

  * requirement 3 -- commits are authored AND committed as the owner's GitHub
    noreply identity, in BOTH fields, and carry no co-author trailer;
  * requirement 12 -- no personal data enters this repository, and what reaches
    history cannot be unpublished.

Those two meet in one failure mode: an address typed into `GIT_AUTHOR_EMAIL`, or
a `Co-authored-by:` trailer pasted into a message, is permanently public the
moment it lands on `main`, and no later commit can retract it. A gate that runs
BEFORE the merge is the only control that works, because every control after it
is a history rewrite the contract forbids.

This repository already carries the scar. Commits that predate this gate are
named, with their reason, in `scripts/ci/commit-identity-allowlist.txt`; they
are ancestors of `main`, permanently public, and deliberately NOT rewritten.

WHAT IT PINS -- BEHAVIOUR, NOT INVENTORY. Two refusals, scoped to the range the
push or pull request actually contributes:

  1. `identity` -- the author or the committer email is not the sanctioned
     noreply identity.
  2. `co-author` -- the message body carries a `Co-authored-by:` trailer, which
     requirement 3 forbids outright.

There is no commit census here. This gate never asserts "the range contains
exactly N commits", never pins a subject line, and never enumerates history:
range-scoping is what keeps it from re-litigating the root commit on every run,
and a closed inventory would break on every legitimate commit. Adding a commit
needs no edit to this file.

WHAT IT DELIBERATELY DOES NOT PRINT. A refusal names the SHA and the rule, and
never echoes the offending address. CI logs on a public repository are public;
a gate that exists to keep an address out of the public record must not publish
it in the course of refusing it. `git log -1 --format='%an <%ae>' <sha>` shows
the author their own identity locally, which is where it belongs.

LIFTING IT. Both refusals lift through
`scripts/ci/commit-identity-allowlist.txt`: one line, one written reason, one
PR. Entries are keyed by SHA and rule -- never by address, for the same reason
the failure message does not print one.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ALLOWLIST = HERE / "commit-identity-allowlist.txt"

# Requirement 12's narrow canonical attribution exception: the already-public
# owner noreply commit identity. Per "Commit identity mechanics" this is the
# only admissible AUTHOR, and the only admissible committer an agent may
# produce.
SANCTIONED_EMAIL = "39077795+snaraj@users.noreply.github.com"

# GitHub's own committer identity, stamped when the OWNER merges a pull request
# through the web UI. It is admitted for the COMMITTER field only, and this is a
# correction rather than a concession: 72 of the 113 commits on `main` at the
# time this gate was written carry it, because squash and rebase merges re-commit
# under GitHub's identity and the merging owner cannot choose otherwise. A rule
# that refused it would refuse every owner-merge forever -- red on every main
# push, liftable only by allowlisting an ever-growing census of merge commits,
# which is exactly the brittle inventory shape the liftable-gates directive
# rejects. It is safe to admit for one reason and one reason only: it names no
# person. It is a shared, non-routable constant that carries no account handle
# and no private contact detail, so it cannot leak what requirement 12 protects.
# It is NOT admitted as an author, because the author field is the attribution
# requirement 3 is actually about.
GITHUB_MERGE_EMAIL = "noreply@github.com"

RULES = ("identity", "co-author")

# `git interpret-trailers` treats a trailer token case-insensitively and allows
# whitespace before the colon, so the refusal matches the same shapes GitHub
# does when it credits a co-author.
CO_AUTHOR = re.compile(r"^[ \t]*co-authored-by[ \t]*:", re.IGNORECASE | re.MULTILINE)

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

RECORD_SEPARATOR = "\x1e"
FIELD_SEPARATOR = "\x1f"
# %B is the raw body, which may contain newlines and blank lines; the unit and
# record separators cannot appear in a git identity or a message written by any
# ordinary editor, so this format parses unambiguously where a newline-delimited
# one would split a multi-line body into fake records.
LOG_FORMAT = FIELD_SEPARATOR.join(("%H", "%ae", "%ce", "%B")) + RECORD_SEPARATOR


@dataclass(frozen=True)
class Commit:
    sha: str
    author_email: str
    committer_email: str
    body: str


@dataclass(frozen=True)
class Refusal:
    sha: str
    rule: str
    detail: str


def read_commits(repository: Path, base: str, head: str) -> list[Commit]:
    """Read `base..head` from a real repository. Fails closed on any git error."""
    completed = subprocess.run(
        ["git", "-C", str(repository), "log", f"--format={LOG_FORMAT}", f"{base}..{head}"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"git could not resolve the range {base}..{head}: "
            f"{completed.stderr.strip()}"
        )
    return parse_log(completed.stdout)


def parse_log(text: str) -> list[Commit]:
    """Split the record-separated log into commits. Fails closed on a bad record."""
    commits: list[Commit] = []
    for raw in text.split(RECORD_SEPARATOR):
        record = raw.strip("\n")
        if not record.strip():
            continue
        fields = record.split(FIELD_SEPARATOR)
        if len(fields) != 4:
            raise AssertionError(
                f"unparseable git log record with {len(fields)} fields, expected 4. "
                f"This gate refuses to pass on output it cannot read."
            )
        sha, author_email, committer_email, body = fields
        if not FULL_SHA.match(sha):
            raise AssertionError(
                f"git log yielded {sha!r} where a 40-hex commit SHA was expected. "
                f"This gate refuses to pass on output it cannot read."
            )
        commits.append(Commit(sha, author_email, committer_email, body))
    return commits


def refusals(commits: list[Commit]) -> list[Refusal]:
    """Every rule violation in `commits`, before the allowlist is applied."""
    found: list[Refusal] = []
    for commit in commits:
        wrong = [
            field
            for field, value, admissible in (
                ("author", commit.author_email, (SANCTIONED_EMAIL,)),
                ("committer", commit.committer_email, (SANCTIONED_EMAIL, GITHUB_MERGE_EMAIL)),
            )
            if value not in admissible
        ]
        if wrong:
            # The offending value is deliberately absent: see the module
            # docstring. Naming WHICH field is wrong is enough to act on.
            found.append(Refusal(commit.sha, "identity", f"{' and '.join(wrong)} email"))
        if CO_AUTHOR.search(commit.body):
            found.append(Refusal(commit.sha, "co-author", "Co-authored-by: trailer"))
    return found


def read_allowlist(text: str | None = None) -> dict[tuple[str, str], str]:
    """Parse `<sha> | <rule> | <reason>` lines.

    `text` exists so these refusals are TESTABLE without writing a broken line
    into the real allowlist; the shipped call passes nothing and reads the file.
    """
    entries: dict[tuple[str, str], str] = {}
    if text is None:
        text = ALLOWLIST.read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 3:
            raise AssertionError(
                f"{ALLOWLIST.name}:{number}: expected exactly three "
                f"`|`-separated fields -- `<sha> | <rule> | <reason>`."
            )
        sha, rule, reason = parts
        if not all((sha, rule, reason)):
            raise AssertionError(
                f"{ALLOWLIST.name}:{number}: every field must be non-empty. "
                f"An allowlist without reasons is a mute button."
            )
        if not FULL_SHA.match(sha):
            raise AssertionError(
                f"{ALLOWLIST.name}:{number}: {sha!r} is not a 40-lowercase-hex "
                f"commit SHA. An abbreviated SHA can become ambiguous as history "
                f"grows, and an exemption that starts matching a second commit is "
                f"an exemption nobody wrote."
            )
        if rule not in RULES:
            raise AssertionError(
                f"{ALLOWLIST.name}:{number}: unknown rule {rule!r}; expected one "
                f"of {', '.join(RULES)}."
            )
        entries[(sha, rule)] = reason
    return entries


def lift_instruction(refusal: Refusal) -> str:
    return (
        f"\n\nTo lift this refusal, add ONE line to "
        f"{ALLOWLIST.relative_to(ROOT).as_posix()}:\n\n"
        f"    {refusal.sha} | {refusal.rule} | <why this commit is admissible>\n\n"
        f"Prefer fixing the cause: an unpushed commit is re-made under the pinned "
        f"identity from `AGENTS.md` \"Commit identity mechanics\", and a co-author "
        f"trailer is simply deleted. Allowlist a commit only when it is already "
        f"published and therefore unfixable."
    )


def report(commits: list[Commit], allowlist: dict[tuple[str, str], str]) -> list[str]:
    """Human-readable refusals, allowlisted ones removed."""
    messages: list[str] = []
    for refusal in refusals(commits):
        if (refusal.sha, refusal.rule) in allowlist:
            continue
        if refusal.rule == "identity":
            messages.append(
                f"{refusal.sha}: the {refusal.detail} is not the sanctioned "
                f"noreply identity that AGENTS.md requirement 3 pins in BOTH the "
                f"author and the committer field. The offending value is not "
                f"printed here on purpose -- CI logs are public, and this gate "
                f"exists to keep an address out of the public record. Run "
                f"`git log -1 --format='%an <%ae> / %cn <%ce>' {refusal.sha}` to "
                f"see it locally." + lift_instruction(refusal)
            )
        else:
            messages.append(
                f"{refusal.sha}: the message body carries a {refusal.detail}, "
                f"which AGENTS.md requirement 3 forbids outright (\"No co-author "
                f"trailers, ever\"). A trailer names a person in permanently "
                f"public history and is never required by this repository's "
                f"attribution model, which is the acting agent's signature line."
                + lift_instruction(refusal)
            )
    return messages


def main(argv: list[str] | None = None) -> int:
    # `__doc__` is `str | None` to a type checker (`-OO` strips docstrings),
    # so the unguarded `.splitlines()` was a reportOptionalMemberAccess this
    # file introduced.
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else None
    )
    parser.add_argument("--repository", default=".", type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args(argv)

    commits = read_commits(args.repository, args.base, args.head)
    messages = report(commits, read_allowlist())
    if messages:
        for message in messages:
            print(message, file=sys.stderr)
            print(file=sys.stderr)
        return 1
    print(f"commit identity contract: {len(commits)} commit(s) in range, no refusals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
