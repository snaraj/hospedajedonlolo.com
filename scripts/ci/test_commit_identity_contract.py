"""Hostile suite for `commit_identity_contract.py`.

Two halves, and both are load-bearing:

  * PURE rules over hand-built `Commit` records, so every refusal and every
    admission is stated as one readable case.
  * REAL git repositories, built in a temp directory and committed with a pinned
    per-command identity, so the plumbing this gate depends on -- the record-
    separated `git log` format, multi-line bodies, an empty range -- is proven
    against the actual tool rather than a fixture that agrees with itself.

The second half exists because the first cannot fail for the reason that would
actually hurt: a `--format` string that silently stops emitting a field, or a
body containing a blank line, breaks the READER, and a reader that returns
nothing makes every rule above it vacuous. `parse_log` therefore fails closed on
a record it cannot resolve, and that refusal is tested here.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

SPEC = importlib.util.spec_from_file_location(
    "commit_identity_contract", HERE / "commit_identity_contract.py"
)
assert SPEC and SPEC.loader
CIC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CIC
SPEC.loader.exec_module(CIC)

SANE = CIC.SANCTIONED_EMAIL
GH = CIC.GITHUB_MERGE_EMAIL

# A stand-in for "some other address". It is a reserved-for-documentation
# domain (RFC 2606), so this fixture introduces no real contact detail --
# requirement 12 binds tests and fixtures exactly as it binds production code.
OTHER = "someone@example.invalid"


def commit(sha: str = "a" * 40, author: str = SANE, committer: str = SANE, body: str = "subject\n") -> object:
    return CIC.Commit(sha=sha, author_email=author, committer_email=committer, body=body)


def rules(*commits) -> set[tuple[str, str]]:
    return {(r.sha, r.rule) for r in CIC.refusals(list(commits))}


class IdentityRuleTests(unittest.TestCase):
    def test_a_fully_sanctioned_commit_is_admitted(self):
        """The positive control. Without it every rule below could pass by
        refusing everything, which is not a gate but a wall."""
        self.assertEqual(rules(commit()), set())

    def test_a_foreign_author_is_refused(self):
        self.assertEqual(rules(commit(author=OTHER)), {("a" * 40, "identity")})

    def test_a_foreign_committer_is_refused(self):
        self.assertEqual(rules(commit(committer=OTHER)), {("a" * 40, "identity")})

    def test_githubs_merge_committer_is_admitted_but_only_as_committer(self):
        """The correction that makes this gate usable at all.

        A squash or rebase merge performed by the owner re-commits under
        GitHub's own identity, so refusing it would turn every main push red
        forever. It is admitted for the committer field ONLY -- as an AUTHOR it
        is still refused, because the author field carries the attribution
        requirement 3 is about.
        """
        self.assertEqual(rules(commit(committer=GH)), set())
        self.assertEqual(rules(commit(author=GH)), {("a" * 40, "identity")})

    def test_the_refusal_never_echoes_the_offending_address(self):
        """CI logs are public on a public repository.

        A gate whose purpose is keeping an address out of the permanent record
        must not publish it while refusing it. This is the assertion that keeps
        a future "make the error more helpful" edit honest.
        """
        messages = CIC.report([commit(author=OTHER, committer=OTHER)], {})
        self.assertEqual(len(messages), 1)
        self.assertNotIn(OTHER, messages[0])
        self.assertIn("a" * 40, messages[0])

    def test_a_co_author_trailer_is_refused_in_every_spelling(self):
        """`git interpret-trailers` is case-insensitive and tolerates padding,
        and so is GitHub when it credits a co-author. The refusal matches the
        same shapes, or it is trivially evaded by pressing shift."""
        for body in (
            "subject\n\nCo-authored-by: Someone <x@example.invalid>\n",
            "subject\n\nco-authored-by: Someone <x@example.invalid>\n",
            "subject\n\nCO-AUTHORED-BY: Someone <x@example.invalid>\n",
            "subject\n\n  Co-authored-by : Someone <x@example.invalid>\n",
            "subject\n\nCo-Authored-By:\tSomeone <x@example.invalid>\n",
        ):
            with self.subTest(body=body.splitlines()[-1]):
                self.assertEqual(rules(commit(body=body)), {("a" * 40, "co-author")})

    def test_prose_merely_discussing_a_trailer_is_not_one(self):
        """The negative control for the rule above.

        A commit body may legitimately explain that co-author trailers are
        forbidden -- this repository's own contract does. Only a line that
        opens with the trailer token counts, so a sentence mentioning it
        mid-line passes.
        """
        body = "subject\n\nThis change forbids a Co-authored-by: trailer outright.\n"
        self.assertEqual(rules(commit(body=body)), set())

    def test_one_commit_can_break_both_rules_at_once(self):
        both = commit(author=OTHER, body="subject\n\nCo-authored-by: X <x@example.invalid>\n")
        self.assertEqual(rules(both), {("a" * 40, "identity"), ("a" * 40, "co-author")})

    def test_the_allowlist_suppresses_exactly_its_own_key(self):
        """Keyed on (sha, rule): exempting one rule must not exempt the other."""
        both = commit(author=OTHER, body="subject\n\nCo-authored-by: X <x@example.invalid>\n")
        messages = CIC.report([both], {("a" * 40, "identity"): "documented"})
        self.assertEqual(len(messages), 1)
        self.assertIn("Co-authored-by", messages[0])

    def test_the_failure_message_prints_the_exact_line_that_lifts_it(self):
        """Every gate ships a one-line lift path, or it is a chore, not a gate."""
        message = CIC.report([commit(author=OTHER)], {})[0]
        self.assertIn("scripts/ci/commit-identity-allowlist.txt", message)
        self.assertIn(f"{'a' * 40} | identity | ", message)


class LogReaderTests(unittest.TestCase):
    """The reader, against real git. A broken reader makes every rule vacuous."""

    @staticmethod
    def git(repository: Path, *arguments: str, **environment: str) -> None:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            env={**dict(__import__("os").environ), **environment},
        )
        if completed.returncode != 0:  # pragma: no cover - a broken fixture, not a finding
            raise AssertionError(f"git {' '.join(arguments)} failed: {completed.stderr}")

    def build(self, directory: Path, commits: list[tuple[str, str, str]]) -> None:
        """Create a repository and land `commits` as (author, committer, message)."""
        self.git(directory, "init", "--quiet", "--initial-branch=main")
        for index, (author, committer, message) in enumerate(commits):
            (directory / f"file{index}.txt").write_text(str(index), encoding="utf-8")
            self.git(directory, "add", "-A")
            self.git(
                directory,
                "-c", "commit.gpgsign=false",
                "commit", "--quiet", "-m", message,
                GIT_AUTHOR_NAME="A", GIT_AUTHOR_EMAIL=author,
                GIT_COMMITTER_NAME="C", GIT_COMMITTER_EMAIL=committer,
            )

    def test_a_real_range_is_read_and_judged_end_to_end(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.build(
                directory,
                [
                    (SANE, SANE, "base\n"),
                    (SANE, SANE, "clean subject\n\nA body with a blank line above it.\n"),
                    (OTHER, SANE, "foreign author\n"),
                    (SANE, SANE, "trailered\n\nCo-authored-by: X <x@example.invalid>\n"),
                ],
            )
            head = subprocess.run(
                ["git", "-C", str(directory), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            base = subprocess.run(
                ["git", "-C", str(directory), "rev-parse", "HEAD~3"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()

            commits = CIC.read_commits(directory, base, head)
            self.assertEqual(len(commits), 3, "the range must exclude its own base")
            # The multi-line body survived the record-separated format: if it had
            # not, the blank line would have split one commit into two records.
            self.assertTrue(any("blank line above it" in c.body for c in commits))
            observed = {rule for _, rule in {(r.sha, r.rule) for r in CIC.refusals(commits)}}
            self.assertEqual(observed, {"identity", "co-author"})

    def test_a_clean_real_range_produces_no_refusals(self):
        """The end-to-end positive control."""
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.build(directory, [(SANE, SANE, "base\n"), (SANE, GH, "owner squash merge\n")])
            head = subprocess.run(
                ["git", "-C", str(directory), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            commits = CIC.read_commits(directory, f"{head}~1", head)
            self.assertEqual(len(commits), 1)
            self.assertEqual(CIC.refusals(commits), [])

    def test_an_unresolvable_range_fails_closed(self):
        """A gate that cannot read its input must go red, never quiet."""
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.build(directory, [(SANE, SANE, "base\n")])
            with self.assertRaises(AssertionError):
                CIC.read_commits(directory, "b" * 40, "HEAD")

    def test_an_unreadable_log_record_fails_closed(self):
        """The reader refuses malformed output instead of returning nothing.

        Returning `[]` would make every rule in this file pass vacuously, which
        is the single most dangerous way for this gate to break.
        """
        with self.assertRaises(AssertionError):
            CIC.parse_log("only\x1ftwo\x1e")
        with self.assertRaises(AssertionError):
            CIC.parse_log("not-a-sha\x1fa@b\x1fa@b\x1fsubject\x1e")

    def test_an_empty_range_reads_as_no_commits(self):
        """A range contributing nothing is legitimately empty, not an error."""
        self.assertEqual(CIC.parse_log(""), [])


class AllowlistTests(unittest.TestCase):
    def test_the_shipped_allowlist_parses(self):
        """The file parses, and this repository's carries no entry: its history
        began under this gate, so every commit already passes it."""
        entries = CIC.read_allowlist()
        self.assertEqual(entries, {}, "an exemption appeared; it needs its own reviewed reason")
        # Positive control: the reader does resolve a well-formed entry, so the
        # emptiness above is the file's, not a reader that finds nothing.
        self.assertEqual(
            CIC.read_allowlist(f"{'a' * 40} | identity | a written reason\n"),
            {("a" * 40, "identity"): "a written reason"},
        )
        for (sha, rule), reason in entries.items():
            with self.subTest(sha=sha, rule=rule):
                self.assertRegex(sha, r"^[0-9a-f]{40}$")
                self.assertIn(rule, CIC.RULES)
                self.assertTrue(reason.strip())

    def test_the_shipped_allowlist_names_no_unsanctioned_address(self):
        """Requirement 12, enforced on the file that documents its violations.

        Recording an offending address here -- even to explain an exemption --
        would be the disclosure this gate exists to prevent. The only addresses
        admissible anywhere in this file are the two the rule itself names, and
        both are already public, non-personal constants.

        The failure message reports a COUNT and never the values, for the same
        reason the refusals do: a red build on a public repository is a public
        document, so an assertion about a leak must not become the leak.
        """
        text = CIC.ALLOWLIST.read_text(encoding="utf-8")
        found = set(re.findall(r"[0-9A-Za-z._%+-]+@[0-9A-Za-z.-]+\.[A-Za-z]{2,}", text))
        unsanctioned = found - {SANE, GH}
        self.assertEqual(
            len(unsanctioned),
            0,
            f"{len(unsanctioned)} unsanctioned address(es) in "
            f"{CIC.ALLOWLIST.name}; the values are deliberately not printed -- "
            f"open the file locally. Exemptions are keyed by SHA and rule; an "
            f"address never belongs in one.",
        )
        # Positive control: the sweep really does find addresses in this file,
        # so the assertion above cannot pass because the pattern matches nothing.
        self.assertIn(GH, found)

    def test_every_shipped_entry_names_a_commit_that_exists(self):
        """A stale exemption protects nothing and can silently cover a future
        commit that reuses the SHA prefix -- which is why abbreviations are
        refused and why this checks the full object resolves."""
        for sha, _ in CIC.read_allowlist():
            with self.subTest(sha=sha):
                completed = subprocess.run(
                    ["git", "-C", str(ROOT), "cat-file", "-t", sha],
                    capture_output=True, text=True,
                )
                self.assertEqual(completed.returncode, 0, f"{sha} is not in this repository")
                self.assertEqual(completed.stdout.strip(), "commit")

    def test_a_malformed_allowlist_entry_is_refused(self):
        """The lift mechanism must never degrade into a mute button."""
        for bad in (
            f"{'a' * 40} | identity",  # two fields
            f"{'a' * 40} | identity | ",  # blank reason
            f"{'a' * 40} | bogus-rule | a reason",  # unknown rule
            "abc1234 | identity | abbreviated sha",
            f"{'A' * 40} | identity | uppercase sha",
            " |  | ",  # every field blank
        ):
            with self.subTest(entry=bad):
                with self.assertRaises(AssertionError):
                    CIC.read_allowlist(bad + "\n")
        # Positive control: a well-formed entry still parses, so the loop above
        # cannot pass merely because the parser refuses everything.
        self.assertEqual(
            CIC.read_allowlist(f"{'a' * 40} | co-author | a real reason\n"),
            {("a" * 40, "co-author"): "a real reason"},
        )


if __name__ == "__main__":
    unittest.main()
