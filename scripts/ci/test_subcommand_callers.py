"""Every `release_contract.py` subcommand must have a caller, and the sweep
that proves it must survive line wrapping.

WHY THIS EXISTS. `scripts/ci/release_contract.py` registers its subcommands
with `argparse`, and the workflows invoke them by NAME, as strings, in shell.
Nothing checked that the two sides agree, in either direction. That asymmetry
produced a near-miss during the 0.1.49 dead-code lane: an audit reported
`release-record` as dead and proposed removing it. It is not dead -- it is
invoked from the terminal publisher step of `release-publisher.yml` and again
from `release-audit.yml`. The audit missed it because the invocation is
wrapped with a trailing backslash, so any same-line pattern that includes an
ARGUMENT (`release-record --release-json`) matches nothing:

    python3 -I -B scripts/ci/release_contract.py release-record \\
      --release-json "${release_json}" --tag "${TAG}" \\
      ...

Removing it was proven to break the publisher at runtime. A gate that only
looks at one side of a string-typed interface is how that gets shipped.

WHAT IT PINS -- BEHAVIOUR, NOT INVENTORY. This gate does NOT assert "the
complete set of subcommands is exactly these 27". Such a pin would break on
every legitimate subcommand addition and would teach the next agent to update
a number rather than think. It asserts one behaviour instead: no registered
subcommand may be unreachable from the repository that ships it. The names
come from the PARSER OBJECT at runtime, so adding or renaming a subcommand
needs no edit here; only a subcommand with genuinely no caller does.

HOW THE SWEEP WORKS.

  * Names are read from the live `argparse` parser (`_parser()`), never from a
    hand-maintained list, so this file cannot drift from the CLI it guards.

  * Each name is searched as a BARE TOKEN -- `(?<![0-9A-Za-z_-])name
    (?![0-9A-Za-z_-])` -- anywhere in a file, with no requirement that it share
    a line with `release_contract.py`. That is the specific defence against the
    near-miss above: a backslash wrap cannot hide a caller from a search that
    never looks at line structure.

  * Comments are stripped first, per file type, because a comment is not a
    caller. `immutable-settings` once appeared in a workflow only in the prose
    sentence "the publisher's authoritative immutable-settings guard";
    counting that as a workflow caller would hide a real smell behind a
    sentence. Markdown is the deliberate exception -- prose in `docs/` IS
    the caller for an operator escape hatch -- so only `<!-- -->` is removed
    there.

  * The defining file, `release_contract.py` itself, is excluded. Its
    `add_parser("x")` registrations and `args.command == "x"` dispatch arms are
    self-references, and counting them would make every subcommand look alive.

TIERS, AND WHY THEY DIFFER. A caller is reported as `workflow`, `script`,
`doc`, or `test`, because the tiers do not mean the same thing. A doc-only
subcommand is legitimate: `settings-receipt` and `settings-preflight` are
operator escape hatches invoked by hand from `docs/release-governance.md`, and
a human running a documented command is a real caller. A TEST-only subcommand
is a genuine smell -- the CLI surface exists solely to be tested, so the test
proves only that the test can call it. This gate therefore fails on zero
callers of any tier, and separately on test-only.

HONEST LIMIT. Bare-token matching over-counts rather than under-counts: a name
that is also an ordinary English word (`publisher`, `transition`) matches
prose. Over-counting can only produce a false GREEN -- never a false RED --
so the failure direction stays safe, but this gate is a floor on reachability,
not a proof of use. Under-counting was the bug it was built for, and that
direction is closed.

LIFTING IT. Both refusals lift through
`scripts/ci/subcommand-callers-allowlist.txt`: one line, one written reason,
one PR. Widening it is an expected part of active development. The gate
refuses a stale entry, so the file ratchets shut as callers land.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import io
import re
import sys
import tokenize
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTRACT = HERE / "release_contract.py"
ALLOWLIST = HERE / "subcommand-callers-allowlist.txt"

SPEC = importlib.util.spec_from_file_location("release_contract", CONTRACT)
assert SPEC and SPEC.loader
RC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RC
SPEC.loader.exec_module(RC)

TIERS = ("workflow", "script", "doc", "test")

# Markdown that RECORDS the past rather than instructing an operator. The doc
# tier counts as a caller because "a human running a documented command is a
# real caller"; a changelog entry is nobody's instruction, so naming a
# subcommand there gives it no reachability. Excluding it is a NARROWING --
# fewer files are searched, so the sweep finds fewer callers and fails more
# readily. It was found the hard way: the 0.1.49 changelog entry describing
# THIS gate mentioned `immutable-settings` in prose, which silently spent the
# allowlist entry that documents why that subcommand is test-only.
HISTORY_DOCS = frozenset({"CHANGELOG.md"})


# --------------------------------------------------------------------------
# Comment stripping, per file type. A comment is not a caller.
# --------------------------------------------------------------------------


def strip_hash_comments(text: str) -> str:
    """Blank `#` comments in YAML and shell, leaving quoted `#` alone.

    Quote state is tracked per line and a `#` only opens a comment at the start
    of a line or after whitespace -- the YAML and POSIX-shell rule. This is
    deliberately simple: over-stripping removes a caller and turns the gate
    RED, which is loud and recoverable; under-stripping counts a comment as a
    caller and turns it GREEN, which is silent. The simple reader errs toward
    the loud direction.
    """
    kept: list[str] = []
    for line in text.splitlines():
        single = double = False
        cut = None
        for index, char in enumerate(line):
            if char == "'" and not double:
                single = not single
            elif char == '"' and not single:
                double = not double
            elif char == "#" and not single and not double:
                if index == 0 or line[index - 1] in " \t":
                    cut = index
                    break
        kept.append(line if cut is None else line[:cut])
    return "\n".join(kept)


def strip_python_comments(text: str) -> str:
    """Remove `#` comments and docstrings, but KEEP ordinary string literals.

    A Python caller passes the subcommand as a string -- `RC.main(["tag-state",
    ...])` -- so dropping every STRING token would erase exactly the callers
    this gate is looking for. Only comments and the module/class/function
    docstrings go, since those are prose.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        tree = ast.parse(text)
    except (SyntaxError, tokenize.TokenError, IndentationError):  # pragma: no cover
        # A file this gate cannot parse is searched raw rather than skipped:
        # skipping it could hide the only caller and produce a false RED.
        return text
    docstrings = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if body and isinstance(body[0], ast.Expr):
            value = body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                docstrings.add((value.lineno, value.col_offset))
    return "\n".join(
        token.string
        for token in tokens
        if token.type != tokenize.COMMENT
        and not (token.type == tokenize.STRING and token.start in docstrings)
    )


def strip_markdown_comments(text: str) -> str:
    """Remove only `<!-- -->`. Markdown PROSE is a legitimate doc caller."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def subcommand_names() -> list[str]:
    """Read the registered names off the live parser object.

    Not a hand-maintained list and not a regex over the source: the parser is
    built and interrogated, so anything argparse would actually accept is
    covered, including a name registered from a loop or a helper.
    """
    parser = RC._parser()
    actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if len(actions) != 1:  # pragma: no cover - fail closed on a parser reshape
        raise AssertionError(
            f"expected exactly one subparsers action in release_contract._parser(), "
            f"found {len(actions)}; this gate cannot enumerate subcommands and "
            f"refuses to pass vacuously"
        )
    return sorted(actions[0].choices)


def searchable_files() -> dict[Path, tuple[str, str]]:
    """Map every searchable file to its (tier, comment-stripped text)."""
    files: dict[Path, tuple[str, str]] = {}

    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        files[path] = ("workflow", strip_hash_comments(path.read_text(encoding="utf-8")))

    for path in sorted((ROOT / "scripts").rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path == CONTRACT or path.name.startswith("test_"):
            continue
        if path.suffix == ".py":
            files[path] = ("script", strip_python_comments(path.read_text(encoding="utf-8")))
        elif path.suffix in (".sh", ".template", ".sb") or not path.suffix:
            files[path] = ("script", strip_hash_comments(path.read_text(encoding="utf-8")))

    for path in sorted((ROOT / "docs").glob("*.md")) + sorted(ROOT.glob("*.md")):
        if path.name in HISTORY_DOCS:
            continue
        files[path] = ("doc", strip_markdown_comments(path.read_text(encoding="utf-8")))

    for path in sorted(HERE.glob("test_*.py")):
        if path == Path(__file__).resolve():
            # This file names every subcommand it reports on. Counting itself
            # would make every subcommand permanently "test-tier alive".
            continue
        files[path] = ("test", strip_python_comments(path.read_text(encoding="utf-8")))

    return files


def bare_token(name: str) -> re.Pattern[str]:
    """Match `name` as a whole token, ignoring line structure entirely."""
    return re.compile(rf"(?<![0-9A-Za-z_-]){re.escape(name)}(?![0-9A-Za-z_-])")


def callers(name: str, files: dict[Path, tuple[str, str]]) -> dict[str, list[str]]:
    """Return {tier: [repo-relative path, ...]} for every file naming `name`."""
    pattern = bare_token(name)
    found: dict[str, list[str]] = {}
    for path, (tier, text) in files.items():
        if pattern.search(text):
            found.setdefault(tier, []).append(path.relative_to(ROOT).as_posix())
    return found


# --------------------------------------------------------------------------
# Allowlist -- the lift mechanism
# --------------------------------------------------------------------------


def read_allowlist(text: str | None = None) -> dict[str, str]:
    """Parse `<subcommand> | <reason>` lines. A missing reason is an error.

    `text` exists so these refusals are TESTABLE without writing a broken line
    into the real allowlist. A parser whose only probe is "edit the file it
    guards and see what happens" is a parser nobody re-checks; the shipped call
    passes nothing and reads the file exactly as before.
    """
    entries: dict[str, str] = {}
    if text is None:
        text = ALLOWLIST.read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip() if raw.lstrip().startswith("#") else raw.strip()
        if not line:
            continue
        if "|" not in line:
            raise AssertionError(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: entry has no reason. "
                f"The format is `<subcommand> | <reason>`; an allowlist without "
                f"reasons is a mute button."
            )
        name, reason = (part.strip() for part in line.split("|", 1))
        if not name or not reason:
            raise AssertionError(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: both the subcommand and "
                f"the reason must be non-empty."
            )
        entries[name] = reason
    return entries


def lift_instruction(name: str, situation: str) -> str:
    """The exact one-line change that lifts this refusal."""
    return (
        f"\n\nTo lift this refusal, add ONE line to "
        f"{ALLOWLIST.relative_to(ROOT).as_posix()}:\n\n"
        f"    {name} | {situation}\n\n"
        f"Replace the text after `|` with the real reason. Widening this "
        f"allowlist is a normal, expected part of active development -- one "
        f"line, one PR, no release train. The alternative fix is to give the "
        f"subcommand a real caller (a workflow step, a script, or a documented "
        f"operator command in docs/)."
    )


# --------------------------------------------------------------------------


class SubcommandCallerTests(unittest.TestCase):
    """Both directions of the string-typed CLI/workflow interface."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.names = subcommand_names()
        cls.files = searchable_files()
        cls.allowlist = read_allowlist()

    def test_the_sweep_finds_a_caller_hidden_by_a_trailing_backslash(self):
        """Replay the near-miss: a wrapped invocation must still be found.

        This is the regression the whole gate exists for. The synthetic file
        below is shaped exactly like `release-publisher.yml`'s terminal step.
        A same-line pattern that includes the first argument finds nothing; the
        bare-token sweep finds it.
        """
        wrapped = (
            '          python3 -I -B scripts/ci/release_contract.py release-record \\\n'
            '            --release-json "${release_json}" --tag "${TAG}" \\\n'
            '            --title "hospedajedonlolo.com ${TAG}"\n'
        )
        self.assertIsNone(
            re.search(r"release-record --release-json", wrapped),
            "the wrap must genuinely defeat a same-line name+argument pattern, "
            "otherwise this test is not reproducing the near-miss",
        )
        self.assertIsNotNone(
            bare_token("release-record").search(strip_hash_comments(wrapped)),
            "the bare-token sweep must find a caller across a backslash wrap",
        )

    def test_the_sweep_reports_zero_for_a_name_nothing_calls(self):
        """The negative control: a guard that cannot fail is no guard.

        Without this, a sweep broken into always-matching would pass every
        other test in this file.
        """
        absent = "definitely-not-a-registered-subcommand-9d41f0"
        self.assertNotIn(
            absent, self.names, "the control name must not be a real subcommand"
        )
        self.assertEqual(
            callers(absent, self.files),
            {},
            "the sweep reported a caller for a name that appears nowhere",
        )

    def test_a_comment_is_not_a_caller(self):
        """Prose naming a subcommand must not count as reaching it."""
        prose = "# the publisher's authoritative immutable-settings guard\n"
        self.assertIsNotNone(bare_token("immutable-settings").search(prose))
        self.assertIsNone(bare_token("immutable-settings").search(strip_hash_comments(prose)))

    def test_every_searchable_tier_has_files(self):
        """Fail closed if discovery silently stops finding a whole tier.

        A glob that matches nothing would make every subcommand in that tier
        look uncalled -- or, worse, make a test-only subcommand look
        caller-free in a way the allowlist then papers over.
        """
        observed = {tier for tier, _ in self.files.values()}
        for tier in TIERS:
            self.assertIn(tier, observed, f"no files discovered for the {tier!r} tier")

    def test_the_parser_registers_subcommands(self):
        """A parser that yields nothing must not pass this suite vacuously."""
        self.assertTrue(self.names, "no subcommands were read from the parser")

    def test_every_subcommand_has_at_least_one_caller(self):
        """Refuse a registered subcommand nothing in the repository reaches."""
        for name in self.names:
            with self.subTest(subcommand=name):
                found = callers(name, self.files)
                if found or name in self.allowlist:
                    continue
                self.fail(
                    f"release_contract.py registers the subcommand {name!r}, but no "
                    f"workflow, script, doc, or test in this repository names it. "
                    f"Either it is dead, or a caller is spelled differently than "
                    f"the parser registers it -- both are bugs, and the second one "
                    f"breaks at runtime, not at parse time."
                    + lift_instruction(name, "<why this subcommand has no caller and should stay>")
                )

    def test_no_subcommand_is_reachable_only_from_a_test(self):
        """A CLI surface that only its own test calls proves nothing."""
        for name in self.names:
            with self.subTest(subcommand=name):
                found = callers(name, self.files)
                if not found or set(found) != {"test"} or name in self.allowlist:
                    continue
                self.fail(
                    f"the subcommand {name!r} is named only by tests "
                    f"({', '.join(found['test'])}) -- no workflow, script, or doc "
                    f"reaches it. The test then proves only that the test can call "
                    f"it. A doc-tier caller is a legitimate fix: an operator command "
                    f"documented under docs/ is a real caller, which is why "
                    f"`settings-receipt` and `settings-preflight` pass."
                    + lift_instruction(name, "<why test-only reachability is correct here>")
                )

    def _drive(self, method: str, names, files, allowlist=None) -> str:
        """Run ONE shipped rule over synthetic inputs; return its message.

        Returns the refusal message, or `""` when the rule passed -- a plain
        `str` rather than `str | None` so callers can assert on the message
        without an Optional narrowing dance a type checker does not follow.

        Shadowing `names`/`files`/`allowlist` on a fresh instance drives the
        SHIPPED rule rather than a copy of its logic -- a reimplementation here
        would stay green while the real rule was deleted, which is the failure
        this fixture exists to close. `subTest` is inert outside a runner, so a
        refusal propagates instead of being swallowed.
        """
        probe = SubcommandCallerTests(method)
        probe.names = names
        probe.files = files
        probe.allowlist = {} if allowlist is None else allowlist
        try:
            getattr(probe, method)()
        except probe.failureException as failure:
            return str(failure)
        return ""

    def test_the_zero_caller_rule_refuses_an_uncalled_subcommand(self):
        """Reach the zero-caller refusal, which no real input reaches.

        Every registered subcommand has a real caller today, so nothing drove
        this rule's `self.fail` and it could be DELETED OUTRIGHT with the suite
        staying green. Its test-only sibling was driven for real at the time,
        and the gap was never extended upward. A sibling repository's review
        caught it.

        The paired live row is the positive control: without it, a rule mutated
        into always-failing would satisfy the refusal assertion and look like
        proof.
        """
        uncalled = "a-subcommand-nothing-calls-4b17ca"
        called = "a-subcommand-something-calls-4b17ca"
        files = {
            ROOT / ".github" / "workflows" / "synthetic.yml": (
                "workflow", f"run: release_contract.py {called}\n"
            ),
        }
        message = self._drive(
            "test_every_subcommand_has_at_least_one_caller", [uncalled], files
        )
        self.assertTrue(message, "an uncalled subcommand was not refused")
        self.assertIn(uncalled, message)
        self.assertIn("no workflow, script, doc, or test", message)
        self.assertIn("To lift this refusal", message)
        # Positive control: a subcommand a workflow really names passes.
        self.assertEqual(
            self._drive("test_every_subcommand_has_at_least_one_caller", [called], files), ""
        )
        # And the allowlist lifts the refusal, through one line naming it.
        self.assertEqual(
            self._drive(
                "test_every_subcommand_has_at_least_one_caller",
                [uncalled],
                files,
                {uncalled: "a written reason"},
            ),
            "",
        )
        # An entry naming a DIFFERENT subcommand must not lift it.
        self.assertTrue(
            self._drive(
                "test_every_subcommand_has_at_least_one_caller",
                [uncalled],
                files,
                {called: "a written reason"},
            )
        )

    def test_the_test_only_rule_refuses_a_test_reachable_subcommand(self):
        """Reach the test-only refusal, which the shipped tree also cannot reach.

        This one looks reachable and is not. No subcommand is test-only in this
        repository -- `immutable-settings`, the last one, has a doc-tier caller
        in `docs/release-governance.md`'s owner-verified commands -- so nothing
        in the shipped tree drives the rule's `self.fail`, and the refusal could
        be deleted with the suite staying green. This synthetic drive is what
        proves the rule still exists.
        """
        name = "a-subcommand-only-a-test-calls-4b17ca"
        test_only = {
            HERE / "test_synthetic.py": ("test", f'RC.main(["{name}"])\n'),
        }
        message = self._drive(
            "test_no_subcommand_is_reachable_only_from_a_test", [name], test_only
        )
        self.assertTrue(message, "a test-only subcommand was not refused")
        self.assertIn(name, message)
        self.assertIn("named only by tests", message)
        self.assertIn("To lift this refusal", message)
        # Positive control: one real workflow caller and the rule passes, so
        # this cannot be a rule that refuses everything.
        also_called = dict(test_only)
        also_called[ROOT / ".github" / "workflows" / "synthetic.yml"] = (
            "workflow", f"run: release_contract.py {name}\n"
        )
        self.assertEqual(
            self._drive(
                "test_no_subcommand_is_reachable_only_from_a_test", [name], also_called
            ),
            "",
        )
        # A doc-tier caller is the documented legitimate fix, so it must pass too.
        documented = dict(test_only)
        documented[ROOT / "docs" / "synthetic.md"] = (
            "doc", f"Run `release_contract.py {name}` by hand.\n"
        )
        self.assertEqual(
            self._drive(
                "test_no_subcommand_is_reachable_only_from_a_test", [name], documented
            ),
            "",
        )
        # And the allowlist lifts it, through one line naming it.
        self.assertEqual(
            self._drive(
                "test_no_subcommand_is_reachable_only_from_a_test",
                [name],
                test_only,
                {name: "a written reason"},
            ),
            "",
        )

    def test_allowlist_entries_name_real_subcommands(self):
        """A stale name in the allowlist silences a gate for nothing."""
        for name in sorted(self.allowlist):
            with self.subTest(entry=name):
                self.assertIn(
                    name,
                    self.names,
                    f"{ALLOWLIST.relative_to(ROOT)} exempts {name!r}, which the parser "
                    f"does not register. Remove the line -- it protects nothing and "
                    f"will silently cover a future subcommand that reuses the name.",
                )

    def test_allowlist_entries_are_still_needed(self):
        """The ratchet: an entry whose subject grew a caller must go.

        Without this the allowlist only ever grows, and the gate quietly
        becomes a list of things nobody checks any more.
        """
        for name in sorted(self.allowlist):
            if name not in self.names:
                continue  # reported by the previous test
            with self.subTest(entry=name):
                found = callers(name, self.files)
                if not found or set(found) == {"test"}:
                    continue
                self.fail(
                    f"{ALLOWLIST.relative_to(ROOT)} still exempts {name!r}, but it now "
                    f"has real callers: "
                    f"{'; '.join(f'{t}: {", ".join(p)}' for t, p in sorted(found.items()))}. "
                    f"Delete that line -- the exemption is spent."
                )

    def test_a_reasonless_allowlist_entry_is_refused(self):
        """The lift mechanism must never degrade into a mute button.

        This drives the PARSER, not the parsed dict. An earlier shape asserted
        `reason.strip()` over `self.allowlist`, which `read_allowlist` has
        already guaranteed non-empty -- an assertion no input could reach, so
        deleting either refusal below left it green. Vacuity found by the
        0.1.49 mutation sweep; the repair is to feed the refusals real input.
        """
        for bad in ("release-record", "release-record |", "| a reason", "  |  "):
            with self.subTest(entry=bad):
                with self.assertRaises(AssertionError):
                    read_allowlist(bad + "\n")
        # Positive control: a well-formed entry still parses, so the loop above
        # cannot pass merely because the parser refuses everything.
        self.assertEqual(
            read_allowlist("release-record | a real reason\n"),
            {"release-record": "a real reason"},
        )


def _report() -> int:  # pragma: no cover - operator convenience, not a gate
    """Print the tier table. `python3 -I -B scripts/ci/test_subcommand_callers.py --report`"""
    files = searchable_files()
    allowlist = read_allowlist()
    print(f"{'subcommand':24} {'workflow':>8} {'script':>6} {'doc':>4} {'test':>4}  status")
    for name in subcommand_names():
        found = callers(name, files)
        counts = [len(found.get(tier, ())) for tier in TIERS]
        if not found:
            status = "NO CALLER"
        elif set(found) == {"test"}:
            status = "TEST-ONLY"
        else:
            status = "ok"
        if name in allowlist and status != "ok":
            status += " (allowlisted)"
        print(f"{name:24} {counts[0]:>8} {counts[1]:>6} {counts[2]:>4} {counts[3]:>4}  {status}")
    return 0


if __name__ == "__main__":
    if "--report" in sys.argv:
        raise SystemExit(_report())
    unittest.main()
