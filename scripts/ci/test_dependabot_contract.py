"""Hostile tests for the `.github/dependabot.yml` contract gate.

Issue #59: nothing validated `.github/dependabot.yml`, and the adversarial
review of PR #58 proved it -- a `patterns:` -> `patternz:` typo under
`groups.svelte` survived actionlint, the release contract, the chart
four-way lock, and both secret scans (PR #58 review, mutants f/f2/g). This
suite mirrors `test_release_contract.py`'s style: the module is loaded
directly by file path so `python3 -I -B` (no site-packages, isolated) can
run it standalone, every case is a `unittest.TestCase` proving one specific
OUTCOME, and the exact PR #58 mutation is replayed against a temp copy of the
real, on-disk file, not just a synthetic fixture.

The suite is deliberately two-sided, and saying "every hostile input proves a
rejection" erased the half that matters most: of its 34 tests, 5 prove
ACCEPTANCE — the real on-disk config, the CLI's exit-0 path, both synthetic
fixtures, and the two official-ecosystem spot checks — and one more proves
both, re-validating the untouched real file after corrupting a temp copy of
it. Without those, a gate that rejected EVERYTHING would pass every rejection
test in here. That is precisely the vacuity AGENTS.md's review protocol asks
to be visible, so it is stated rather than implied.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("dependabot_contract", HERE / "dependabot_contract.py")
assert SPEC and SPEC.loader
DC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DC
SPEC.loader.exec_module(DC)

REAL_CONFIG_PATH = ROOT / ".github" / "dependabot.yml"


def minimal_document() -> str:
    """A two-entry synthetic document: github-actions and npm, both grouped.

    Not the real file's shape, and the difference matters when reading a
    mutation aimed at "the real config". `.github/dependabot.yml` declares
    TWO ecosystems — github-actions and gomod — and the gomod entry carries
    no `groups:` stanza at all. This fixture therefore never exercises an
    `updates[]` entry that legitimately lacks `groups`;
    `_validate_update_entry`'s `if "groups" in entry.entries:` branch is
    covered only through the real on-disk file. The npm entry here is a
    grammar fixture only: this repository has no Node and no npm.
    """
    return textwrap.dedent(
        """\
        version: 2
        updates:
          - package-ecosystem: github-actions
            directory: /
            schedule:
              interval: weekly
            open-pull-requests-limit: 5
            groups:
              codeql-action:
                patterns:
                  - "github/codeql-action*"
          - package-ecosystem: npm
            directory: /frontend
            schedule:
              interval: weekly
            open-pull-requests-limit: 3
            groups:
              svelte:
                patterns:
                  - "svelte"
                  - "svelte-check"
        """
    )


def single_update_document(ecosystem: str = "npm", *, interval: str = "daily") -> str:
    """A minimal one-entry document, for tests that don't need groups."""
    return textwrap.dedent(
        f"""\
        version: 2
        updates:
          - package-ecosystem: {ecosystem}
            directory: /
            schedule:
              interval: {interval}
        """
    )


def rich_document() -> str:
    """Exercises every optional field the minimal fixture leaves untouched:
    schedule.day/time/timezone, and groups.*.exclude-patterns/dependency-
    type/update-types/applies-to."""
    return textwrap.dedent(
        """\
        version: 2
        updates:
          - package-ecosystem: pip
            directory: /server
            schedule:
              interval: monthly
              day: monday
              time: "05:00"
              timezone: America/New_York
            groups:
              backend:
                patterns:
                  - "*"
                exclude-patterns:
                  - "legacy-*"
                dependency-type: production
                update-types:
                  - patch
                  - minor
                applies-to: version-updates
        """
    )


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"fixture drift: {old!r} appears {count} time(s), expected exactly 1")
    return text.replace(old, new, 1)


class RealConfigTests(unittest.TestCase):
    """The actual repository file, read from disk, is the primary oracle."""

    def test_the_real_repository_config_satisfies_the_contract(self):
        DC.validate_file(REAL_CONFIG_PATH)

    def test_corrupting_a_temp_copy_of_the_real_config_with_the_pr_58_mutation_turns_the_gate_red(self):
        # The sibling repository's PR #58 adversarial review recorded this
        # mutant -- `patterns:` -> `patternz:` under a group -- as SURVIVED
        # against every gate that existed at the time; this is the gate that
        # kills it. Here it lands on the real file's only group.
        original = REAL_CONFIG_PATH.read_text(encoding="utf-8")
        target = "      codeql-action:\n        patterns:\n"
        replacement = "      codeql-action:\n        patternz:\n"
        corrupted = replace_once(original, target, replacement)
        with tempfile.TemporaryDirectory() as tmp:
            copy_path = Path(tmp) / "dependabot.yml"
            copy_path.write_text(corrupted, encoding="utf-8")
            with self.assertRaises(DC.DependabotContractError) as caught:
                DC.validate_file(copy_path)
        self.assertIn("patternz", str(caught.exception))
        self.assertIn("groups.codeql-action", str(caught.exception))
        # The real file on disk was never touched by the mutation above.
        DC.validate_file(REAL_CONFIG_PATH)


class CLITests(unittest.TestCase):
    """The `python3 -I -B ... <path>` contract: exit 0 valid, exit 2 invalid."""

    @staticmethod
    def run_cli(path: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", "-B", str(HERE / "dependabot_contract.py"), str(path)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=30,
        )

    def test_cli_exits_zero_and_reports_ok_for_the_real_repository_config(self):
        completed = self.run_cli(REAL_CONFIG_PATH)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("OK:", completed.stdout)

    def test_cli_exits_two_and_denies_on_stderr_for_an_invalid_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "dependabot.yml"
            bad_path.write_text(replace_once(single_update_document(), "version: 2", "version: 1"), encoding="utf-8")
            completed = self.run_cli(bad_path)
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertIn("DENY:", completed.stderr)
        self.assertIn("version must be exactly 2", completed.stderr)

    def test_cli_exits_two_and_denies_for_non_utf8_bytes_instead_of_crashing(self):
        # PR #84 review finding 2: Path.read_text(encoding="utf-8") raises
        # UnicodeDecodeError -- a ValueError, not an OSError -- on invalid
        # bytes. Before the fix, validate_file caught only OSError, so this
        # propagated uncaught: a traceback and a bare non-zero exit (1),
        # with no DENY line. Reproduces the reviewer's exact fixture: a file
        # containing a lone 0xff byte, not valid UTF-8 anywhere.
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "dependabot.yml"
            bad_path.write_bytes(b"\xff")
            completed = self.run_cli(bad_path)
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertIn("DENY:", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)


class TopLevelTests(unittest.TestCase):
    def test_minimal_and_rich_fixtures_are_both_accepted(self):
        DC.validate_text(minimal_document())
        DC.validate_text(rich_document())

    def test_version_must_be_exactly_2(self):
        text = replace_once(minimal_document(), "version: 2", "version: 1")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("version must be exactly 2", str(caught.exception))

    def test_unknown_top_level_key_is_rejected(self):
        text = replace_once(minimal_document(), "version: 2\n", "version: 2\nenable-beta-ecosystems: true\n")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown key 'enable-beta-ecosystems'", str(caught.exception))

    def test_empty_updates_is_rejected(self):
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text("version: 2\nupdates:\n")
        self.assertIn("must be a non-empty list", str(caught.exception))

    def test_non_mapping_update_entry_is_rejected(self):
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text('version: 2\nupdates:\n  - "just-a-string"\n')
        self.assertIn("must be a mapping", str(caught.exception))

    def test_duplicate_key_within_an_entry_is_rejected(self):
        text = replace_once(
            minimal_document(),
            "  - package-ecosystem: github-actions\n    directory: /\n",
            "  - package-ecosystem: github-actions\n    package-ecosystem: npm\n    directory: /\n",
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("duplicate key 'package-ecosystem'", str(caught.exception))

    def test_tab_indentation_anywhere_is_rejected(self):
        text = replace_once(minimal_document(), "  - package-ecosystem: github-actions", "\t- package-ecosystem: github-actions")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("tab characters are not supported", str(caught.exception))

    def test_flow_style_list_is_rejected(self):
        text = replace_once(
            minimal_document(),
            '        patterns:\n          - "github/codeql-action*"\n',
            '        patterns: ["github/codeql-action*"]\n',
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("flow-style values", str(caught.exception))

    def test_comments_are_rejected(self):
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(single_update_document() + "  # a trailing comment\n")
        self.assertIn("comments are not supported", str(caught.exception))


class UpdateEntryTests(unittest.TestCase):
    def test_missing_schedule_is_rejected(self):
        text = replace_once(
            minimal_document(),
            "    directory: /\n    schedule:\n      interval: weekly\n",
            "    directory: /\n",
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("missing required key 'schedule'", str(caught.exception))

    def test_unknown_ecosystem_is_rejected_on_the_second_entry(self):
        # Mutates the SECOND updates[] entry, proving every item is
        # validated -- not just index 0.
        text = replace_once(minimal_document(), "package-ecosystem: npm", "package-ecosystem: bogus-ecosystem")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown package-ecosystem 'bogus-ecosystem'", str(caught.exception))

    def test_directory_must_start_with_a_slash(self):
        text = replace_once(single_update_document(), "directory: /", "directory: frontend")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("directory must start with '/'", str(caught.exception))

    def test_open_pull_requests_limit_must_be_a_non_negative_integer(self):
        text = replace_once(minimal_document(), "open-pull-requests-limit: 5", "open-pull-requests-limit: five")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("open-pull-requests-limit must be a non-negative integer", str(caught.exception))

    def test_unknown_key_on_an_update_entry_is_rejected(self):
        text = replace_once(single_update_document(), "directory: /\n", "directory: /\n    reviewers: someone\n")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown key 'reviewers'", str(caught.exception))

    def test_package_ecosystem_must_be_a_plain_scalar_not_a_nested_block(self):
        text = replace_once(
            single_update_document(),
            "package-ecosystem: npm\n",
            "package-ecosystem:\n      - npm\n",
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("must be a plain value", str(caught.exception))

    def test_official_ecosystem_spot_check_is_accepted(self):
        for ecosystem in ("docker", "pip", "cargo", "bundler", "gomod"):
            with self.subTest(ecosystem=ecosystem):
                DC.validate_text(single_update_document(ecosystem))

    def test_mix_is_accepted_as_the_documented_hex_elixir_ecosystem(self):
        # PR #84 review finding 1: `mix` (not `hex`) is the documented
        # package-ecosystem value for Hex/Elixir, per both the github/docs
        # supported-package-managers table and SchemaStore's
        # dependabot-2.0.json enum.
        DC.validate_text(single_update_document("mix"))

    def test_hex_is_rejected_it_is_not_a_documented_ecosystem_value(self):
        text = replace_once(single_update_document(), "package-ecosystem: npm", "package-ecosystem: hex")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown package-ecosystem 'hex'", str(caught.exception))


class ScheduleTests(unittest.TestCase):
    def test_interval_is_restricted_to_daily_weekly_monthly(self):
        for bad in ("quarterly", "yearly", "cron", "sometimes"):
            with self.subTest(interval=bad):
                text = replace_once(single_update_document(), "interval: daily", f"interval: {bad}")
                with self.assertRaises(DC.DependabotContractError) as caught:
                    DC.validate_text(text)
                self.assertIn("schedule.interval must be one of", str(caught.exception))

    def test_unknown_key_on_schedule_is_rejected(self):
        text = replace_once(single_update_document(), "interval: daily\n", "interval: daily\n      cron: nope\n")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown key 'cron'", str(caught.exception))

    def test_day_must_be_a_lowercase_weekday_name(self):
        text = replace_once(rich_document(), "day: monday", "day: Someday")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("schedule.day must be a lowercase weekday name", str(caught.exception))

    def test_time_must_be_24_hour_hh_mm(self):
        text = replace_once(rich_document(), '"05:00"', '"5:00"')
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("schedule.time must be 24-hour", str(caught.exception))

    def test_timezone_must_look_like_an_iana_zone(self):
        text = replace_once(rich_document(), "timezone: America/New_York", "timezone: nowhere fast")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("schedule.timezone must look like an IANA zone identifier", str(caught.exception))


class GroupsTests(unittest.TestCase):
    def test_malformed_groups_patterns_typo_is_rejected(self):
        # The exact PR #58 shape (mutant f), against a synthetic fixture.
        text = replace_once(
            minimal_document(),
            "      svelte:\n        patterns:\n",
            "      svelte:\n        patternz:\n",
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown key 'patternz'", str(caught.exception))
        self.assertIn("groups.svelte", str(caught.exception))

    def test_unknown_key_on_a_group_entry_is_rejected(self):
        text = replace_once(
            minimal_document(),
            '          - "github/codeql-action*"\n',
            '          - "github/codeql-action*"\n        ignore-me: true\n',
        )
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("unknown key 'ignore-me'", str(caught.exception))

    # Named for what it actually empties. The line removed is the sole item
    # under `exclude-patterns:`, not under `patterns:`, and the assertion
    # below names `groups.backend.exclude-patterns`. The sibling property —
    # that `groups.*.patterns` must itself be a non-empty list — has no test
    # in this suite; that gap is real and was hidden by this test's old name.
    def test_exclude_patterns_must_be_a_non_empty_list(self):
        text = replace_once(rich_document(), '          - "legacy-*"\n', "")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("groups.backend.exclude-patterns must be a non-empty list", str(caught.exception))

    def test_dependency_type_must_be_development_or_production(self):
        text = replace_once(rich_document(), "dependency-type: production", "dependency-type: staging")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("dependency-type must be one of", str(caught.exception))

    def test_update_types_items_are_restricted_to_major_minor_patch(self):
        text = replace_once(rich_document(), "- patch\n", "- hotfix\n")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("update-types item must be one of", str(caught.exception))

    def test_applies_to_is_restricted_to_the_two_documented_targets(self):
        text = replace_once(rich_document(), "applies-to: version-updates", "applies-to: performance-updates")
        with self.assertRaises(DC.DependabotContractError) as caught:
            DC.validate_text(text)
        self.assertIn("applies-to must be one of", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
