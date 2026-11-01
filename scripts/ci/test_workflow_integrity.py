"""Narrow refusals in `.github/workflows/` -- and deliberately no step
inventory.

WHAT THIS REFUSES. Each of the first three rules names ONE construct that
silently changes what a gate means, rather than one that merely changes what a
gate does; the fourth refuses a workflow and the contract describing it
disagreeing about the same number:

  1. `continue-on-error: true` on a job or step in the required-checks set.
     It converts a red gate into a green one with no other visible change. The
     release publisher authorizes against `pr-gate.yml`'s exact job inventory
     and CodeQL's exact run/job inventory, and both read a CONCLUSION. A job
     that fails but is told to continue still reports `success`, so this one
     key is the difference between "the gate passed" and "the gate ran".

  2. An `env:` key that SHADOWS an outer declaration of the same key, or that
     redeclares a tool pin `install-tools.sh` owns -- at EVERY scope a step's
     environment comes from, not only the innermost. Scope precedence means the
     inner declaration wins silently, so a step can run against a different
     value than the one every reader sees declared above it -- while the outer
     declaration still reads correct. `GO_COVERAGE_FLOOR` and `SOURCE_SHA` are
     the sharp cases: a shadowed floor passes any coverage, and a shadowed
     source SHA lets a step act on a commit other than the authorized one.

  3. A custom `shell:` on a step in the required-checks set, or a
     `defaults.run.shell` at job or workflow level, which is the same construct
     written where no step carries it and reshells EVERY `run:` step beneath
     it. The runner default for `run:` on Linux is `bash -e {0}`, and this
     repository's convention is to open every `run: |` block with
     `set -euo pipefail`. A custom shell changes failure semantics underneath
     that convention -- `shell: sh` drops `pipefail` support entirely, so a
     failing command mid-pipeline stops being a failing step.

  4. A `GO_COVERAGE_FLOOR` the contract states differently from the value a
     workflow enforces (issue #225). Requirement 7 calls the floor "ONE fact
     recorded in three places" and nothing read both files, so the two could
     drift silently and in either direction: raise the gate alone and AGENTS.md
     understates what CI permits; lower it alone and AGENTS.md promises a
     guarantee CI no longer makes. The number is found by SEARCH on both sides
     -- every `env:` scope of every workflow, and every AGENTS.md paragraph
     naming the variable next to a number -- so a new legitimate sentence
     widens what is read rather than failing for being new.

EVERY SCOPE, NOT THE FIRST ONE SOMEBODY THOUGHT OF. Three of the four review
rounds on this file found the same defect in a different rule: the rule's own
construct written at a SCOPE the rule does not read, passing at `actionlint`
rc=0 on a real workflow. Round 3 found it for rule 3 (`defaults.run.shell` at
job and workflow level, where no step carries it); round 4 found it for rule 2
(a job- or workflow-level `env:`, where no step carries it). So the scope set
of each rule is written down here, audited against GitHub's workflow syntax
rather than against what this repository happens to write, and each rule reads
ALL of its own:

  rule 1  `jobs.<id>.continue-on-error` and `jobs.<id>.steps[*].continue-on-
          error`. Those are the only two positions the key exists in; there is
          no `defaults.continue-on-error` and no workflow-level one.
  rule 2  four positions supply a step's environment, outermost first:
          `jobs.<id>.container.env` (a job container's own environment, which
          every `run:` step in the job inherits), the workflow-level `env:`,
          `jobs.<id>.env`, and `jobs.<id>.steps[*].env`. NOT in the set, and
          deliberately: `jobs.<id>.services.<id>.env` sets the environment of a
          SERVICE container, which is a different container from the one steps
          run in, so no step ever reads it.
  rule 3  `jobs.<id>.steps[*].shell`, `jobs.<id>.defaults.run.shell`, and the
          workflow-level `defaults.run.shell`.

One boundary is worth stating because most of this gate does NOT cover it: a
composite action (`action.yml` or `action.yaml`) has its own `runs.steps[*]`
carrying `shell:` and `continue-on-error:`. Rules 1-3 remain workflow rules,
and this repository ships no composite action today. A repository that adds one
is adding a surface rules 1-3 do not read -- extend those rules then, rather
than assuming they are covered.

The CodeQL lockstep rule is deliberately not bounded that way. It starts at
both workflow extensions and FOLLOWS every same-repository `uses: ./dir`
reference into the action it executes, transitively, because the executable
namespace is what GitHub can run and not a directory convention: the 0.1.65
reviews got past a workflows-only sweep with a wrapper under
`.github/actions`, and then past that sweep by moving the same wrapper one
directory outside it, each time leaving a version-matched direct call behind
as an unreachable decoy. Reachability is the reason a third path does not
exist to find.

WHAT THIS DELIBERATELY DOES NOT DO -- READ THIS BEFORE "COMPLETING" IT.

There is no closed step inventory here. This gate will never assert "the chart
job has exactly these N steps", "the workflows declare exactly these job
names", or "these are all the env keys". That pin is tempting because it looks
thorough, and it is precisely the failure mode this gate was written to avoid:
an exhaustive-inventory assertion breaks on every legitimate addition, so it
burns a release cycle per discovery, teaches whoever hits it to update the pin
rather than think about the change, and converts a security control into a
chore. A validator in the sibling platform lane pinned a pristine object shape
and spent six releases, six owner merges and six cluster slots learning -- one
per cycle -- that Flux writes ownership labels, Calico writes pod annotations,
and the Deployment controller writes `pod-template-hash`. Every one of those
refusals was individually correct and collectively a waste.

So: pin BEHAVIOUR, not inventory. Refuse a specific dangerous construct;
never assert that the complete set of anything is exactly X, when normal
evolution extends it. Adding a step, a job, or an env key must need no edit
here. If you are about to add an inventory assertion to this file, add a rule
that refuses a construct instead -- and give it a lift path.

The one thing this file DOES enumerate is derived, not maintained: the
required-checks set comes from `EXPECTED_MAIN_JOBS` and `EXPECTED_CODEQL_JOBS`
in `release_contract.py`, which the release contract already keeps exact
because the publisher authorizes against them. Reading them here adds no
second copy to keep in sync.

LIFTING IT, AND THE ONE CLASS THAT DOES NOT LIFT. There are two kinds of red
here and they have different remedies. Saying otherwise -- as an earlier
revision of this docstring and of the allowlist header both did -- sends
whoever hits the second kind to a file that will not help them.

A RULE refusal lifts through `scripts/ci/workflow-integrity-allowlist.txt`:
one line, one written reason, one PR. Every rule prints the exact line to
paste. Steps are located by NAME, not index, so an entry survives a step being
inserted above it. Four subjects address the positions no step name can:
`<defaults.run.shell>` and `<job>/<defaults.run.shell>` for rule 3's two
default-shell positions, and `<workflow.env>/<KEY>`, `<job>/<job.env>/<KEY>`
and `<job>/<container.env>/<KEY>` for rule 2's three non-step scopes.

A READER refusal does NOT lift, by design, and prints no lift line. It is
raised while resolving the file, before any rule consults the allowlist -- and
that ordering is the correct behaviour rather than an accident of structure.
An allowlist entry waives a RULE's verdict about a value this reader resolved;
when nothing resolved there is no verdict to waive, and silencing a construct
nobody can say the meaning of is exactly the silent pass this reader was
inverted to remove. It would also have to name its subject by line or by raw
text, since the resolved subject is precisely what is missing -- the brittle
inventory pin this file refuses to become. The remedies are, in order: write
the construct in block style, or the value in a spelling this reader resolves
(quoting a scalar usually does it -- `shell: "bash -e {0}"` resolves and lifts,
while the same value unquoted is refused); and, when a construct is genuinely
needed and genuinely unresolvable, widen `resolve_scalar`'s recognised set in
one reviewed edit HERE, which this suite then gates like any other change.
`test_a_reader_refusal_is_not_liftable_by_the_allowlist` pins both directions,
so this paragraph cannot drift away from the code again.

PARSING. `python3 -I` runs isolated with no site-packages, so there is no
`yaml` module; `dependabot_contract.py`'s parser is deliberately conservative
and refuses comments, which every workflow here has. This file therefore
carries a small structural reader that understands exactly what these rules
need: indentation, block scalars, and comments. It fails CLOSED -- anything it
cannot resolve, structure or value, fails the suite rather than passing
quietly, which is the only safe direction for a reader a gate depends on. The
next section is that boundary, and it is the most important part of this file.

THE READER'S BOUNDARY -- the part that bites, so do not re-derive it by hand.
A reader that SKIPS what it does not understand is worse than no reader: the
skipped construct is invisible to every rule, so the gate reports green on
precisely the thing it exists to refuse, while looking strict to a reviewer.

THE DEFAULT IS THE DEFECT, AND IT IS INVERTED HERE. Three successive 0.1.49
reviews each found "another valid form evades the reader", and each repair
that ADDED a form was overtaken by the next one:

  round 1 -- a step written `- {name: x}` was skipped as unparseable;
  round 2 -- six step SHAPES (a bare `-`, a sequence level with its own
             `steps:` key, a wider gap after the dash, ...) located no step;
  round 3 -- four `continue-on-error` VALUE forms -- the scalar on the next
             line, and `!!bool true`, at job and step level -- resolved to
             text that simply was not `true`, so the rule returned without
             refusing. Every one passed `actionlint` at rc=0.

That sequence does not end by enumerating forms, because a hand-rolled YAML
subset that recognises the spellings somebody thought of and treats everything
else as "not a match" leaks BY CONSTRUCTION. This repository cannot take a
PyYAML dependency (`python3 -I` runs with no site-packages, and requirement 9
keeps the Go module stdlib-only for the same reason), so the answer is not a
real parser -- it is fail-closed resolution:

  **the reader resolves a small, explicit set of forms, and REFUSES
  everything else, in every position a rule reads.**

Refusing is not a fallback here; it is the default, and recognition is the
exception. The test of whether that holds: a brand-new exotic-but-valid way of
writing `true` must turn the gate RED with no edit to this file.
`test_an_unrecognised_way_of_writing_true_is_refused` is that test, and
`UNRECOGNISED_TRUE_SPELLINGS` is a table of twelve rows none of which has a
branch anywhere in this module.

WHAT THE READER RESOLVES -- structure. Differential-tested against a real YAML
parser; `test_the_reader_resolves_every_step_shape_a_real_parser_accepts` is
the executable copy, so extending one means extending the other:

  - `- name: x` -- the canonical item, and the only shape this repository
    actually writes today.
  - `-` alone with the step's keys on the following lines, at any deeper
    indent. Valid YAML, `actionlint` rc=0, and the runner executes it.
  - a sequence indented LEVEL with its own `steps:` key rather than deeper.
    This is the more common style in the wild; that no workflow here uses it
    is a habit, not a boundary.
  - a wider gap after the dash (`-   name: x`): the step's property column is
    derived from where its first key actually sits, never a fixed `+ 2`.
  - a comment between the dash and the first key.
  - quoted keys (`"name": x`).
  - block scalars in every spelling (`|`, `>`, `|-`, `|2`, `|2-`): their
    bodies are skipped whole, so shell text that merely LOOKS like `shell:` or
    `env:` is never mistaken for structure.

WHAT THE READER RESOLVES -- values, which is the narrower and stricter half.
`resolve_scalar` accepts exactly three spellings and `resolve_boolean` narrows
that further:

  - nothing at all on the key's line AND nothing nested under it: YAML null.
    (Nothing on the line WITH something nested under it is refused -- that is
    round 3's evasion, and the two cases are indistinguishable to a reader
    that only looks at the same line.)
  - `'text'` with no `''` escape, and `"text"` with no backslash escape; the
    quotes are stripped, the way a real parser strips them.
  - a plain scalar of `[A-Za-z0-9_][A-Za-z0-9_./+-]*`, which cannot begin with
    a YAML indicator and cannot contain a tag, a flow marker, or a `${{ }}`.
  - for `continue-on-error` only: that resolved text must then be `true` or
    `false` in any casing. `yes`, `on`, `1`, `!!str true` and a folded scalar
    are REFUSED rather than compared, even though `actionlint` rejects some of
    them -- a fail-closed reader that depends on another tool catching what it
    waves through is not fail-closed.

Rule 1 is therefore TOTAL: every input either raises or resolves to one of two
booleans, so there is no third outcome for a spelling to hide in.

REFUSED, LOUDLY, with a message naming the construct (see
`_refuse_unresolvable`): flow mappings and flow sequences in any position a
rule depends on (`- {name: x}`, `steps: [...]`, `env: {...}`), YAML anchors,
aliases and tags, merge keys (`<<:`), explicit keys (`? k` / `: v`), a row in
an `env:` or `container:` mapping this reader cannot name, a job that declares
`steps:` and resolves none, and multi-document files. Each raises rather than
returning a partial answer -- a partial answer is the silent pass. None of
these appears in any workflow here, and GitHub Actions accepts block style
everywhere, so the refusal costs nothing and closes the whole class at once.

ONE SHORTHAND IS RECOGNISED RATHER THAN REFUSED, and the reason is the one
above about lifting: `container:` takes a scalar image reference
(`ubuntu:24.04`) or an expression naming one, neither of which can carry a
mapping and therefore neither of which can hide an `env:`. Refusing them would
be a false red with NO lift path, so they are matched positively
(`IMAGE_REFERENCE`, `EXPRESSION`) and anything else on that line is refused.
Where a reader refusal is un-liftable, the boundary has to be drawn with more
care than "anything unfamiliar", not less.

THE ONE VALUE DELIBERATELY OUTSIDE THAT BOUNDARY is a step's `name:`, which is
free text (`Test hostile contract suites (release, dependabot)`) and is not
compared by any rule -- it is only the allowlist SUBJECT. Mis-resolving a name
fails closed on its own: the `<where>` an entry names then does not match, so
the refusal stands rather than being lifted.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = GITHUB / "workflows"
INSTALL_TOOLS = HERE / "install-tools.sh"
ALLOWLIST = HERE / "workflow-integrity-allowlist.txt"
AGENTS = ROOT / "AGENTS.md"

# Issue #225. Requirement 7 calls the Go coverage floor "ONE fact recorded in
# three places" -- this workflow variable and two sentences in AGENTS.md -- and
# nothing read both, so the two could drift apart silently and in either
# direction: a raised gate leaves the contract overstating what CI permits, a
# lowered one leaves it promising a guarantee CI no longer makes.
COVERAGE_FLOOR_KEY = "GO_COVERAGE_FLOOR"
# A number stated NEXT TO the variable's own name, in the same paragraph, is a
# claim about the floor. Deliberately a search rather than an inventory of
# permitted locations: a new legitimate sentence about the floor widens what
# this reads, and cannot fail the gate merely for being new.
_FLOOR_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
CODEQL_ACTION_REFERENCE = re.compile(
    r"^github/codeql-action/(init|analyze)@([0-9a-f]{40})$", re.IGNORECASE
)
CODEQL_VERSION_COMMENT = re.compile(r"\s+#\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*$")

SPEC = importlib.util.spec_from_file_location("release_contract", HERE / "release_contract.py")
assert SPEC and SPEC.loader
RC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RC
SPEC.loader.exec_module(RC)

RULES = ("continue-on-error", "env-shadow", "custom-shell", "contract-floor")
BLOCK_SCALAR = re.compile(r":\s*[|>][+-]?\d*\s*$")

# THE RESOLUTION BOUNDARY, stated as what the reader UNDERSTANDS.
#
# These three patterns are the complete set of scalar spellings this reader
# claims to resolve for a value a rule compares. They are deliberately written
# as a positive recognition rather than a list of forbidden characters, because
# the 0.1.49 review found three rounds of "another valid spelling evades the
# reader" and a blocklist loses that game by construction: the previous
# revision refused `^[\[{&*]` and was beaten by `!!bool true`, by an empty
# same-line value with the scalar on the next line, and by `${{ true }}`.
# Anything not matched here RAISES, so a spelling nobody anticipated is a red
# gate rather than a silent pass, with no code change needed to catch it.
PLAIN_SCALAR = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./+-]*$")
SINGLE_QUOTED = re.compile(r"^'[^'\\]*'$")
DOUBLE_QUOTED = re.compile(r'^"[^"\\]*"$')

# A `uses:` value is a REFERENCE, not a scalar any rule compares: it needs `@`,
# `:` and a leading `.`, which `PLAIN_SCALAR` excludes on purpose. Same
# fail-closed default -- recognised spellings only, everything else RAISES --
# with the character set this one position actually needs.
USES_REFERENCE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./@:+-]*$")

# `container:` carries a scalar SHORTHAND whose value is an image reference
# (`ubuntu:24.04`, `ghcr.io/owner/image@sha256:...`), or an expression naming
# one. `PLAIN_SCALAR` deliberately admits neither -- it forbids `:`, `@` and
# `$` -- so the shorthand needs its own positive recognition. It gets one
# rather than being refused, because a reader refusal cannot be lifted through
# the allowlist: a false red in this position would be a wall, not a line of
# paperwork. Neither form can carry a mapping, so neither can hide an `env:`.
IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./+:@-]*$")
EXPRESSION = re.compile(r"^\$\{\{[^{}]*\}\}$")

# Rule 1's value is boolean-typed, so its recognised set is smaller still: the
# two spellings `actionlint` itself accepts, case-insensitively, plus YAML null
# for a bare key. `yes`, `on`, `1`, `!!str true` and a folded scalar all resolve
# TRUTHY or STRING-"true" in a real parser and are refused here rather than
# compared -- which is what makes rule 1 total. See `resolve_boolean`.
BOOLEAN_SPELLINGS = {"true": True, "false": False}

MERGE_KEY = re.compile(r"^<<\s*:")
DOCUMENT_SEPARATOR = "---"
DOCUMENT_END = "..."

# `defaults.run.shell` sets the shell for every `run:` step beneath it, at
# workflow or job level, and is rule 3's construct written somewhere no step
# carries it. It needs an allowlist subject that cannot collide with a step
# name, hence the angle brackets: a step named this would have to be written
# `- name: <defaults.run.shell>`, which `actionlint` accepts but which is then
# exempted by the same line either way -- the subject is the construct, and
# both spellings of it are the thing being waived.
DEFAULT_SHELL_SUBJECT = "<defaults.run.shell>"

# Rule 2's three non-step scopes need the same treatment for the same reason:
# a workflow-level, job-level or container-level `env:` key is not written
# inside any step, so `<job>/<step>/<KEY>` cannot address it. The subjects are
# `<workflow.env>/<KEY>`, `<job>/<job.env>/<KEY>` and
# `<job>/<container.env>/<KEY>`. A step would have to be named literally
# `<job.env>` to collide, and the same line then exempts either reading -- the
# subject IS the construct, exactly as for the default-shell subject above.
WORKFLOW_ENV_SUBJECT = "<workflow.env>"
JOB_ENV_SUBJECT = "<job.env>"
CONTAINER_ENV_SUBJECT = "<container.env>"


# --------------------------------------------------------------------------
# A small structural reader for GitHub workflow YAML
# --------------------------------------------------------------------------


# A key's value together with the line it was declared on. Every rule below
# reports the line of the OFFENDING KEY, never the line of the job or step
# that contains it: a message that points at `chart:` when the problem is a
# `continue-on-error:` three lines below sends the next agent to the wrong
# place, and "exactly what to fix and where" is the whole point of the
# message.
Keyed = tuple[str, int]
# Rule 1 compares a BOOLEAN, never text. Resolution happens once, in the
# reader, where an unrecognised spelling can still raise; by the time a value
# reaches the rule there is nothing left to normalise and therefore nothing
# left to normalise WRONG.
KeyedBool = tuple[bool, int]


@dataclass
class Step:
    name: str
    line: int
    shell: Keyed | None = None
    continue_on_error: KeyedBool | None = None
    env: dict[str, int] = field(default_factory=dict)


@dataclass
class Job:
    name: str
    line: int
    continue_on_error: KeyedBool | None = None
    default_shell: Keyed | None = None
    env: dict[str, int] = field(default_factory=dict)
    # A job container's own environment. Every `run:` step in the job inherits
    # it, so it is a rule-2 scope -- the OUTERMOST one, because the runner
    # passes the workflow/job/step `env:` explicitly when it execs each step
    # and those therefore win over it. Empty for the ordinary runner-hosted
    # job, which is every job in this repository today.
    container_env: dict[str, int] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    # Whether the job declared a `steps:` key at all. A reusable-workflow job
    # (`uses:` at job level) legitimately has none, so "every job has steps" is
    # a false pin; "every job that SAYS it has steps resolved some" is not.
    declares_steps: bool = False


@dataclass
class Workflow:
    path: Path
    env: dict[str, int] = field(default_factory=dict)
    default_shell: Keyed | None = None
    jobs: dict[str, Job] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.path.name


def _strip_comment(line: str) -> str:
    """Cut an unquoted `#` comment. Quote state is tracked per line."""
    single = double = False
    for index, char in enumerate(line):
        if char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
        elif char == "#" and not single and not double and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def structural_lines(text: str) -> list[tuple[int, int, str]]:
    """Return (lineno, indent, content) for lines that carry YAML structure.

    Block-scalar bodies -- everything under a `run: |` -- are skipped whole.
    That is load-bearing rather than tidy: those bodies are shell scripts full
    of `#` comments and lines that look like `env:` or `shell:` keys, and
    parsing them as structure would invent constructs that do not exist.
    """
    out: list[tuple[int, int, str]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        index += 1
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped.strip()
        out.append((index, indent, content))
        if BLOCK_SCALAR.search(stripped):
            # Consume the body: every following blank line, or line indented
            # deeper than the key that opened it.
            while index < len(lines):
                body = lines[index]
                if body.strip() and (len(body) - len(body.lstrip(" "))) <= indent:
                    break
                index += 1
    return out


KEY = re.compile(
    r"""^(?:"([A-Za-z_][\w.-]*)"|'([A-Za-z_][\w.-]*)'|([A-Za-z_][\w.-]*))\s*:\s*(.*)$"""
)


def _key(content: str) -> tuple[str, str] | None:
    """Split `key: value` into (key, value); None when the line is not a key.

    Quoted key spellings (`"name":`, `'shell':`) resolve to the same name a
    real parser gives them. An unquoted-only reader saw `"shell": sh` as a
    non-key and dropped the step's shell silently.
    """
    match = KEY.match(content)
    if not match:
        return None
    return (match.group(1) or match.group(2) or match.group(3)), match.group(4).strip()


def _display(path: Path) -> str:
    """Repository-relative where that is meaningful, absolute otherwise.

    The hostile suites below build whole mutant repositories under a temporary
    directory, and those paths are not under `ROOT`; a bare `relative_to` there
    raises `ValueError` from inside the refusal it was formatting, which reads
    as a broken test rather than the refusal that actually fired.
    """
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _refuse_unresolvable(path: Path, lineno: int, construct: str, detail: str) -> NoReturn:
    """Fail the suite on a construct the reader cannot resolve.

    The alternative -- skipping it -- is what the 0.1.49 review caught: an
    unresolved step is invisible to all three rules, so the gate passes on the
    exact construct it exists to refuse while still reading as strict. Refusing
    is the only safe direction for a reader a gate depends on.

    Declared `NoReturn` on purpose: every call site is a dead end, so a type
    checker proves no caller can fall through one and carry on with an
    unresolved value -- the exact bug this function exists to prevent.

    The message states plainly that this refusal is NOT liftable through the
    allowlist, because it is not: this raises while the file is being resolved,
    before any rule consults `self.allowlist`, and that ordering is deliberate
    (see the module docstring's LIFTING IT section). An earlier revision of
    that docstring, of the allowlist header, and of this message all implied
    otherwise, which sent a reader to a file that cannot help.
    """
    raise AssertionError(
        f"{_display(path)}:{lineno}: the structural reader cannot resolve "
        f"{construct}. {detail} This reader is BLOCK-style only, and it refuses "
        f"what it cannot resolve rather than skipping it: a skipped construct is "
        f"invisible to every rule in this file, which is a silent pass on exactly "
        f"what the rule refuses.\n\nThis refusal is NOT liftable through "
        f"{ALLOWLIST.relative_to(ROOT).as_posix()}, and no lift line is printed "
        f"for it: that file waives a RULE's verdict about a value this reader "
        f"resolved, and there is no verdict to waive when nothing resolved. "
        f"Rewrite the construct in block style -- GitHub Actions accepts that "
        f"form in every one of these positions -- or the value in a spelling "
        f"this reader resolves; quoting a scalar usually does it. If the "
        f"construct is genuinely needed and genuinely unresolvable, widen "
        f"`resolve_scalar`'s recognised set in one reviewed edit to this file."
    )


def _is_item(content: str) -> bool:
    """A block-sequence item: `- value`, or a bare `-` carrying its body below."""
    return content == "-" or content.startswith("- ")


def _has_body(rows: list[tuple[int, int, str]], position: int, column: int) -> bool:
    """Whether the key at `rows[position]` carries its value on FOLLOWING lines.

    Only the very next structural row can begin a nested node, so one lookahead
    is the whole question. An empty same-line value therefore means one of two
    completely different things -- YAML null, or a scalar/collection below --
    and comparing the empty string for both is how `continue-on-error:` with
    `true` on the next line read as "not true" and passed.
    """
    for _, indent, _ in rows[position + 1 :]:
        return indent > column
    return False


def resolve_scalar(
    rows: list[tuple[int, int, str]],
    position: int,
    column: int,
    value: str,
    path: Path,
    lineno: int,
    where: str,
) -> str:
    """Resolve a scalar a rule compares, or REFUSE. Never returns a guess.

    This is the value-level half of the fail-closed contract, and it is written
    as an ALLOWLIST of spellings on purpose. The 0.1.49 reviews found, in three
    successive rounds, that a reader which recognises "the ways of writing X I
    thought of" and treats everything else as "not X" leaks by construction:
    the leak is not any particular spelling, it is the default. Inverting the
    default is the repair -- an unrecognised form raises, so a spelling nobody
    anticipated turns the gate RED with no edit to this file.

    Recognised, and nothing else:

      - an absent same-line value with NO nested row under the key: YAML null,
        the only empty form this reader accepts;
      - `'text'` with no `''` escape, and `"text"` with no backslash escape;
      - a plain scalar of `PLAIN_SCALAR`'s characters, which cannot begin with
        any YAML indicator and cannot contain a tag, a flow marker, or a `${{`
        expression.

    Everything else -- `!!bool true`, `${{ true }}`, `>-` with the text below,
    `"tr\\u0075e"`, an anchor, an alias, a flow node, a multi-word plain scalar
    -- raises. The cost is one allowlist line for a legitimate exotic value,
    and no workflow in this repository writes one.
    """
    if not value:
        if _has_body(rows, position, column):
            _refuse_unresolvable(
                path, lineno, f"{where}, whose value is not on the same line",
                "The reader cannot tell a nested scalar from a nested collection "
                "here, and reading the empty same-line text as the value compares "
                "`\"\"` against a scalar a real parser resolves -- which is the "
                "silent pass. Write the value on the key's own line.",
            )
        return ""
    if SINGLE_QUOTED.match(value) or DOUBLE_QUOTED.match(value):
        return value[1:-1]
    if PLAIN_SCALAR.match(value):
        return value
    _refuse_unresolvable(
        path, lineno, f"{where}, written as `{value}`",
        "That is not one of the scalar spellings this reader resolves (a plain "
        "token, a quoted string without escapes, or nothing at all). It is "
        "refused rather than compared, because comparing text this reader did "
        "not resolve is how a value a real parser reads as `true` passes as "
        "`not true`.",
    )


def resolve_boolean(
    rows: list[tuple[int, int, str]],
    position: int,
    column: int,
    value: str,
    path: Path,
    lineno: int,
    where: str,
) -> bool:
    """Resolve a boolean-typed value, or REFUSE. Rule 1's whole normalisation.

    Total by construction: every input either resolves to one of exactly two
    booleans or raises. There is no third outcome and therefore no "some other
    spelling of true" to discover -- `yes`, `on`, `y`, `1`, `!!str true`, a
    folded scalar and a `${{ }}` expression are all REFUSED rather than
    silently compared as not-`true`, even though `actionlint` rejects some of
    them for us. Depending on another tool to catch what this one waves through
    is exactly the coupling a fail-closed reader must not have.

    A bare `continue-on-error:` with nothing under it is YAML null, which is
    falsy in every parser and in the runner; it resolves `False` rather than
    raising, so a legitimate null is not false-reddened.
    """
    text = resolve_scalar(rows, position, column, value, path, lineno, where)
    if not text:
        return False
    resolved = BOOLEAN_SPELLINGS.get(text.lower())
    if resolved is None:
        _refuse_unresolvable(
            path, lineno, f"{where}, written as `{value}`",
            f"A boolean here is `true` or `false` in any casing and nothing else. "
            f"{text!r} may well resolve truthy in a real YAML parser -- `yes`, "
            f"`on` and `1` all do -- so it is refused rather than compared, "
            f"because comparing it would pass it.",
        )
    return resolved


def _item_indent(rows: list[tuple[int, int, str]], at: int, parent_indent: int) -> int | None:
    """Indent of the block sequence under `rows[at]`, or None when there is none.

    YAML lets a sequence sit at the SAME indent as the key that owns it, and
    that is the commoner style in the wild; every workflow here happens to use
    the deeper one. Deriving the indent from the first item reads both, so
    "the style we happen to write" stops being a boundary of what the gate sees.
    """
    for _, indent, content in rows[at + 1 :]:
        if indent < parent_indent or not _is_item(content):
            return None
        return indent
    return None


def _first_deeper_indent(rows: list[tuple[int, int, str]], position: int, floor: int) -> int:
    """The indent of the row nested under `rows[position]`, for a bare `-` item."""
    for _, indent, _ in rows[position + 1 :]:
        if indent > floor:
            return indent
        break
    return floor + 2


def _mapping_keys(
    rows: list[tuple[int, int, str]], start: int, indent: int, path: Path, where: str
) -> dict[str, int]:
    """Collect `key: value` names declared at exactly `indent`, from `start`.

    Rule 2 reads these NAMES, so a row at the mapping's own column that this
    reader cannot read as a key is not a curiosity -- it is a declaration the
    rule will never see. Skipping it hid three real shapes on the real
    `pr-gate.yml`, all of them resolved by a real parser: an explicit key
    (`? GO_COVERAGE_FLOOR` / `: '0'`, which `actionlint` accepts at rc=0 and
    which shadows the coverage floor invisibly), a merge key pulling an entire
    mapping in by alias, and a key spelling `KEY` does not match. Refusing is
    the same inversion the value layer applies: understand it, or say so.
    """
    keys: dict[str, int] = {}
    for lineno, row_indent, content in rows[start:]:
        if row_indent < indent:
            break
        if row_indent != indent:
            continue
        parsed = _key(content)
        if not parsed:
            _refuse_unresolvable(
                path, lineno, f"the entry `{content}` in {where}",
                "Every entry of a mapping rule 2 reads must be a plain `KEY: value` "
                "line. An entry this reader cannot name is a declaration the rule "
                "cannot see, so it could shadow an outer pin unnoticed.",
            )
        keys[parsed[0]] = lineno
    return keys


def _read_default_shell(
    rows: list[tuple[int, int, str]], defaults_at: int, path: Path, where: str
) -> Keyed | None:
    """Resolve `defaults: run: shell:`, rule 3's construct written above a step.

    `defaults.run.shell` at workflow or job level replaces the runner default
    for EVERY `run:` step beneath it. It is exactly what rule 3 refuses on a
    step, spelled somewhere no step carries it -- and it was invisible: both
    positions pass `actionlint` at rc=0 and left the suite green.
    """
    run_indent = _child_indent(rows, defaults_at)
    for run_at, (lineno, indent, content) in enumerate(
        rows[defaults_at + 1 :], start=defaults_at + 1
    ):
        if indent < run_indent:
            break
        if indent != run_indent:
            continue
        parsed = _key(content)
        if not parsed:
            _refuse_unresolvable(
                path, lineno, f"the entry `{content}` in the `defaults:` of {where}",
                "A `defaults:` block this reader cannot read as a mapping could "
                "carry a `run.shell` that silently reshells every step below it.",
            )
        if parsed[0] != "run":
            continue
        if parsed[1]:
            _refuse_unresolvable(
                path, lineno, f"the inline `defaults.run:` of {where}",
                "An inline or aliased `run:` mapping resolves to no shell here, so "
                "a default shell it declares would evade rule 3.",
            )
        shell_indent = _child_indent(rows, run_at)
        for shell_at, (shell_line, shell_row_indent, shell_content) in enumerate(
            rows[run_at + 1 :], start=run_at + 1
        ):
            if shell_row_indent < shell_indent:
                break
            if shell_row_indent != shell_indent:
                continue
            shell_parsed = _key(shell_content)
            if not shell_parsed:
                _refuse_unresolvable(
                    path, shell_line,
                    f"the entry `{shell_content}` in the `defaults.run:` of {where}",
                    "It could be the `shell:` key rule 3 refuses.",
                )
            if shell_parsed[0] == "shell":
                return (
                    resolve_scalar(
                        rows, shell_at, shell_indent, shell_parsed[1], path, shell_line,
                        f"the `defaults.run.shell:` of {where}",
                    ),
                    shell_line,
                )
    return None


def _read_container_env(
    rows: list[tuple[int, int, str]],
    container_at: int,
    value: str,
    path: Path,
    lineno: int,
    where: str,
) -> dict[str, int]:
    """Resolve `container: … env:`, rule 2's construct at its outermost scope.

    A job container's environment is inherited by every `run:` step in the job,
    so a name declared here reaches the same shell that reads a tool pin. It is
    the OUTERMOST source rather than the innermost: the runner passes the
    workflow-, job- and step-level `env:` explicitly when it execs each step,
    so those win over the container's own. That is why rule 2 compares this
    scope as an outer declaration and never as a shadow of one.

    The scalar shorthand (`container: ubuntu:24.04`) carries no mapping and
    therefore no `env:`, and it must NOT be refused -- a reader refusal cannot
    be lifted, so a false red here would be a wall rather than a line of
    paperwork. It is recognised positively, as an image reference or a
    whole-value expression. Anything else on that line is a flow mapping, an
    alias or an anchor, each of which CAN carry an `env:` this reader would
    never see, and is refused.
    """
    if value:
        if IMAGE_REFERENCE.match(value) or EXPRESSION.match(value):
            return {}
        _refuse_unresolvable(
            path, lineno, f"the `container:` of {where}, written as `{value}`",
            "A same-line `container:` value is an image reference or an expression "
            "naming one, and neither carries a mapping. A flow mapping, an alias or "
            "an anchor here can carry an `env:` whose keys rule 2 would never see.",
        )
    env_indent = _child_indent(rows, container_at)
    for position, (row_line, indent, content) in enumerate(
        rows[container_at + 1 :], start=container_at + 1
    ):
        if indent < env_indent:
            break
        if indent != env_indent:
            continue
        parsed = _key(content)
        if not parsed:
            _refuse_unresolvable(
                path, row_line, f"the entry `{content}` in the `container:` of {where}",
                "A `container:` block this reader cannot read as a mapping could "
                "carry an `env:` whose keys rule 2 would never see.",
            )
        if parsed[0] != "env":
            continue
        if parsed[1]:
            _refuse_unresolvable(
                path, row_line, f"the inline `container.env:` of {where}",
                "Rule 2 reads this mapping's KEYS; an unresolved one reads as no "
                "declaration at all, so nothing it declares can be compared.",
            )
        return _mapping_keys(
            rows, position + 1, _child_indent(rows, position), path,
            f"the `container.env:` of {where}",
        )
    return {}


def read_workflow(path: Path) -> Workflow:
    """Resolve a workflow file into its env, jobs, and steps."""
    return parse_workflow(path.read_text(encoding="utf-8"), path)


def _parse_synthetic(text: str) -> Workflow:
    """Parse workflow TEXT through the identical reader the gate uses.

    The synthetic-fixture tests must exercise the same code path as the real
    sweep; a separate parser for tests would prove nothing about the sweep.
    """
    return parse_workflow(text, WORKFLOWS / "<synthetic>.yml")


def parse_workflow(text: str, path: Path) -> Workflow:
    """Resolve workflow text into its env, jobs, and steps. Fails closed."""
    rows = structural_lines(text)
    workflow = Workflow(path=path)

    seen_content = False
    for position, (lineno, indent, content) in enumerate(rows):
        if content == DOCUMENT_SEPARATOR:
            # A second document would be merged into the first by this reader
            # while a real parser -- and the runner -- read only the first. A
            # benign later `jobs:` would then overwrite a dangerous earlier one.
            if seen_content:
                _refuse_unresolvable(
                    path, lineno, "a second YAML document in this file",
                    "The runner reads only the first; merging them here would let "
                    "a later job definition mask an earlier one.",
                )
            continue
        seen_content = True
        if indent != 0:
            continue
        if content == DOCUMENT_END:
            continue
        parsed = _key(content)
        if not parsed:
            # The root is a mapping, so every row at column 0 is one of its
            # keys. A row that is not -- a merge key aliasing a whole mapping
            # in, an explicit key, a directive -- can introduce `env:` or
            # `jobs:` without this reader seeing where they came from.
            _refuse_unresolvable(
                path, lineno, f"the root-level row `{content}`",
                "The root of a workflow is a block mapping; a row here this reader "
                "cannot name could introduce `env:` or `jobs:` invisibly.",
            )
        key, value = parsed
        if key == "env":
            if value:
                _refuse_unresolvable(
                    path, lineno, "the workflow-level `env:` value",
                    "An inline `env:` hides the outer declarations rule 2 compares "
                    "step keys against, so a shadowed pin would read as no shadow.",
                )
            workflow.env = _mapping_keys(
                rows, position + 1, _child_indent(rows, position), path,
                "the workflow-level `env:`",
            )
        elif key == "defaults":
            if value:
                _refuse_unresolvable(
                    path, lineno, "the workflow-level `defaults:` value",
                    "An inline or aliased `defaults:` resolves to no shell here, so "
                    "a `run.shell` it declares would evade rule 3.",
                )
            workflow.default_shell = _read_default_shell(
                rows, position, path, "this workflow"
            )
        elif key == "jobs":
            if value:
                _refuse_unresolvable(
                    path, lineno, "the `jobs:` value", "It is not a block mapping."
                )
            _read_jobs(rows, position, workflow)

    if not workflow.jobs:
        raise AssertionError(
            f"{path.relative_to(ROOT)}: the structural reader resolved no jobs. "
            f"This gate refuses to pass on a workflow it cannot read."
        )
    return workflow


def _child_indent(rows: list[tuple[int, int, str]], position: int) -> int:
    """The indent of the first row nested under `rows[position]`."""
    parent = rows[position][1]
    for _, indent, _ in rows[position + 1 :]:
        if indent > parent:
            return indent
        break
    return parent + 2


def _read_jobs(rows: list[tuple[int, int, str]], jobs_at: int, workflow: Workflow) -> None:
    job_indent = _child_indent(rows, jobs_at)
    for position, (lineno, indent, content) in enumerate(rows[jobs_at + 1 :], start=jobs_at + 1):
        if indent < job_indent:
            break
        if indent != job_indent:
            continue
        parsed = _key(content)
        if not parsed:
            _refuse_unresolvable(
                workflow.path, lineno, f"the row `{content}` under `jobs:`",
                "`jobs:` is a block mapping of job ids; a row here this reader "
                "cannot name could be a job whose steps no rule would then see.",
            )
        if parsed[1]:
            # A job is always a mapping. A job id carrying ANY same-line value
            # is an anchor, an alias, or a flow node -- something whose steps
            # this reader does not resolve, so every rule would see an empty
            # job. Refused positively rather than pattern-matched, so a spelling
            # nobody listed is still refused.
            _refuse_unresolvable(
                workflow.path, lineno, f"job {parsed[0]!r}, written as `{content}`",
                "A job is a block mapping. A same-line value here is an anchor, an "
                "alias, or a flow node, so its steps cannot be resolved and every "
                "rule below would see an empty job.",
            )
        job = Job(name=parsed[0], line=lineno)
        _read_job_body(rows, position, job_indent, job, workflow.path)
        workflow.jobs[job.name] = job


def _read_job_body(rows, job_at: int, job_indent: int, job: Job, path: Path) -> None:
    prop_indent = _child_indent(rows, job_at)
    for position, (lineno, indent, content) in enumerate(rows[job_at + 1 :], start=job_at + 1):
        if indent <= job_indent:
            break
        if indent != prop_indent:
            continue
        if MERGE_KEY.match(content):
            _refuse_unresolvable(
                path, lineno, f"the merge key in job {job.name!r}",
                "Merged keys are not expanded here, so a merged-in "
                "`continue-on-error`, `env`, or `steps` would be invisible.",
            )
        parsed = _key(content)
        if not parsed:
            if _is_item(content):
                continue  # a block sequence written level with its own key
            _refuse_unresolvable(
                path, lineno, f"the row `{content}` in job {job.name!r}",
                "A job's properties are a block mapping; a row here this reader "
                "cannot name could be `continue-on-error`, `env`, `defaults` or "
                "`steps` under a spelling every rule below would then miss.",
            )
        key, value = parsed
        if key == "continue-on-error":
            job.continue_on_error = (
                resolve_boolean(
                    rows, position, prop_indent, value, path, lineno,
                    f"the `continue-on-error:` of job {job.name!r}",
                ),
                lineno,
            )
        elif key == "env":
            if value:
                _refuse_unresolvable(
                    path, lineno, f"the inline `env:` in job {job.name!r}",
                    "Rule 2 compares step keys against this declaration; an "
                    "unresolved one reads as no declaration, so nothing shadows it.",
                )
            job.env = _mapping_keys(
                rows, position + 1, _child_indent(rows, position), path,
                f"the `env:` of job {job.name!r}",
            )
        elif key == "container":
            job.container_env = _read_container_env(
                rows, position, value, path, lineno, f"job {job.name!r}"
            )
        elif key == "defaults":
            if value:
                _refuse_unresolvable(
                    path, lineno, f"the inline `defaults:` in job {job.name!r}",
                    "An inline or aliased `defaults:` resolves to no shell here, so "
                    "a `run.shell` it declares would evade rule 3.",
                )
            job.default_shell = _read_default_shell(
                rows, position, path, f"job {job.name!r}"
            )
        elif key == "steps":
            if value:
                _refuse_unresolvable(
                    path, lineno, f"the inline `steps:` in job {job.name!r}",
                    "A flow sequence or alias of steps resolves to no steps here, "
                    "so every step in the job would evade all three rules.",
                )
            job.declares_steps = True
            _read_steps(rows, position, prop_indent, job, path)
            if not job.steps:
                _refuse_unresolvable(
                    path, lineno, f"the `steps:` sequence in job {job.name!r}",
                    "The job declares steps and this reader resolved none, so every "
                    "rule below would see an empty job and pass it. A job with no "
                    "steps at all is a reusable-workflow call, which writes `uses:` "
                    "at job level and no `steps:` key.",
                )


def _read_steps(rows, steps_at: int, prop_indent: int, job: Job, path: Path) -> None:
    """Read the step list.

    Items are located by the SEQUENCE's own indent, derived from its first
    item, and each step's properties by the column its first key actually sits
    in -- never by a fixed `+ 2` from the dash and never by assuming the
    sequence is indented deeper than its key. Three valid shapes broke the
    fixed-offset reader, each making the step, and therefore every rule below,
    invisible: a bare `-` with the keys on the following lines, a sequence
    level with its own `steps:` key, and a wider gap after the dash. All three
    pass `actionlint` at rc=0 and all three run.

    Every row this reader meets at the item column or the property column must
    RESOLVE -- as a sequence item, or as a key it can name. A row it cannot
    read is refused rather than skipped, because a skipped property is a
    `shell:`, `continue-on-error:` or `env:` that all three rules then miss.
    See the module docstring's boundary section for the full set, and the
    differential-parser fixture that pins it.
    """
    item_indent = _item_indent(rows, steps_at, prop_indent)
    if item_indent is None:
        return
    for position, (lineno, indent, content) in enumerate(rows[steps_at + 1 :], start=steps_at + 1):
        if indent < item_indent:
            break
        if indent == item_indent and not _is_item(content):
            break  # the sequence ended; this is the job's next property
        if indent != item_indent:
            continue  # a property line of the step already being read
        inline = content[1:].lstrip(" ")
        # The property column is where the first key LANDS, so `-   name: x`
        # reads the same as `- name: x` instead of losing every later key.
        step_indent = (
            indent + 1 + (len(content) - 1 - len(inline))
            if inline
            else _first_deeper_indent(rows, position, item_indent)
        )
        first = _key(inline) if inline else None
        if inline and first is None:
            # A step is a mapping. An item whose content is not a `key: value`
            # is a flow mapping, an anchor, an alias, or a plain scalar -- none
            # of which this reader resolves into keys, so the step would evade
            # all three rules. Refused by NOT recognising it, rather than by
            # matching a list of leading characters.
            _refuse_unresolvable(
                path, lineno, f"the step item `{content}` in job {job.name!r}",
                "A step is a block mapping. An item this reader cannot read as a "
                "`key: value` is a flow mapping, an anchor, an alias, or a bare "
                "scalar, and none of them resolves into the keys all three rules "
                "read.",
            )
        step = Step(name=(first[1].strip("\"'") if first and first[0] == "name" else ""), line=lineno)
        # A step written as `- shell: sh` carries the key on the item line
        # itself, so that line IS the key's line, and `step_indent` is the
        # column that key starts in -- which is what decides whether an empty
        # same-line value has a scalar nested under it.
        if first and first[0] == "shell":
            step.shell = (
                resolve_scalar(
                    rows, position, step_indent, first[1], path, lineno,
                    f"the `shell:` of the step at line {lineno}",
                ),
                lineno,
            )
        if first and first[0] == "continue-on-error":
            step.continue_on_error = (
                resolve_boolean(
                    rows, position, step_indent, first[1], path, lineno,
                    f"the `continue-on-error:` of the step at line {lineno}",
                ),
                lineno,
            )
        for inner, (inner_line, inner_indent, inner_content) in enumerate(
            rows[position + 1 :], start=position + 1
        ):
            if inner_indent < step_indent:
                break
            if inner_indent != step_indent:
                continue
            if MERGE_KEY.match(inner_content):
                _refuse_unresolvable(
                    path, inner_line, f"the merge key in step {step.name or lineno!r}",
                    "Merged keys are not expanded, so a merged-in `shell`, "
                    "`continue-on-error`, or `env` would never be seen.",
                )
            parsed = _key(inner_content)
            if not parsed:
                if _is_item(inner_content):
                    continue  # a block sequence written level with its own key
                _refuse_unresolvable(
                    path, inner_line,
                    f"the row `{inner_content}` in step {step.name or lineno!r}",
                    "A step's properties are a block mapping; a row here this reader "
                    "cannot name could be `shell`, `continue-on-error` or `env` under "
                    "a spelling all three rules would then miss.",
                )
            key, value = parsed
            if key == "name" and not step.name:
                step.name = value.strip("\"'")
            elif key == "shell":
                step.shell = (
                    resolve_scalar(
                        rows, inner, inner_indent, value, path, inner_line,
                        f"the `shell:` of step {step.name or lineno!r}",
                    ),
                    inner_line,
                )
            elif key == "continue-on-error":
                step.continue_on_error = (
                    resolve_boolean(
                        rows, inner, inner_indent, value, path, inner_line,
                        f"the `continue-on-error:` of step {step.name or lineno!r}",
                    ),
                    inner_line,
                )
            elif key == "env":
                if value:
                    _refuse_unresolvable(
                        path, inner_line, f"the inline `env:` in step {step.name or lineno!r}",
                        "Rule 2 reads this mapping's KEYS; an unresolved one reads "
                        "as an empty step env, so nothing it declares can shadow.",
                    )
                step.env = _mapping_keys(
                    rows, inner + 1, _child_indent(rows, inner), path,
                    f"the `env:` of step {step.name or lineno!r}",
                )
        if not step.name:
            step.name = f"<unnamed step at line {lineno}>"
        job.steps.append(step)


# --------------------------------------------------------------------------
# The required-checks set, DERIVED from the release contract
# --------------------------------------------------------------------------


def required_jobs(workflow: Workflow) -> set[str]:
    """Which of this workflow's jobs the release publisher authorizes against.

    Derived from `release_contract.py`, never re-listed here. `pr-gate.yml`
    job IDs appear verbatim in `EXPECTED_MAIN_JOBS`. CodeQL's expected names
    are matrix-expanded (`analyze (go, manual)`), so a job ID counts when an
    expected name is that ID or begins `<id> (`.
    """
    if workflow.name == "pr-gate.yml":
        return {job for job in workflow.jobs if job in RC.EXPECTED_MAIN_JOBS}
    if workflow.name == "codeql.yml":
        return {
            job
            for job in workflow.jobs
            for expected in RC.EXPECTED_CODEQL_JOBS
            if expected == job or expected.startswith(f"{job} (")
        }
    return set()


def pinned_tool_variables() -> set[str]:
    """Names `install-tools.sh` pins -- tool versions and their checksums."""
    text = INSTALL_TOOLS.read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Z][A-Z0-9_]*(?:_VERSION|_SHA256))=", text, flags=re.MULTILINE))


# --------------------------------------------------------------------------
# Allowlist -- the lift mechanism
# --------------------------------------------------------------------------


def read_allowlist(text: str | None = None) -> dict[tuple[str, str, str], str]:
    """Parse `<workflow> | <rule> | <where> | <reason>` lines.

    `text` exists so these refusals are TESTABLE without writing a broken line
    into the real allowlist. A parser whose only probe is "edit the file it
    guards and see what happens" is a parser nobody re-checks; the shipped call
    passes nothing and reads the file exactly as before.
    """
    entries: dict[tuple[str, str, str], str] = {}
    if text is None:
        text = ALLOWLIST.read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4:
            raise AssertionError(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: expected exactly four "
                f"`|`-separated fields -- `<workflow> | <rule> | <where> | <reason>`."
            )
        workflow, rule, where, reason = parts
        if not all((workflow, rule, where, reason)):
            raise AssertionError(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: every field must be "
                f"non-empty. An allowlist without reasons is a mute button."
            )
        if rule not in RULES:
            raise AssertionError(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: unknown rule {rule!r}; "
                f"expected one of {', '.join(RULES)}."
            )
        entries[(workflow, rule, where)] = reason
    return entries


def stale_reason(
    workflows: list[Workflow], workflow_name: str, rule: str, where: str
) -> str | None:
    """Why this allowlist entry protects nothing any more, or None if it is live.

    A lift mechanism must ratchet SHUT as well as open. Checking only that the
    WORKFLOW field names a real file lets an entry outlive its subject: the
    exempted step is renamed or deleted, the line stays, and it silently
    pre-authorises whatever later takes that name. `subcommand-callers-
    allowlist.txt` already refuses both a subject that does not exist and one
    that no longer needs exempting; this is the same contract for this file,
    which the 0.1.49 changelog claimed and only half delivered.

    `where` is `<job>`, `<job>/<step>`, `<job>/<step>/<key>`, or one of the
    sentinel subjects for the scopes no step name can address: the bare
    `DEFAULT_SHELL_SUBJECT` and `<job>/DEFAULT_SHELL_SUBJECT` for rule 3's two
    `defaults.run.shell` positions, and `WORKFLOW_ENV_SUBJECT/<key>`,
    `<job>/JOB_ENV_SUBJECT/<key>` and `<job>/CONTAINER_ENV_SUBJECT/<key>` for
    rule 2's three non-step scopes. Every one of them ratchets: the entry dies
    when the declaration it exempts does.
    """
    workflow = next((w for w in workflows if w.name == workflow_name), None)
    if workflow is None:
        return None  # already refused by test_allowlist_entries_name_real_workflows
    if rule == "contract-floor":
        # The subject is a sentence in AGENTS.md, not a construct in any job,
        # so it is settled before the `<job>/...` partition below. It is
        # addressed by its TEXT for the same reason every other subject here
        # is addressed by name: a line number is an inventory pin that an
        # edit three paragraphs above invalidates.
        if where not in {claim.text for claim in coverage_floor_claims(agents_text())}:
            return (
                f"exempts the coverage-floor claim {where!r}, which AGENTS.md no longer "
                f"states"
            )
        return None
    if rule == "custom-shell" and where == DEFAULT_SHELL_SUBJECT:
        if workflow.default_shell is None:
            return (
                f"exempts the workflow-level `defaults.run.shell`, which "
                f"{workflow_name} does not set"
            )
        return None
    if rule == "env-shadow" and where.split("/")[0] == WORKFLOW_ENV_SUBJECT:
        # The workflow-level scope carries no job, so it is settled before the
        # `<job>/...` partition below -- exactly like the default-shell subject.
        _, separator, key = where.partition("/")
        if not separator:
            return f"is missing the `{WORKFLOW_ENV_SUBJECT}/<KEY>` subject it needs"
        if key not in workflow.env:
            return (
                f"exempts workflow-level `env: {key}`, which {workflow_name} does "
                f"not declare"
            )
        return None
    job_name, _, rest = where.partition("/")
    job = workflow.jobs.get(job_name)
    if job is None:
        return f"names job {job_name!r}, which {workflow_name} does not declare"
    if rule == "custom-shell" and rest == DEFAULT_SHELL_SUBJECT:
        if job.default_shell is None:
            return (
                f"exempts `defaults.run.shell` on job {job_name!r}, which does not "
                f"set one"
            )
        return None
    if rule == "env-shadow":
        scope_subject, separator, scoped_key = rest.partition("/")
        for subject, label, declared in (
            (JOB_ENV_SUBJECT, "job-level", job.env),
            (CONTAINER_ENV_SUBJECT, "container-level", job.container_env),
        ):
            if scope_subject != subject:
                continue
            if not separator:
                return f"is missing the `<job>/{subject}/<KEY>` subject it needs"
            if scoped_key not in declared:
                return (
                    f"exempts {label} `env: {scoped_key}` on job {job_name!r}, "
                    f"which does not declare it"
                )
            return None

    if rule == "continue-on-error" and not rest:
        if job.continue_on_error is None:
            return f"exempts `continue-on-error` on job {job_name!r}, which does not set it"
        return None

    step_name, key = rest, ""
    if rule == "env-shadow":
        # The KEY is the last segment; a step name may itself contain a slash.
        # Key off the SEPARATOR, not the key: `rpartition` on a `<job>/<step>`
        # subject puts the step name in `key` and leaves the step name empty,
        # which reads as a plausible parse of a malformed entry.
        step_name, separator, key = rest.rpartition("/")
        if not separator:
            return "is missing the `<job>/<step>/<key>` subject the env-shadow rule needs"
    if not step_name:
        return f"names no step in job {job_name!r}"
    step = next((s for s in job.steps if s.name == step_name), None)
    if step is None:
        return f"names step {step_name!r}, which job {job_name!r} does not have"
    if rule == "continue-on-error" and step.continue_on_error is None:
        return f"exempts `continue-on-error` on step {step_name!r}, which does not set it"
    if rule == "custom-shell" and step.shell is None:
        return f"exempts `shell:` on step {step_name!r}, which does not set one"
    if rule == "env-shadow" and key not in step.env:
        return f"exempts `env: {key}` on step {step_name!r}, which does not declare it"
    return None


# --------------------------------------------------------------------------
# Issue #225 -- the coverage floor is one fact in more than one file
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FloorDeclaration:
    """Where a workflow declares the coverage floor, and what it declares."""

    workflow: str
    scope: str
    line: int
    value: str

    @property
    def where(self) -> str:
        return f".github/workflows/{self.workflow}:{self.line} ({self.scope})"


@dataclass(frozen=True)
class FloorClaim:
    """Where the contract states the coverage floor, and what it states."""

    line: int
    value: str
    text: str

    @property
    def where(self) -> str:
        return f"AGENTS.md:{self.line}"


def _declared_scalar(path: Path, lineno: int, key: str) -> str:
    """Resolve the value of `key` declared on one exact line, or REFUSE.

    The structural reader records WHERE each `env:` key is declared, not what
    it is set to, because no rule needed the value until this one. Reading it
    back reuses the same comment stripping and the same allowlist of scalar
    spellings, so an exotic value raises here exactly as it would there rather
    than being compared as text nobody resolved.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    content = _strip_comment(lines[lineno - 1]).strip()
    parsed = _key(content)
    if not parsed or parsed[0] != key:
        _refuse_unresolvable(
            path, lineno, f"the `{key}` declaration",
            "The line the structural reader recorded no longer reads as that key.",
        )
    value = parsed[1]
    if SINGLE_QUOTED.match(value) or DOUBLE_QUOTED.match(value):
        return value[1:-1]
    if PLAIN_SCALAR.match(value):
        return value
    _refuse_unresolvable(
        path, lineno, f"the `{key}` value, written as `{value}`",
        "That is not one of the scalar spellings this reader resolves, and a "
        "floor nobody resolved cannot be compared against the contract.",
    )


def coverage_floor_declarations(workflows: list[Workflow]) -> list[FloorDeclaration]:
    """Every `GO_COVERAGE_FLOOR` a workflow declares, at any `env:` scope.

    Scoped by SEARCH, never by a pinned job/step address: moving the coverage
    step, renaming it, or declaring the floor at job level are all ordinary
    edits, and a gate that pinned today's address would fail them for being
    different rather than for being wrong.
    """
    found: list[FloorDeclaration] = []
    for workflow in workflows:
        scopes: list[tuple[str, dict[str, int]]] = [("workflow env", workflow.env)]
        for job_name, job in workflow.jobs.items():
            scopes.append((f"job {job_name} env", job.env))
            scopes.append((f"job {job_name} container env", job.container_env))
            for step in job.steps:
                scopes.append((f"job {job_name}, step {step.name!r} env", step.env))
        for scope, env in scopes:
            line = env.get(COVERAGE_FLOOR_KEY)
            if line is None:
                continue
            found.append(
                FloorDeclaration(
                    workflow=workflow.name,
                    scope=scope,
                    line=line,
                    value=_declared_scalar(workflow.path, line, COVERAGE_FLOOR_KEY),
                )
            )
    return found


def coverage_floor_claims(text: str) -> list[FloorClaim]:
    """Every place the contract states a number FOR the coverage floor.

    A claim is the variable's own name followed, inside the same paragraph, by
    a number. That keeps the historical figures beside it out of scope -- the
    measured coverage when the floor was last raised is a different fact -- by
    taking the FIRST number after the name and nothing else, which is how both
    of requirement 7's sentences are written.
    """
    claims: list[FloorClaim] = []
    for block in re.finditer(r"(?:(?!\n\s*\n).)+", text, flags=re.DOTALL):
        paragraph = block.group(0)
        for mention in re.finditer(re.escape(COVERAGE_FLOOR_KEY), paragraph):
            number = _FLOOR_NUMBER.search(paragraph, mention.end())
            if number is None:
                continue
            claims.append(
                FloorClaim(
                    line=text.count("\n", 0, block.start() + mention.start()) + 1,
                    value=number.group(0),
                    text=" ".join(paragraph[mention.start() : number.end()].split()),
                )
            )
    return claims


def coverage_floor_disagreements(
    declarations: list[FloorDeclaration],
    claims: list[FloorClaim],
    allowlist: dict[tuple[str, str, str], str] | None = None,
) -> list[str]:
    """Report every way the enforced floor and the stated floor fail to be one fact.

    Returns human-readable lines rather than raising, so the caller can print
    ALL of them at once: a refusal that names one location and stops makes the
    reader re-derive the parse to find the other.
    """
    allowed = {where for (_workflow, rule, where) in (allowlist or {}) if rule == "contract-floor"}
    rendered_declarations = ", ".join(
        f"{declaration.where} = {declaration.value}" for declaration in declarations
    ) or "(none)"
    problems: list[str] = []
    if not declarations:
        return [
            "no workflow declares "
            f"`{COVERAGE_FLOOR_KEY}`, so the enforced coverage floor cannot be read at all"
        ]
    values = {float(declaration.value) for declaration in declarations}
    if len(values) != 1:
        problems.append(
            f"the workflows declare {len(values)} different `{COVERAGE_FLOOR_KEY}` values "
            f"({rendered_declarations}); the floor is one fact"
        )
    enforced = declarations[0].value
    if not claims:
        problems.append(
            f"AGENTS.md states no `{COVERAGE_FLOOR_KEY}` number at all, while CI enforces "
            f"{rendered_declarations}. Requirement 7's contract must state the floor it "
            "is enforcing; deleting the claim is not how the two are kept in step"
        )
    for claim in claims:
        if claim.text in allowed:
            continue
        if float(claim.value) != float(enforced):
            problems.append(
                f"{claim.where} states {claim.value} for the coverage floor "
                f"({claim.text!r}), while CI enforces {rendered_declarations}"
            )
    return problems


def lift_instruction(workflow: str, rule: str, where: str) -> str:
    return (
        f"\n\nTo lift this refusal, add ONE line to "
        f"{ALLOWLIST.relative_to(ROOT).as_posix()}:\n\n"
        f"    {workflow} | {rule} | {where} | <why this construct is correct here>\n\n"
        f"Widening this allowlist is a normal, expected part of active "
        f"development -- one line, one PR, no release train. Prefer removing "
        f"the construct when it is not load-bearing."
    )


def workflow_paths(workflows: Path = WORKFLOWS) -> list[Path]:
    """Return every workflow extension GitHub accepts."""
    return sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml")))


def run_blocks(text: str) -> list[tuple[int, int, str]]:
    """Every `run: |` literal block: the line of its key, its length, and its dedented shell."""
    lines = text.splitlines()
    blocks = []
    for index, line in enumerate(lines):
        key = re.match(r"^(\s*)(?:- )?run:\s*\|[-+]?\s*$", line)
        if not key:
            continue
        body = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= len(key[1]):
                break
            body.append(following)
        blocks.append((index + 1, len(body), textwrap.dedent("\n".join(body)) + "\n"))
    return blocks


def resolve_uses(value: str, path: Path, lineno: int) -> str:
    """Resolve a `uses:` reference, or REFUSE. Never returns a guess.

    `resolve_scalar`'s fail-closed default, in the one position whose character
    set it cannot serve. The 0.1.65 review beat the previous inline
    quote-stripping with `!!str github/codeql-action/init@<old sha>`: an
    explicit tag is a spelling a real parser and `actionlint` both accept, the
    tagged text does not START with `github/`, and a reader that skips what it
    does not recognise made that spelling the silent pass. Recognising is now
    the only way past this function, so a spelling nobody anticipated turns the
    gate RED with no edit here.
    """
    if SINGLE_QUOTED.match(value) or DOUBLE_QUOTED.match(value):
        value = value[1:-1]
        if USES_REFERENCE.match(value):
            return value
    elif USES_REFERENCE.match(value):
        return value
    _refuse_unresolvable(
        path, lineno, f"the `uses:` reference written as `{value}`",
        "That is not one of the reference spellings this reader resolves (a "
        "plain reference, or a quoted one without escapes). An action this "
        "reader cannot name is an action it cannot hold to a release, which is "
        "a silent pass on exactly the drift the rule below exists to refuse.",
    )


def uses_references(text: str, path: Path) -> list[tuple[int, str]]:
    """Every `uses:` reference one workflow or action file declares."""
    found: list[tuple[int, str]] = []
    for lineno, _indent, content in structural_lines(text):
        candidate = content[1:].lstrip() if _is_item(content) else content
        parsed = _key(candidate)
        if parsed and parsed[0] == "uses":
            found.append((lineno, resolve_uses(parsed[1], path, lineno)))
    return found


def local_action_entrypoint(root: Path, reference: str, path: Path, lineno: int) -> Path:
    """Resolve a `./` reference to the file GitHub executes, or REFUSE.

    A same-repository action lives at ANY repository-relative directory holding
    `action.yml` or `action.yaml`. `.github/actions` is a convention and
    nothing more, which is what the 0.1.65 review proved by moving the executed
    CodeQL role one directory outside it and leaving a version-matched decoy
    behind: a sweep of the convention read as complete and covered nothing that
    ran. Following the reference is what makes the surface below the executable
    namespace instead of a naming habit.

    Both `./` spellings resolve here, because `uses:` carries both: a job-level
    local REUSABLE WORKFLOW names its file (`./.github/workflows/x.yml`), while
    a step-level local ACTION names the directory holding its metadata. Reading
    only the second refused the first, which is a legitimate construct this
    repository may add on any ordinary day -- a gate that reddens on new work
    it never anticipated is the failure this file's own contract forbids.
    """
    target = root / reference[2:]
    candidates = (
        (target,)
        if target.suffix in (".yml", ".yaml")
        else (target / "action.yml", target / "action.yaml")
    )
    for entrypoint in candidates:
        if entrypoint.is_file():
            return entrypoint
    _refuse_unresolvable(
        path, lineno, f"the same-repository reference `{reference}`",
        "It names neither a workflow file nor a directory holding an "
        "`action.yml` or `action.yaml`, so this reader cannot see what runs.",
    )


def all_workflows() -> list[Workflow]:
    return [read_workflow(path) for path in workflow_paths()]


def agents_text() -> str:
    return AGENTS.read_text(encoding="utf-8")


def codeql_lockstep_problems(github: Path = GITHUB) -> list[str]:
    """Report any executable CodeQL role that leaves one shared release.

    Reads from disk and expands as it goes: the workflows GitHub runs, then
    every same-repository action they reach, transitively, because a composite
    can call another composite. There is no injectable text mapping -- WHAT
    THIS FINDS is half of what the rule asserts, and a dict handed in by a test
    proves nothing about a tree on disk.
    """
    root = github.parent
    texts = {
        path: path.read_text(encoding="utf-8")
        for path in workflow_paths(github / "workflows")
    }
    pending = list(texts)
    references: list[tuple[str, str, str, Path, int]] = []
    problems: list[str] = []
    while pending:
        path = pending.pop()
        raw_lines = texts[path].splitlines()
        for lineno, value in uses_references(texts[path], path):
            if value.startswith("./"):
                entrypoint = local_action_entrypoint(root, value, path, lineno)
                if entrypoint not in texts:
                    texts[entrypoint] = entrypoint.read_text(encoding="utf-8")
                    pending.append(entrypoint)
                continue
            if not value.casefold().startswith(
                ("github/codeql-action/init@", "github/codeql-action/analyze@")
            ):
                continue
            action = CODEQL_ACTION_REFERENCE.fullmatch(value)
            version = CODEQL_VERSION_COMMENT.search(raw_lines[lineno - 1])
            if not action or not version:
                problems.append(
                    f"{_display(path)}:{lineno}: CodeQL init/analyze must use "
                    "one full lowercase SHA and a trailing vX.Y.Z comment"
                )
                continue
            references.append((action[1].lower(), action[2], version[1], path, lineno))
    roles = {role for role, _sha, _version, _path, _line in references}
    if roles != {"init", "analyze"}:
        problems.append(f"CodeQL action roles resolved as {sorted(roles)!r}, expected init and analyze")
    releases = {(sha, version) for _role, sha, version, _path, _line in references}
    if len(releases) != 1:
        rendered = ", ".join(
            f"{role}={sha[:12]} {version}" for role, sha, version, _path, _line in references
        ) or "(none)"
        problems.append(f"CodeQL init/analyze do not share one immutable release: {rendered}")
    return problems


# --------------------------------------------------------------------------


class WorkflowIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflows = all_workflows()
        cls.allowlist = read_allowlist()

    # -- the reader itself must not pass vacuously ---------------------------

    def test_every_workflow_resolves_into_jobs_and_steps(self):
        """Fail closed if the structural reader stops seeing structure.

        A floor of one, never a count: this proves the reader works, without
        pinning how many jobs or steps any workflow has.

        PER JOB, not `any()` across the workflow. The 0.1.49 round-2 review
        found the `any()` form could let one job resolving steps mask another
        resolving none -- and could not exploit it, because the reader refuses
        every shape that produces a silent zero-step job. It was closed by the
        reader, not by this test, which is a fragile place for it to be closed.
        `all(job.steps ...)` would be WRONG: a reusable-workflow job (`uses:` at
        job level) legitimately has no steps, so that form false-reds the day
        one lands. `declares_steps` is the exact predicate -- a job that WROTE
        `steps:` must have resolved some -- and the reader now refuses a
        declared-but-empty `steps:` outright, so the two agree by construction.
        If you are here because a reusable-workflow job went red, the bug is in
        the reader setting `declares_steps`, never in relaxing this back to
        `any()`.
        """
        self.assertTrue(self.workflows, "no workflows were discovered")
        declaring = 0
        for workflow in self.workflows:
            with self.subTest(workflow=workflow.name):
                self.assertTrue(workflow.jobs, "resolved no jobs")
                for name, job in sorted(workflow.jobs.items()):
                    if not job.declares_steps:
                        continue  # a reusable-workflow call has no steps to resolve
                    declaring += 1
                    self.assertTrue(
                        job.steps,
                        f"job {name!r} declares `steps:` and the reader resolved none",
                    )
        self.assertTrue(declaring, "no job in any workflow declares `steps:`")

    def test_the_required_checks_set_is_non_empty(self):
        """The rules below are scoped by this set; an empty one disarms them."""
        covered = {w.name: required_jobs(w) for w in self.workflows}
        self.assertTrue(
            covered.get("pr-gate.yml"), "no required jobs resolved for pr-gate.yml"
        )
        self.assertTrue(
            covered.get("codeql.yml"), "no required jobs resolved for codeql.yml"
        )

    OLD_CODEQL = ("db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28", "v4.37.8")
    COMPOSITE = (
        "name: Initialize CodeQL\n"
        "description: A same-repository wrapper around the real action\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: github/codeql-action/init@"
        "db488ddef3bf6cb639b32c2e9a7c0a7ea8271d28 # v4.37.8\n"
    )

    @staticmethod
    def write_tree(root: Path, files: dict[str, str]) -> Path:
        """Write a whole mutant repository to disk; return its `.github`."""
        for relative, text in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return root / ".github"

    def displace_init(self, real: str) -> str:
        """Leave the current release where a shallow reader looks; run `real`.

        Every surviving bypass the 0.1.65 reviews found has this shape: a
        syntactically perfect, version-matched CodeQL reference that never
        executes, in front of the reference that does.
        """
        mutated, count = re.subn(
            r"(?m)^(\s*)- name: Initialize CodeQL\n"
            r"(\s*)uses: github/codeql-action/init@([0-9a-f]{40})"
            r"\s+#\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*$",
            lambda match: (
                f"{match[1]}- name: Unreachable current-release decoy\n"
                f"{match[2]}if: ${{{{ github.repository == 'never/real' }}}}\n"
                f"{match[2]}uses: github/codeql-action/init@{match[3]} # {match[4]}\n"
                f"{match[1]}- name: Initialize CodeQL\n"
                f"{match[2]}{real}"
            ),
            (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8"),
            count=1,
        )
        self.assertEqual(count, 1, f"did not displace the real init with `{real}`")
        return mutated

    def test_codeql_init_and_analyze_share_one_immutable_release(self):
        """The two security-action roles move together, independent of version."""
        self.assertEqual(codeql_lockstep_problems(), [])

    def test_codeql_lockstep_kills_every_known_displacement(self):
        """Each bypass the reviews found, rebuilt as a real repository on disk.

        Real trees rather than an injected mapping, deliberately: discovery IS
        half of this rule, and a dict handed to the function under test asserts
        only about texts a test already chose to include. Two of these mutants
        exist because a sweep that read as repository-wide was in fact a sweep
        of `.github/workflows` and then of `.github/actions`.
        """
        old_sha, old_version = self.OLD_CODEQL
        current = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")

        def rollback(role: str) -> str:
            mutated, count = re.subn(
                rf"(github/codeql-action/{role}@)[0-9a-f]{{40}}"
                rf"(\s+#\s*)v[0-9]+\.[0-9]+\.[0-9]+",
                lambda match: f"{match[1]}{old_sha}{match[2]}{old_version}",
                current,
                count=1,
            )
            self.assertEqual(count, 1, f"did not construct the {role}-old mutant")
            return mutated

        shadow = (
            "name: CodeQL shadow\n"
            "on:\n"
            "  workflow_dispatch:\n"
            "permissions: {}\n"
            "jobs:\n"
            "  analyze:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            f"      - uses: github/codeql-action/init@{old_sha} # {old_version}\n"
            f"      - uses: github/codeql-action/analyze@{old_sha} # {old_version}\n"
        )
        mutants = {
            "init-only rollback": {".github/workflows/codeql.yml": rollback("init")},
            "analyze-only rollback": {".github/workflows/codeql.yml": rollback("analyze")},
            "GitHub's second workflow extension": {
                ".github/workflows/codeql.yml": current,
                ".github/workflows/codeql-shadow.yaml": shadow,
            },
            "case-variant owner and repository": {
                ".github/workflows/codeql.yml": self.displace_init(
                    f"uses: GitHub/codeql-action/init@{old_sha} # {old_version}"
                ),
            },
            "composite action at the conventional path": {
                ".github/workflows/codeql.yml": self.displace_init(
                    "uses: ./.github/actions/codeql-init"
                ),
                ".github/actions/codeql-init/action.yml": self.COMPOSITE,
            },
            "composite action outside every convention": {
                ".github/workflows/codeql.yml": self.displace_init("uses: ./tools/codeql-init"),
                "tools/codeql-init/action.yaml": self.COMPOSITE,
            },
        }
        for label, files in mutants.items():
            with self.subTest(bypass=label), tempfile.TemporaryDirectory() as directory:
                self.assertTrue(
                    codeql_lockstep_problems(self.write_tree(Path(directory), files)),
                    f"the {label} bypass survived",
                )

    def test_codeql_lockstep_accepts_a_local_reusable_workflow(self):
        """A legitimate `./…/x.yml` job reference is resolved, not refused.

        The negative control for the sweep above. `uses:` names a file at job
        level and a directory at step level, and reading only the directory
        form turned an ordinary, correct workflow RED -- the exact "gate
        reddens on work it never anticipated" failure this file forbids.
        """
        current = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
        files = {
            ".github/workflows/reusable.yml": current,
            ".github/workflows/caller.yml": (
                "name: Caller\n"
                "on:\n"
                "  workflow_dispatch:\n"
                "permissions: {}\n"
                "jobs:\n"
                "  analyze:\n"
                "    uses: ./.github/workflows/reusable.yml\n"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                codeql_lockstep_problems(self.write_tree(Path(directory), files)), []
            )

    def test_codeql_lockstep_refuses_a_reference_it_cannot_resolve(self):
        """Fail closed on an unresolved `uses:`, rather than walking past it.

        An explicit tag and a dangling local reference are both spellings a
        real parser accepts and this reader does not. Skipping either is the
        silent pass: the step still runs, and nothing holds it to a release.
        """
        old_sha, old_version = self.OLD_CODEQL
        for label, files in {
            "explicitly tagged action reference": {
                ".github/workflows/codeql.yml": self.displace_init(
                    f"uses: !!str github/codeql-action/init@{old_sha} # {old_version}"
                ),
            },
            "local action reference resolving to nothing": {
                ".github/workflows/codeql.yml": self.displace_init("uses: ./tools/codeql-init"),
            },
        }.items():
            with self.subTest(spelling=label), tempfile.TemporaryDirectory() as directory:
                github = self.write_tree(Path(directory), files)
                with self.assertRaises(AssertionError) as caught:
                    codeql_lockstep_problems(github)
                self.assertIn("cannot resolve", str(caught.exception))

    def test_the_reader_ignores_constructs_inside_a_run_block(self):
        """A `shell:` line inside a shell script is text, not a step key.

        Without block-scalar skipping this gate would invent violations from
        the bash it is reading over -- and an agent would then "fix" a script.
        """
        synthetic = (
            "jobs:\n"
            "  gate:\n"
            "    steps:\n"
            "      - name: Probe\n"
            "        run: |\n"
            "          # shell: sh\n"
            "          printf 'continue-on-error: true\\n'\n"
            "          env:\n"
            "            NOT_A_KEY: 1\n"
        )
        rows = structural_lines(synthetic)
        contents = [content for _, _, content in rows]
        self.assertNotIn("# shell: sh", contents)
        self.assertNotIn("env:", contents)
        self.assertIn("- name: Probe", contents)

    def test_the_reader_sees_a_real_step_key(self):
        """The positive control for the test above.

        Block-scalar skipping must hide only what is INSIDE a `run:` body. If
        it also swallowed genuine step keys, all three rules would silently
        stop finding anything and this suite would pass on any workflow.
        """
        synthetic = (
            "jobs:\n"
            "  gate:\n"
            "    steps:\n"
            "      - name: Probe\n"
            "        shell: sh\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          REAL_KEY: 1\n"
            "        run: |\n"
            "          shell: hidden\n"
            "      - uses: ./.github/actions/probe\n"
            "        name: Named On An Inner Line\n"
        )
        job = _parse_synthetic(synthetic).jobs["gate"]
        step = job.steps[0]
        self.assertEqual(step.name, "Probe")
        # Value AND the line the key sits on -- the failure messages report
        # the key's own line, so parsing it wrong would misdirect the reader.
        self.assertEqual(step.shell, ("sh", 5))
        # A resolved BOOLEAN, not the text `true`: rule 1 never sees a string,
        # so there is no spelling left for it to compare wrong.
        self.assertEqual(step.continue_on_error, (True, 6))
        self.assertEqual(sorted(step.env), ["REAL_KEY"])
        # A step may open with `uses:` and carry its name on an inner line.
        # Every rule keys its allowlist entry on `<job>/<step name>`, so a name
        # resolved ONLY from the `- ` item line would report such a step as
        # `<unnamed step at line N>` and force a line-number-brittle entry --
        # exactly the inventory pin this file refuses to become. No workflow
        # here is written that way today, which is why the branch survived the
        # 0.1.49 mutation sweep until this fixture landed.
        self.assertEqual(job.steps[1].name, "Named On An Inner Line")

    # -- the reader's boundary, pinned shape by shape -------------------------

    # Every entry was differential-tested against a real YAML parser: the
    # reader's resolution equals the parser's for each shape below. This table
    # is the executable copy of the module docstring's boundary; extending one
    # means extending the other. `python3 -I` has no `yaml` module, so the
    # comparison cannot run here -- the EXPECTATIONS are what that comparison
    # produced, and re-deriving them means re-running it, not guessing.
    STEP_SHAPES = {
        "canonical `- name:`":
            ("      - name: Probe\n        shell: sh\n", "Probe", "sh"),
        "bare dash, keys below":
            ("      -\n        name: Probe\n        shell: sh\n", "Probe", "sh"),
        "sequence level with its `steps:` key":
            ("    - name: Probe\n      shell: sh\n", "Probe", "sh"),
        "wider gap after the dash":
            ("      -   name: Probe\n          shell: sh\n", "Probe", "sh"),
        "comment between dash and first key":
            ("      -\n        # a comment\n        name: Probe\n        shell: sh\n",
             "Probe", "sh"),
        "quoted keys":
            ('      - "name": Probe\n        "shell": sh\n', "Probe", "sh"),
        "single-quoted step name":
            ("      - name: 'Probe'\n        shell: sh\n", "Probe", "sh"),
        "shell on the item line itself":
            ("      - shell: sh\n        name: Probe\n", "Probe", "sh"),
        "block scalar body is not structure":
            ("      - name: Probe\n        shell: sh\n        run: |\n"
             "          shell: hidden\n          env:\n            NOT_A_KEY: 1\n",
             "Probe", "sh"),
        "folded block scalar body":
            ("      - name: Probe\n        shell: sh\n        run: >\n"
             "          echo shell: hidden\n", "Probe", "sh"),
        "explicitly indented block scalar":
            ("      - name: Probe\n        shell: sh\n        run: |2\n"
             "          echo hi\n", "Probe", "sh"),
        # Quotes are STRIPPED by the resolver, the way a real parser strips
        # them -- the rule compares a resolved value, never a spelling.
        "single-quoted scalar value":
            ("      - name: Probe\n        shell: 'sh'\n", "Probe", "sh"),
        "double-quoted scalar value":
            ('      - name: Probe\n        shell: "sh"\n', "Probe", "sh"),
    }

    UNRESOLVABLE_SHAPES = {
        "flow-mapping step item": "      - {name: Probe, shell: sh}\n",
        "aliased step item": "      - *a_step\n",
        "anchored step item": "      - &a_step\n        name: Probe\n",
        "bare scalar step item": "      - checkout\n",
        "merge key inside a step": "      - name: Probe\n        <<: *defaults\n",
        "explicit key inside a step": "      - name: Probe\n        ? shell\n        : sh\n",
        # Rule 3 keys on PRESENCE, so an unresolvable `shell:` value would
        # still redden -- but it would redden with text this reader never
        # resolved in the message, and `stale_reason` would compare that text.
        # The value layer is uniform across both rules that read one.
        "tagged step shell": "      - name: Probe\n        shell: !!str sh\n",
        "expression step shell": "      - name: Probe\n        shell: ${{ env.S }}\n",
        "step shell on the following line":
            "      - name: Probe\n        shell:\n          sh\n",
        "inline step env": "      - name: Probe\n        env: {A: 1}\n",
        "merge key inside a step env":
            "      - name: Probe\n        env:\n          <<: *outer\n",
        "explicit key inside a step env":
            "      - name: Probe\n        env:\n          ? GO_COVERAGE_FLOOR\n          : '0'\n",
        "step env entry this reader cannot name":
            "      - name: Probe\n        env:\n          0BAD: 1\n",
        "step env written as a sequence":
            "      - name: Probe\n        env:\n          - GO_COVERAGE_FLOOR\n",
    }

    # THE POINT OF THE WHOLE INVERSION, as an executable table.
    #
    # Every row is valid YAML that a real parser resolves TRUTHY or to the
    # string "true" -- so every row is a way of writing `continue-on-error:
    # true` that the runner would honour or that at minimum this reader cannot
    # honestly call "not true". None of them has a branch anywhere in this
    # file. They go red because the reader refuses what it does not recognise,
    # which is the only property that survives the next spelling nobody here
    # has thought of.
    #
    # `actionlint` rc=0 on `!!bool true`, `${{ true }}` and the next-line
    # scalar: those four SHIPPED past this gate at the 0.1.49 round-2 head and
    # are the review's finding 1. The rest `actionlint` happens to reject
    # today, and they are refused here anyway -- a fail-closed reader that
    # depends on another tool catching what it waves through is not fail-closed.
    UNRECOGNISED_TRUE_SPELLINGS = {
        "the scalar on the following line": "continue-on-error:\n          true\n",
        "an explicit `!!bool` tag": "continue-on-error: !!bool true\n",
        "an expression": "continue-on-error: ${{ true }}\n",
        "an `!!str` tag": "continue-on-error: !!str true\n",
        "a folded block scalar": "continue-on-error: >-\n          true\n",
        "a literal block scalar": "continue-on-error: |-\n          true\n",
        "a YAML 1.1 `yes`": "continue-on-error: yes\n",
        "a YAML 1.1 `on`": "continue-on-error: on\n",
        "an integer": "continue-on-error: 1\n",
        "a double-quoted escape": 'continue-on-error: "tr\\u0075e"\n',
        "an anchored value": "continue-on-error: &c true\n",
        "a flow sequence": "continue-on-error: [true]\n",
    }

    # The complete set of spellings the reader DOES resolve, and what it
    # resolves them to. Rule 1 is total across these two tables: every input is
    # in one or the other, so there is no third outcome for a spelling to hide
    # in. `True` here means rule 1 refuses; `False` means it passes.
    RECOGNISED_BOOLEANS = {
        "true": True, "True": True, "TRUE": True, '"true"': True, "'true'": True,
        "false": False, "False": False, "FALSE": False, '"false"': False,
    }

    def test_the_reader_resolves_every_step_shape_a_real_parser_accepts(self):
        """Read each valid shape the way a real YAML parser reads it.

        A reader that SKIPS a shape it does not understand is the worst kind of
        gate: the skipped step is invisible to all three rules, so the suite is
        green on exactly the construct being refused, while still reading as
        strict to a reviewer. The 0.1.49 review found one such shape; a
        differential sweep against a real parser found that the fixed `+ 2`
        offset and the `- `-prefix test between them hid SIX more. Each shape
        here is valid YAML that `actionlint` accepts at rc=0 and the runner
        executes.
        """
        # A floor, never a count. Emptying the table makes this a zero-
        # iteration loop, and the boundary the module docstring calls the most
        # important part of this file stops being pinned by anything -- the
        # exact surviving-mutant class the 0.1.49 reviews kept finding, and one
        # the round-3 commit closed for two of the four tables and not these.
        # Adding rows needs no edit here.
        self.assertTrue(self.STEP_SHAPES, "the resolvable-shape table is empty")
        for label, (item, name, shell) in self.STEP_SHAPES.items():
            with self.subTest(shape=label):
                job = _parse_synthetic("jobs:\n  gate:\n    steps:\n" + item).jobs["gate"]
                self.assertEqual(len(job.steps), 1, "the step was not resolved")
                self.assertEqual(job.steps[0].name, name)
                resolved = job.steps[0].shell
                # The first assertion carries the check; the `else ""` exists
                # only so a type checker can follow the narrowing.
                self.assertIsNotNone(resolved, "the step's shell was dropped")
                self.assertEqual(resolved[0] if resolved else "", shell)

    def test_the_reader_refuses_what_it_cannot_resolve(self):
        """Fail closed rather than skip, for every shape outside the boundary.

        These are resolvable by a real parser and NOT by this reader. Returning
        a partial answer for them is the silent pass; refusing is the only safe
        direction, costs nothing (no workflow here uses one), and leaves a
        message naming the construct.
        """
        # A floor, never a count -- see the sibling assertion above. Without it
        # the step-shape half of this test becomes a zero-iteration loop.
        self.assertTrue(self.UNRESOLVABLE_SHAPES, "the unresolvable-shape table is empty")
        for label, item in self.UNRESOLVABLE_SHAPES.items():
            with self.subTest(shape=label):
                with self.assertRaises(AssertionError) as caught:
                    _parse_synthetic("jobs:\n  gate:\n    steps:\n" + item)
                self.assertIn("cannot resolve", str(caught.exception))
        # Whole-file and job-level shapes, same rule.
        for label, text in (
            ("inline steps:", "jobs:\n  gate:\n    steps: [{name: Probe}]\n"),
            ("aliased job", "jobs:\n  gate: *template\n"),
            ("inline job env", "jobs:\n  gate:\n    env: {A: 1}\n    steps:\n      - name: P\n"),
            ("inline workflow env", "env: {A: 1}\njobs:\n  gate:\n    steps:\n      - name: P\n"),
            ("merge key in a job", "jobs:\n  gate:\n    <<: *d\n    steps:\n      - name: P\n"),
            ("merge key at the root",
             "<<: *root\njobs:\n  gate:\n    steps:\n      - name: P\n"),
            ("explicit key among a job's properties",
             "jobs:\n  gate:\n    ? shell\n    : sh\n    steps:\n      - name: P\n"),
            ("row under `jobs:` that is not a job id",
             "jobs:\n  <<: *jobs\n  gate:\n    steps:\n      - name: P\n"),
            ("inline job defaults",
             "jobs:\n  gate:\n    defaults: {run: {shell: sh}}\n    steps:\n      - name: P\n"),
            ("inline workflow defaults",
             "defaults: *d\njobs:\n  gate:\n    steps:\n      - name: P\n"),
            ("aliased defaults.run",
             "jobs:\n  gate:\n    defaults:\n      run: *r\n    steps:\n      - name: P\n"),
            ("inline job container",
             "jobs:\n  gate:\n    container: {image: x, env: {A: 1}}\n"
             "    steps:\n      - name: P\n"),
            ("aliased job container",
             "jobs:\n  gate:\n    container: *c\n    steps:\n      - name: P\n"),
            ("anchored job container",
             "jobs:\n  gate:\n    container: &c\n      image: x\n"
             "    steps:\n      - name: P\n"),
            ("inline container env",
             "jobs:\n  gate:\n    container:\n      image: x\n      env: {A: 1}\n"
             "    steps:\n      - name: P\n"),
            ("merge key inside a container",
             "jobs:\n  gate:\n    container:\n      <<: *c\n    steps:\n      - name: P\n"),
            ("container env entry this reader cannot name",
             "jobs:\n  gate:\n    container:\n      image: x\n      env:\n"
             "        0BAD: 1\n    steps:\n      - name: P\n"),
            ("second document",
             "jobs:\n  gate:\n    steps:\n      - name: P\n---\njobs:\n  gate:\n"
             "    steps:\n      - name: Q\n"),
        ):
            with self.subTest(shape=label):
                with self.assertRaises(AssertionError) as caught:
                    _parse_synthetic(text)
                self.assertIn("cannot resolve", str(caught.exception))

    def test_the_reader_reads_every_env_scope_rule_two_depends_on(self):
        """All four scopes resolve, and the container shorthand is not refused.

        Rule 2's scopes are `container.env`, the workflow-level `env:`, a job's
        `env:`, and a step's own. Three of them went unread until the 0.1.49
        round-4 audit, so this is the reader-level half of that repair: if the
        reader drops a scope, the rule cannot refuse in it no matter what the
        rule says.

        The two shorthand controls are the other half. `container:` carries a
        scalar form -- an image reference, or an expression naming one -- and
        neither can hide an `env:`. Refusing them would be a false red with NO
        lift path, because a reader refusal is not liftable, so the shorthand
        is recognised positively rather than pattern-excluded.
        """
        workflow = _parse_synthetic(
            "env:\n"
            "  WORKFLOW_KEY: a\n"
            "jobs:\n"
            "  gate:\n"
            "    container:\n"
            "      image: ghcr.io/owner/image@sha256:abc\n"
            "      env:\n"
            "        CONTAINER_KEY: b\n"
            "    env:\n"
            "      JOB_KEY: c\n"
            "    steps:\n"
            "      - name: Probe\n"
            "        env:\n"
            "          STEP_KEY: d\n"
        )
        job = workflow.jobs["gate"]
        self.assertEqual(sorted(workflow.env), ["WORKFLOW_KEY"])
        self.assertEqual(sorted(job.container_env), ["CONTAINER_KEY"])
        self.assertEqual(sorted(job.env), ["JOB_KEY"])
        self.assertEqual(sorted(job.steps[0].env), ["STEP_KEY"])
        for label, shorthand in (
            ("an image reference", "container: ubuntu:24.04"),
            ("a digest-pinned reference", "container: ghcr.io/o/i@sha256:abc"),
            ("an expression", "container: ${{ needs.a.outputs.image }}"),
        ):
            with self.subTest(shorthand=label):
                plain = _parse_synthetic(
                    f"jobs:\n  gate:\n    {shorthand}\n"
                    f"    steps:\n      - name: Probe\n        run: true\n"
                )
                self.assertEqual(plain.jobs["gate"].container_env, {})

    def test_a_reader_refusal_is_not_liftable_by_the_allowlist(self):
        """Pin the promise the three documents used to get wrong.

        A READER refusal raises while the file is being resolved, before any
        rule consults `self.allowlist`, so no allowlist line can lift it and no
        lift line is printed with it. That is correct -- an entry waives a
        rule's verdict about a RESOLVED value, and silencing a construct nobody
        can state the meaning of is the silent pass this reader was inverted to
        remove -- but the module docstring said "Every refusal lifts through",
        the allowlist header said the same of its own two examples, and both
        were wrong. Documentation drifts; this test does not.

        Both of the header's former examples are driven here, WITH the exact
        entry that would lift a rule refusal of the same subject, and the
        quoted-template control proves the boundary is the RESOLUTION and not
        the construct: `shell: "bash -e {0}"` resolves, so its refusal is a rule
        refusal, prints a lift line, and lifts.
        """
        for label, method, text, entry in (
            ("`${{ }}` on continue-on-error", "test_no_required_check_continues_on_error",
             "jobs:\n  application:\n    continue-on-error: ${{ true }}\n"
             "    steps:\n      - name: Probe\n        run: true\n",
             ("pr-gate.yml", "continue-on-error", "application")),
            ("an unquoted shell template", "test_no_gate_step_sets_a_custom_shell",
             "jobs:\n  application:\n    steps:\n      - name: Probe\n"
             "        shell: bash -e {0}\n",
             ("pr-gate.yml", "custom-shell", "application/Probe")),
        ):
            for case, allowlist in (("no entry", None), ("with the exact entry",
                                                         {entry: "a written reason"})):
                with self.subTest(refusal=label, allowlist=case):
                    with self.assertRaises(AssertionError) as caught:
                        self._drive(method, text, allowlist)
                    message = str(caught.exception)
                    self.assertIn("cannot resolve", message)
                    self.assertIn("NOT liftable", message)
                    self.assertNotIn("To lift this refusal", message)
        quoted = (
            'jobs:\n  application:\n    steps:\n      - name: Probe\n'
            '        shell: "bash -e {0}"\n'
        )
        refusal = self._drive("test_no_gate_step_sets_a_custom_shell", quoted)
        self.assertIn("To lift this refusal", refusal)
        self.assertEqual(
            self._drive(
                "test_no_gate_step_sets_a_custom_shell", quoted,
                {("pr-gate.yml", "custom-shell", "application/Probe"): "a written reason"},
            ),
            "",
            "a resolved value's refusal must still lift through one line",
        )

    def test_a_job_that_declares_steps_must_resolve_some(self):
        """The silent zero-step job, closed at the reader rather than the test.

        A job whose `steps:` resolves to nothing is invisible to all three
        rules while still counting as a job, and the anti-vacuity test above
        can only see it if the reader hands it over. So the reader refuses it,
        and a reusable-workflow job -- `uses:` at job level, no `steps:` key at
        all -- must NOT be refused, which is the whole reason the predicate is
        `declares_steps` rather than "has steps".
        """
        with self.assertRaises(AssertionError) as caught:
            _parse_synthetic("jobs:\n  application:\n    steps:\n    runs-on: x\n")
        self.assertIn("cannot resolve", str(caught.exception))
        self.assertIn("resolved none", str(caught.exception))
        reusable = _parse_synthetic(
            "jobs:\n  call:\n    uses: ./.github/workflows/other.yml\n"
            "  application:\n    steps:\n      - name: Probe\n        run: true\n"
        )
        self.assertFalse(reusable.jobs["call"].declares_steps)
        self.assertEqual(reusable.jobs["call"].steps, [])
        self.assertTrue(reusable.jobs["application"].declares_steps)

    def test_the_step_floor_still_bites_on_a_job_the_reader_cannot_produce(self):
        """Drive the per-job floor over a state the READER now refuses to emit.

        `test_every_workflow_resolves_into_jobs_and_steps` asserts, per job,
        that a job which declared `steps:` resolved some. The reader refuses a
        declared-but-empty `steps:` outright (the test above), so NO workflow
        text can reach that assertion any more -- which would leave it
        decorative and its deletion undetectable, the exact surviving-mutant
        class these reviews keep finding. Constructing the `Job` directly is
        the honest way to prove it still bites: it is the same shadow-the-
        instance seam `_drive` uses for the three rules, and it drives the
        SHIPPED assertion rather than a copy of it.
        """
        probe = WorkflowIntegrityTests("test_every_workflow_resolves_into_jobs_and_steps")
        hollow = Workflow(path=WORKFLOWS / "pr-gate.yml")
        hollow.jobs["application"] = Job(name="application", line=1, declares_steps=True)
        probe.workflows = [hollow]
        with self.assertRaises(probe.failureException) as caught:
            probe.test_every_workflow_resolves_into_jobs_and_steps()
        self.assertIn("resolved none", str(caught.exception))
        # Positive control, both directions: the floor passes once that job
        # resolves a step, AND a reusable-workflow job that declares none is
        # never asked to -- which is why `all(job.steps ...)` would be wrong.
        hollow.jobs["application"].steps.append(Step(name="Probe", line=2))
        hollow.jobs["call"] = Job(name="call", line=3)
        probe.test_every_workflow_resolves_into_jobs_and_steps()

    # The subjects that are NOT a step's name, because the construct they
    # address is not written inside a step. Every one of them is a string an
    # operator types by hand into the allowlist.
    SENTINEL_SUBJECTS = {
        "DEFAULT_SHELL_SUBJECT": (DEFAULT_SHELL_SUBJECT, "<defaults.run.shell>"),
        "WORKFLOW_ENV_SUBJECT": (WORKFLOW_ENV_SUBJECT, "<workflow.env>"),
        "JOB_ENV_SUBJECT": (JOB_ENV_SUBJECT, "<job.env>"),
        "CONTAINER_ENV_SUBJECT": (CONTAINER_ENV_SUBJECT, "<container.env>"),
    }

    def test_every_sentinel_subject_is_the_spelling_the_allowlist_documents(self):
        """Code and lift file must agree on every subject an operator types.

        These are the `<where>` spellings for the constructs no step name can
        address -- rule 3's two `defaults.run.shell` positions and rule 2's
        three non-step env scopes. Renaming a constant would move the rule and
        its own fixtures together and leave the allowlist header -- the thing a
        human reads before typing the line -- documenting a spelling nothing
        accepts. This is a parity pin, not an inventory: it names the sentinel
        subjects only, and adding a STEP-addressed subject needs no edit here.
        """
        # A floor, never a count: emptying the table would make both loops
        # vacuous and their deletion undetectable.
        self.assertTrue(self.SENTINEL_SUBJECTS, "the sentinel-subject table is empty")
        text = ALLOWLIST.read_text(encoding="utf-8")
        for constant, (value, spelling) in self.SENTINEL_SUBJECTS.items():
            with self.subTest(subject=constant):
                self.assertEqual(value, spelling)
                self.assertIn(
                    value,
                    text,
                    f"{ALLOWLIST.relative_to(ROOT)} does not document the "
                    f"`{value}` subject its readers have to type.",
                )

    def test_an_unrecognised_way_of_writing_true_is_refused(self):
        """The inversion, stated as a test: refuse what you cannot resolve.

        Three review rounds found "another valid form evades the reader", and
        enumerating forms is why -- a hand-rolled YAML subset that recognises
        the spellings of `true` somebody listed, and treats everything else as
        "not true", leaks by construction. The default is the defect.

        So the reader now refuses any scalar outside a small, explicit set, and
        this table is the proof: none of these rows has a branch in this file,
        and every one of them raises. Add another exotic-but-valid spelling
        here and it goes red with NO code change -- that is the property being
        pinned, not the twelve particular rows.
        """
        # A floor, never a count: emptying the table would make the loop
        # vacuous and its deletion undetectable, which is the exact
        # surviving-mutant class the 0.1.49 reviews kept finding. Adding rows
        # needs no edit here.
        self.assertTrue(self.UNRECOGNISED_TRUE_SPELLINGS, "the spelling table is empty")
        for label, construct in self.UNRECOGNISED_TRUE_SPELLINGS.items():
            for position, text in (
                ("job", "jobs:\n  application:\n    " + construct
                        + "    steps:\n      - name: Probe\n        run: true\n"),
                ("step", "jobs:\n  application:\n    steps:\n      - name: Probe\n"
                         "        " + construct),
            ):
                with self.subTest(spelling=label, position=position):
                    with self.assertRaises(AssertionError) as caught:
                        _parse_synthetic(text)
                    self.assertIn("cannot resolve", str(caught.exception))

    def test_rule_one_resolves_every_spelling_it_does_recognise(self):
        """The positive control, and the other half of rule 1's totality.

        Without this the test above could pass on a reader that refuses every
        `continue-on-error` ever written, which would be a gate nobody can use
        and would hide a rule that no longer fires. Between the two tables
        every input either refuses or resolves to one of exactly two booleans:
        `true` in any casing or quoting REFUSES, `false` and a bare null PASS.
        """
        self.assertTrue(self.RECOGNISED_BOOLEANS, "the recognised-boolean table is empty")
        self.assertIn(True, self.RECOGNISED_BOOLEANS.values(), "no refusing spelling")
        self.assertIn(False, self.RECOGNISED_BOOLEANS.values(), "no passing spelling")
        for spelling, expected in self.RECOGNISED_BOOLEANS.items():
            with self.subTest(spelling=spelling):
                job = _parse_synthetic(
                    f"jobs:\n  application:\n    continue-on-error: {spelling}\n"
                    f"    steps:\n      - name: Probe\n        run: true\n"
                ).jobs["application"]
                self.assertEqual(job.continue_on_error, (expected, 3))
                refused = bool(
                    self._drive(
                        "test_no_required_check_continues_on_error",
                        f"jobs:\n  application:\n    continue-on-error: {spelling}\n"
                        f"    steps:\n      - name: Probe\n        run: true\n",
                    )
                )
                self.assertEqual(refused, expected, "the rule disagreed with the reader")
        # A bare `continue-on-error:` with nothing under it is YAML null, which
        # is falsy in every parser and in the runner. It must NOT false-red --
        # the fail-closed repair has to distinguish "no value" from "a value
        # this reader cannot see", and this is the boundary between them.
        job = _parse_synthetic(
            "jobs:\n  application:\n    continue-on-error:\n"
            "    steps:\n      - name: Probe\n        run: true\n"
        ).jobs["application"]
        self.assertEqual(job.continue_on_error, (False, 3))

    def test_a_run_block_heredoc_is_not_a_merge_key(self):
        """The positive control for the merge-key refusal.

        `release-after-main.yml` is full of `jq … <<<"${x}"` inside `run:`
        blocks. Block-scalar skipping must keep those out of the reader, or the
        refusal above would red the suite on shell text. The real sweep in
        `setUpClass` covers this, but only while those files keep that shape.
        """
        job = _parse_synthetic(
            "jobs:\n  gate:\n    steps:\n      - name: Probe\n        run: |\n"
            '          class="$(jq -er .class <<<"${verdict}")"\n'
        ).jobs["gate"]
        self.assertEqual([step.name for step in job.steps], ["Probe"])

    # -- every rule must be REACHABLE, not merely correct --------------------

    def _drive(self, method: str, text: str, allowlist=None) -> str:
        """Run ONE shipped rule over a synthetic workflow; return its message.

        Returns the refusal message, or `""` when the rule passed -- a plain
        `str` rather than `str | None` so callers can assert on the message
        without an Optional narrowing dance a type checker does not follow.

        `parse_workflow(..., WORKFLOWS / "pr-gate.yml")` is the whole seam: the
        path decides `required_jobs()`, so a synthetic job named like a real
        required one lands inside the set the rules are scoped by. Shadowing
        `workflows` and `allowlist` on a fresh instance drives the SHIPPED rule
        methods rather than a copy of their logic -- a reimplementation here
        would pass while the real rule was deleted, which is the very failure
        these fixtures exist to close. No production code exists to make this
        reachable.
        """
        probe = WorkflowIntegrityTests(method)
        probe.workflows = [parse_workflow(text, WORKFLOWS / "pr-gate.yml")]
        probe.allowlist = {} if allowlist is None else allowlist
        try:
            getattr(probe, method)()
        except probe.failureException as failure:
            return str(failure)
        return ""

    # `application` is a real `EXPECTED_MAIN_JOBS` entry, so these fixtures are
    # inside the required-checks set exactly as a real offending job would be.
    CONTINUE_ON_ERROR_JOB = (
        "jobs:\n  application:\n    continue-on-error: true\n"
        "    steps:\n      - name: Probe\n        run: exit 1\n"
    )
    CONTINUE_ON_ERROR_STEP = (
        "jobs:\n  application:\n    steps:\n"
        "      - name: Probe\n        continue-on-error: true\n        run: exit 1\n"
    )
    ENV_SHADOW = (
        "jobs:\n  application:\n    env:\n      GO_COVERAGE_FLOOR: 93.2\n"
        "    steps:\n      - name: Probe\n        env:\n          GO_COVERAGE_FLOOR: 0\n"
    )
    ENV_PINNED_TOOL = (
        "jobs:\n  application:\n    steps:\n"
        "      - name: Probe\n        env:\n          GITLEAKS_VERSION: 0.0.0\n"
    )
    # Rule 2's construct written where no STEP carries it. All three were live
    # on the real `release-publisher.yml` at `actionlint` rc=0 until this round;
    # the container scope is the outermost one, reached by every `run:` step in
    # the job.
    WORKFLOW_ENV_PINNED_TOOL = (
        "env:\n  TRIVY_SHA256: '0'\n"
        "jobs:\n  application:\n    steps:\n      - name: Probe\n        run: true\n"
    )
    JOB_ENV_SHADOW = (
        "env:\n  SOURCE_SHA: outer\n"
        "jobs:\n  application:\n    env:\n      SOURCE_SHA: inner\n"
        "    steps:\n      - name: Probe\n        run: true\n"
    )
    JOB_ENV_PINNED_TOOL = (
        "jobs:\n  application:\n    env:\n      GITLEAKS_VERSION: '0'\n"
        "    steps:\n      - name: Probe\n        run: true\n"
    )
    CONTAINER_ENV_PINNED_TOOL = (
        "jobs:\n  application:\n    container:\n      image: ubuntu:24.04\n"
        "      env:\n        HELM_VERSION: '0'\n"
        "    steps:\n      - name: Probe\n        run: true\n"
    )
    JOB_ENV_SHADOWS_CONTAINER = (
        "jobs:\n  application:\n    container:\n      image: ubuntu:24.04\n"
        "      env:\n        SOURCE_SHA: from-the-container\n"
        "    env:\n      SOURCE_SHA: from-the-job\n"
        "    steps:\n      - name: Probe\n        run: true\n"
    )
    # The step-against-container pair, which the job-against-container pair
    # above does NOT cover: the step loop compares against three outer scopes
    # and dropping the container one from it survived the first sweep of this
    # commit. Each scope PAIR needs its own row, not each scope.
    STEP_ENV_SHADOWS_CONTAINER = (
        "jobs:\n  application:\n    container:\n      image: ubuntu:24.04\n"
        "      env:\n        SOURCE_SHA: from-the-container\n"
        "    steps:\n      - name: Probe\n        env:\n"
        "          SOURCE_SHA: from-the-step\n"
    )
    CUSTOM_SHELL = (
        "jobs:\n  application:\n    steps:\n      - name: Probe\n        shell: sh\n"
    )
    # Rule 3's construct written where no step carries it. Both positions pass
    # `actionlint` at rc=0 and both reshell every `run:` step beneath them.
    JOB_DEFAULT_SHELL = (
        "jobs:\n  application:\n    defaults:\n      run:\n        shell: sh\n"
        "    steps:\n      - name: Probe\n        run: true\n"
    )
    WORKFLOW_DEFAULT_SHELL = (
        "defaults:\n  run:\n    shell: sh\n"
        "jobs:\n  application:\n    steps:\n      - name: Probe\n        run: true\n"
    )
    CLEAN = "jobs:\n  application:\n    steps:\n      - name: Probe\n        run: true\n"

    def test_every_rule_refuses_its_own_construct(self):
        """Drive all three rules to an actual refusal.

        Every workflow in this repository is clean, so before this fixture NO
        input reached any of the three `self.fail` calls -- each rule could be
        DELETED OUTRIGHT with the suite staying green. The rules were correct
        (mutating the real workflows proved each fires) but their removal was
        undetectable, which is not a gate, it is a comment.

        This is the same gap `test_the_reader_sees_a_real_step_key` closed one
        layer down for the reader's inner-`name:` branch. It was found there
        and not extended upward; the 0.1.49 review caught that, and these
        fixtures are the extension.
        """
        for label, method, text, expected in (
            ("rule 1 / job", "test_no_required_check_continues_on_error",
             self.CONTINUE_ON_ERROR_JOB, "continue-on-error"),
            ("rule 1 / step", "test_no_required_check_continues_on_error",
             self.CONTINUE_ON_ERROR_STEP, "continue-on-error"),
            ("rule 2 / shadows job env", "test_no_step_env_shadows_an_outer_declaration",
             self.ENV_SHADOW, "shadows the job-level declaration"),
            ("rule 2 / redeclares a tool pin", "test_no_step_env_shadows_an_outer_declaration",
             self.ENV_PINNED_TOOL, "redeclares a tool pin"),
            ("rule 2 / workflow env tool pin",
             "test_no_step_env_shadows_an_outer_declaration",
             self.WORKFLOW_ENV_PINNED_TOOL, "workflow-level `env: TRIVY_SHA256`"),
            ("rule 2 / job env shadows workflow env",
             "test_no_step_env_shadows_an_outer_declaration",
             self.JOB_ENV_SHADOW, "shadows the workflow-level declaration"),
            ("rule 2 / job env tool pin", "test_no_step_env_shadows_an_outer_declaration",
             self.JOB_ENV_PINNED_TOOL, "job-level `env: GITLEAKS_VERSION`"),
            ("rule 2 / container env tool pin",
             "test_no_step_env_shadows_an_outer_declaration",
             self.CONTAINER_ENV_PINNED_TOOL, "container-level `env: HELM_VERSION`"),
            ("rule 2 / job env shadows container env",
             "test_no_step_env_shadows_an_outer_declaration",
             self.JOB_ENV_SHADOWS_CONTAINER, "shadows the container-level declaration"),
            ("rule 2 / step env shadows container env",
             "test_no_step_env_shadows_an_outer_declaration",
             self.STEP_ENV_SHADOWS_CONTAINER, "shadows the container-level declaration"),
            ("rule 3 / custom shell", "test_no_gate_step_sets_a_custom_shell",
             self.CUSTOM_SHELL, "shell: sh"),
            ("rule 3 / job defaults", "test_no_gate_step_sets_a_custom_shell",
             self.JOB_DEFAULT_SHELL, "defaults.run.shell: sh"),
            ("rule 3 / workflow defaults", "test_no_gate_step_sets_a_custom_shell",
             self.WORKFLOW_DEFAULT_SHELL, "at workflow level"),
        ):
            with self.subTest(rule=label):
                message = self._drive(method, text)
                self.assertTrue(message, "the rule did not refuse its own construct")
                self.assertIn(expected, message)
                # The lift path must be printed with the refusal, or the next
                # agent's only route past a correct refusal is to weaken it.
                self.assertIn("To lift this refusal", message)

    def test_a_shadow_names_the_innermost_declaration_it_hides(self):
        """The scope ORDER is load-bearing, so it is pinned rather than assumed.

        A key declared at several outer scopes is shadowed by the INNERMOST of
        them -- that is the declaration whose value the inner one actually
        replaces, and the only line worth sending a reader to. The rule reports
        the first match in an ordered list, so reordering that list silently
        points at the wrong line while every other assertion in this file stays
        green. It survived the first mutation sweep of this commit in both
        directions, which is exactly why it is a test now: `scopes` carries an
        ORDER, and an order nothing checks is a comment.
        """
        step = self._drive(
            "test_no_step_env_shadows_an_outer_declaration",
            "env:\n"                      # 1
            "  SOURCE_SHA: from-workflow\n"   # 2
            "jobs:\n"                     # 3
            "  application:\n"            # 4
            "    env:\n"                  # 5
            "      SOURCE_SHA: from-job\n"    # 6
            "    steps:\n"                # 7
            "      - name: Probe\n"       # 8
            "        env:\n"              # 9
            "          SOURCE_SHA: from-step\n",  # 10
            # The job-level declaration is itself a shadow of the workflow one
            # and is refused first; exempting it is what lets the STEP-level
            # verdict surface, and it exercises the interaction while it is
            # here. Each scope keeps its own entry -- one does not lift another.
            {("pr-gate.yml", "env-shadow", f"application/{JOB_ENV_SUBJECT}/SOURCE_SHA"):
             "so the step-level verdict below is the one under test"},
        )
        self.assertIn("step-level `env: SOURCE_SHA`", step)
        self.assertIn("shadows the job-level declaration at line 6", step)
        job = self._drive(
            "test_no_step_env_shadows_an_outer_declaration",
            "env:\n"                              # 1
            "  SOURCE_SHA: from-workflow\n"       # 2
            "jobs:\n"                             # 3
            "  application:\n"                    # 4
            "    container:\n"                    # 5
            "      image: ubuntu:24.04\n"         # 6
            "      env:\n"                        # 7
            "        SOURCE_SHA: from-container\n"    # 8
            "    env:\n"                          # 9
            "      SOURCE_SHA: from-job\n"        # 10
            "    steps:\n"                        # 11
            "      - name: Probe\n"               # 12
            "        run: true\n",                # 13
        )
        self.assertIn("job-level `env: SOURCE_SHA`", job)
        self.assertIn("shadows the workflow-level declaration at line 2", job)

    def test_no_rule_refuses_a_clean_workflow(self):
        """The positive control: these fixtures fail for their construct only.

        Without this, a rule mutated into always-failing would satisfy every
        assertion above and look like proof.
        """
        for method in (
            "test_no_required_check_continues_on_error",
            "test_no_step_env_shadows_an_outer_declaration",
            "test_no_gate_step_sets_a_custom_shell",
        ):
            with self.subTest(rule=method):
                self.assertEqual(self._drive(method, self.CLEAN), "")

    def test_the_allowlist_lifts_every_rule(self):
        """Each refusal above must clear through one allowlist line, and only
        through the line that names it.

        A lift path nobody exercises is a lift path that turns out to be broken
        on the day a real refusal needs it -- the sibling repository shipped
        exactly that, an allowlist pinned so the documented lift reddened the
        suite.
        """
        for label, method, text, entry in (
            ("rule 1 / job", "test_no_required_check_continues_on_error",
             self.CONTINUE_ON_ERROR_JOB, ("pr-gate.yml", "continue-on-error", "application")),
            ("rule 1 / step", "test_no_required_check_continues_on_error",
             self.CONTINUE_ON_ERROR_STEP,
             ("pr-gate.yml", "continue-on-error", "application/Probe")),
            ("rule 2 / shadow", "test_no_step_env_shadows_an_outer_declaration",
             self.ENV_SHADOW,
             ("pr-gate.yml", "env-shadow", "application/Probe/GO_COVERAGE_FLOOR")),
            ("rule 2 / workflow env", "test_no_step_env_shadows_an_outer_declaration",
             self.WORKFLOW_ENV_PINNED_TOOL,
             ("pr-gate.yml", "env-shadow", f"{WORKFLOW_ENV_SUBJECT}/TRIVY_SHA256")),
            ("rule 2 / job env", "test_no_step_env_shadows_an_outer_declaration",
             self.JOB_ENV_SHADOW,
             ("pr-gate.yml", "env-shadow", f"application/{JOB_ENV_SUBJECT}/SOURCE_SHA")),
            ("rule 2 / container env", "test_no_step_env_shadows_an_outer_declaration",
             self.CONTAINER_ENV_PINNED_TOOL,
             ("pr-gate.yml", "env-shadow",
              f"application/{CONTAINER_ENV_SUBJECT}/HELM_VERSION")),
            ("rule 3 / shell", "test_no_gate_step_sets_a_custom_shell",
             self.CUSTOM_SHELL, ("pr-gate.yml", "custom-shell", "application/Probe")),
            ("rule 3 / job defaults", "test_no_gate_step_sets_a_custom_shell",
             self.JOB_DEFAULT_SHELL,
             ("pr-gate.yml", "custom-shell", f"application/{DEFAULT_SHELL_SUBJECT}")),
            ("rule 3 / workflow defaults", "test_no_gate_step_sets_a_custom_shell",
             self.WORKFLOW_DEFAULT_SHELL,
             ("pr-gate.yml", "custom-shell", DEFAULT_SHELL_SUBJECT)),
        ):
            with self.subTest(rule=label):
                self.assertTrue(self._drive(method, text), "not refused without the entry")
                self.assertEqual(
                    self._drive(method, text, {entry: "a written reason"}),
                    "",
                    "the exempting entry did not lift the refusal",
                )
                wrong = (entry[0], entry[1], entry[2] + "-not-this-one")
                self.assertTrue(
                    self._drive(method, text, {wrong: "a written reason"}),
                    "an entry naming a DIFFERENT subject lifted this refusal",
                )

    # -- rule 1: continue-on-error ------------------------------------------

    def test_no_required_check_continues_on_error(self):
        """`continue-on-error: true` turns a red required gate green."""
        for workflow in self.workflows:
            for name in sorted(required_jobs(workflow)):
                job = workflow.jobs[name]
                self._refuse_continue_on_error(workflow, job.continue_on_error, name)
                for step in job.steps:
                    self._refuse_continue_on_error(
                        workflow, step.continue_on_error, f"{name}/{step.name}"
                    )

    def _refuse_continue_on_error(self, workflow, keyed, where):
        # `keyed` carries a BOOLEAN the reader already resolved -- or the reader
        # raised. There is no text normalisation left to do here, and that is
        # the point: every "another spelling of true" this gate leaked came
        # from comparing text at this line instead of resolving it at the
        # reader. `None` means the key is absent; `False` covers `false` in any
        # casing and a bare `continue-on-error:` (YAML null).
        if keyed is None:
            return
        value, line = keyed
        if not value:
            return
        if (workflow.name, "continue-on-error", where) in self.allowlist:
            return
        self.fail(
            f"{workflow.path.relative_to(ROOT)}:{line}: `continue-on-error: true` on "
            f"{where}, which is in the required-checks set the release publisher "
            f"authorizes against. A job that fails but continues still reports "
            f"`success`, so this converts a red gate into a green one with no "
            f"other visible change."
            + lift_instruction(workflow.name, "continue-on-error", where)
        )

    # -- rule 2: env shadowing ----------------------------------------------

    def test_no_step_env_shadows_an_outer_declaration(self):
        """Innermost scope wins silently, so a shadowed pin reads correct.

        FOUR scopes, not one. Until the 0.1.49 round-4 audit this rule read
        `step.env` and nothing else, so its own construct written one and two
        scopes OUT was invisible: on the real `release-publisher.yml` -- the
        only workflow here with both an outer `env:` and a job `env:`
        populated -- a job-level `env: IMAGE` shadowing the workflow-level
        declaration, a job-level `env: GITLEAKS_VERSION`, and a workflow-level
        `env: TRIVY_SHA256` were all GREEN at `actionlint` rc=0, while the
        identical key one scope deeper went red. That is the same defect round
        3 found in rule 3, in a different rule.

        The scopes, outermost first, are `container.env`, the workflow-level
        `env:`, a job's `env:`, and a step's own; the module docstring's scope
        audit says why those four and why `services.<id>.env` is not one. Each
        is compared against the scopes OUTSIDE it for shadowing, and all four
        against the tool pins, since a pin redeclared at any scope reaches the
        shell that reads it.
        """
        pinned = pinned_tool_variables()
        self.assertTrue(pinned, "no pinned tool variables read from install-tools.sh")
        for workflow in self.workflows:
            for key, line in sorted(workflow.env.items()):
                # Nothing is outside the workflow scope, so this one is checked
                # for the tool-pin half alone.
                self._refuse_env(
                    workflow, f"{WORKFLOW_ENV_SUBJECT}/{key}", key, line, (), pinned,
                    "workflow", "every step of every job here",
                )
            for job_name, job in workflow.jobs.items():
                for key, line in sorted(job.container_env.items()):
                    # The outermost scope: a step's own environment overrides
                    # it, so it shadows nothing and is checked the same way.
                    self._refuse_env(
                        workflow, f"{job_name}/{CONTAINER_ENV_SUBJECT}/{key}", key, line,
                        (), pinned, "container",
                        f"every `run:` step in job {job_name!r}",
                    )
                for key, line in sorted(job.env.items()):
                    self._refuse_env(
                        workflow, f"{job_name}/{JOB_ENV_SUBJECT}/{key}", key, line,
                        (("workflow", workflow.env), ("container", job.container_env)),
                        pinned, "job", f"every step in job {job_name!r}",
                    )
                for step in job.steps:
                    for key, line in sorted(step.env.items()):
                        # Ordered innermost-outer first, so a key declared at
                        # several outer scopes reports the one actually being
                        # shadowed -- or the message points at the wrong line.
                        self._refuse_env(
                            workflow, f"{job_name}/{step.name}/{key}", key, line,
                            (("job", job.env), ("workflow", workflow.env),
                             ("container", job.container_env)),
                            pinned, "step", "this step",
                        )

    def _refuse_env(self, workflow, where, key, line, scopes, pinned, inner, blast):
        """Refuse one `env:` key at one scope, or return.

        `scopes` is the ordered list of scopes OUTSIDE this one, innermost
        first; `inner` names this scope and `blast` its radius, so the message
        reads the same at every scope while telling the truth about how far the
        shadow reaches. One allowlist entry lifts both halves for that key at
        that scope, which is the shape the step-level rule already had.
        """
        if (workflow.name, "env-shadow", where) in self.allowlist:
            return
        for scope, declared in scopes:
            if key in declared:
                self.fail(
                    f"{workflow.path.relative_to(ROOT)}:{line}: {inner}-level "
                    f"`env: {key}` shadows the {scope}-level declaration at "
                    f"line {declared[key]}. The inner value wins silently, so "
                    f"{blast} can run against a value no reader of the "
                    f"outer declaration would expect -- while the outer "
                    f"declaration still reads correct."
                    + lift_instruction(workflow.name, "env-shadow", where)
                )
        if key in pinned:
            self.fail(
                f"{workflow.path.relative_to(ROOT)}:{line}: {inner}-level "
                f"`env: {key}` redeclares a tool pin that "
                f"`scripts/ci/install-tools.sh` owns. A workflow that "
                f"sets a pinned version or checksum name can run an "
                f"unpinned tool while the pin in install-tools.sh "
                f"still reads correct."
                + lift_instruction(workflow.name, "env-shadow", where)
            )

    # -- rule 3: custom shell ------------------------------------------------

    def test_no_gate_step_sets_a_custom_shell(self):
        """A custom shell changes failure semantics under `set -euo pipefail`.

        Three positions, not one. `defaults.run.shell` at workflow or job level
        reshells EVERY `run:` step beneath it and is the same construct written
        where no step carries it; both positions pass `actionlint` at rc=0 and
        both left this rule green until the 0.1.49 round-3 audit.
        """
        for workflow in self.workflows:
            required = sorted(required_jobs(workflow))
            if required and workflow.default_shell is not None:
                # Workflow-level defaults reach every job, so any required job
                # at all makes this in scope; the subject carries no job name
                # because the construct is not written inside one.
                shell, line = workflow.default_shell
                self._refuse_shell(
                    workflow, shell, line, DEFAULT_SHELL_SUBJECT,
                    f"`defaults.run.shell: {shell}` at workflow level, which replaces "
                    f"the runner default for every `run:` step in every job -- "
                    f"including the required-checks jobs {', '.join(required)}",
                )
            for name in required:
                job = workflow.jobs[name]
                if job.default_shell is not None:
                    shell, line = job.default_shell
                    self._refuse_shell(
                        workflow, shell, line, f"{name}/{DEFAULT_SHELL_SUBJECT}",
                        f"`defaults.run.shell: {shell}` on required-checks job "
                        f"{name!r}, which replaces the runner default for every "
                        f"`run:` step in it",
                    )
                for step in job.steps:
                    if step.shell is None:
                        continue
                    shell, line = step.shell
                    self._refuse_shell(
                        workflow, shell, line, f"{name}/{step.name}",
                        f"step {step.name!r} in required-checks job {name!r} sets "
                        f"`shell: {shell}`",
                    )

    def _refuse_shell(self, workflow, shell, line, where, subject):
        if (workflow.name, "custom-shell", where) in self.allowlist:
            return
        self.fail(
            f"{workflow.path.relative_to(ROOT)}:{line}: {subject}. The "
            f"runner default is `bash -e {{0}}` and this repository opens every "
            f"`run:` block with `set -euo pipefail`; a custom shell changes "
            f"failure semantics underneath that convention -- `sh` has no "
            f"`pipefail`, so a failing command mid-pipeline stops failing the "
            f"step."
            + lift_instruction(workflow.name, "custom-shell", where)
        )

    def test_the_go_toolchain_check_refuses_an_older_installed_compiler(self):
        """The toolchain check must fail on the compiler the Go steps would use.

        go.mod's `toolchain` line makes the default auto mode fetch that
        release for `go env GOVERSION` alone, so a check in auto mode passes
        while every `GOTOOLCHAIN: local` step builds and tests with an older
        installed compiler (#367 review). Text cannot show that a check
        enforces anything: a commented-out or `|| true` assertion reads the
        same. So every `run:` block that reads GOVERSION is executed as the
        runner executes a step with no `shell:`, `bash -e {0}`, against a
        stand-in `go` that reports the installed compiler in local mode and
        go.mod's toolchain in auto mode. A step, job or workflow shell is
        refused rather than imitated. The block must pass with exactly that
        toolchain installed and fail with every other release of its train
        below it, the next patch and minor, the bare minor, and go1.0; and
        pr-gate.yml, which the release publisher authorizes against, must keep
        one.
        """
        declared = re.search(r"^toolchain go(\d+)\.(\d+)\.(\d+)$", (ROOT / "go.mod").read_text(), re.M)
        if declared is None:
            self.fail("go.mod names no toolchain of the form goX.Y.Z")
        major, minor, patch = map(int, declared.groups())
        toolchain = f"go{major}.{minor}.{patch}"
        others = [f"go{major}.{minor}.{earlier}" for earlier in range(patch)] + [
            f"go{major}.{minor}.{patch + 1}", f"go{major}.{minor + 1}.0", f"go{major}.{minor}", "go1.0",
        ]
        checks: dict[str, int] = {}
        for path in workflow_paths():
            text = path.read_text()
            workflow = read_workflow(path)
            covered: set[int] = set()
            for lineno, length, block in run_blocks(text):
                covered.update(range(lineno, lineno + length + 1))
                if "GOVERSION" not in block:
                    continue
                where = f"{path.relative_to(ROOT)}:{lineno}"
                shell = self._declared_shell(workflow, lineno)
                if shell is not None:
                    self.fail(f"{where}: the step runs under `shell: {shell}`; this test executes only the "
                              f"runner default, `bash -e {{0}}`")
                self.assertEqual(
                    self._run_toolchain_check(block, toolchain, toolchain), 0,
                    f"{where}: the toolchain check fails with go.mod's toolchain ({toolchain}) installed",
                )
                accepted = [other for other in others if self._run_toolchain_check(block, other, toolchain) == 0]
                self.assertEqual(
                    accepted, [],
                    f"{where}: the toolchain check passes with {', '.join(accepted)} installed; it must "
                    f"accept exactly {toolchain}, read with GOTOOLCHAIN=local in an assertion that runs "
                    f"and fails the step",
                )
                checks[path.name] = checks.get(path.name, 0) + 1
            for lineno, line in enumerate(text.splitlines(), 1):
                if "GOVERSION" in line and lineno not in covered:
                    self.fail(f"{path.relative_to(ROOT)}:{lineno}: GOVERSION is read outside a "
                              f"`run: |` block this test can execute")
        self.assertTrue(
            checks.get("pr-gate.yml"),
            ".github/workflows/pr-gate.yml no longer checks the installed Go toolchain",
        )

    @staticmethod
    def _holding_step(workflow: Workflow, lineno: int) -> tuple[Job, Step] | None:
        """The job and step that hold line `lineno`: the last step to start at or before it."""
        holder = None
        for job in workflow.jobs.values():
            for step in job.steps:
                if step.line <= lineno and (holder is None or step.line > holder[1].line):
                    holder = (job, step)
        return holder

    @classmethod
    def _declared_shell(cls, workflow: Workflow, lineno: int) -> str | None:
        """The shell the step holding line `lineno` runs under, when anything sets one."""
        holder = cls._holding_step(workflow, lineno)
        if holder is None:
            return None
        job, step = holder
        for declared in (step.shell, job.default_shell, workflow.default_shell):
            if declared is not None:
                return declared[0]
        return None

    def _run_toolchain_check(self, block: str, installed: str, module: str) -> int:
        """Run one `run:` block as the runner runs a step with no `shell:`, with stand-in node, npm and go.

        This repository's toolchain check reads Go alone; the node and npm
        stand-ins answer only if a block ever asks them, so a Node pin added
        later is executed rather than skipped."""
        expected = dict(re.findall(r'\$\((node|npm) --version\)" = "([^"]+)"', block))
        with tempfile.TemporaryDirectory() as scratch:
            stubs = {
                "go": f'[ "$*" = "env GOVERSION" ] || exit 97\n'
                      f'if [ "${{GOTOOLCHAIN:-auto}}" = local ]; then echo {shlex.quote(installed)}; '
                      f'else echo {shlex.quote(module)}; fi\n',
                "node": f"echo {shlex.quote(expected.get('node', ''))}\n",
                "npm": f"echo {shlex.quote(expected.get('npm', ''))}\n",
            }
            for name, body in stubs.items():
                stub = Path(scratch) / name
                stub.write_text("#!/bin/sh\n" + body)
                stub.chmod(0o755)
            script = Path(scratch) / "run.sh"
            script.write_text(block)
            return subprocess.run(
                [shutil.which("bash") or "/bin/bash", "-e", str(script)],
                env={"PATH": f"{scratch}:/usr/bin:/bin", "HOME": scratch},
                capture_output=True,
            ).returncode

    # -- allowlist hygiene ---------------------------------------------------

    def test_a_malformed_allowlist_entry_is_refused(self):
        """The lift mechanism must never degrade into a mute button.

        The allowlist is empty by design, so nothing else in this file drives
        `read_allowlist`'s three refusals -- they were reachable only by
        hand-editing the file they guard, which is a probe nobody re-runs.
        """
        for bad in (
            "pr-gate.yml | continue-on-error | security",  # three fields
            "pr-gate.yml | continue-on-error | security | ",  # blank reason
            "pr-gate.yml | bogus-rule | security | a reason",  # unknown rule
            " |  |  | ",  # every field blank
        ):
            with self.subTest(entry=bad):
                with self.assertRaises(AssertionError):
                    read_allowlist(bad + "\n")
        # Positive control: a well-formed entry still parses, so the loop above
        # cannot pass merely because the parser refuses everything.
        self.assertEqual(
            read_allowlist("pr-gate.yml | custom-shell | security/Probe | a real reason\n"),
            {("pr-gate.yml", "custom-shell", "security/Probe"): "a real reason"},
        )

    # -- issue #225: the contract states the floor the gate enforces ---------

    def test_the_contract_states_the_coverage_floor_ci_actually_enforces(self):
        """Requirement 7's "ONE fact in three places", enforced rather than hoped.

        Nothing read both files before this, and the drift is silent in both
        directions: raise the gate alone and the contract understates what CI
        permits; lower it alone and the contract promises a guarantee CI no
        longer makes. The refusal names every location it read, with the value
        found at each, so the repair needs no re-derivation of the parse.
        """
        declarations = coverage_floor_declarations(self.workflows)
        claims = coverage_floor_claims(agents_text())
        self.assertTrue(
            declarations,
            f"no workflow declares `{COVERAGE_FLOOR_KEY}`; requirement 7's floor is enforced "
            f"nowhere",
        )
        self.assertTrue(
            claims,
            f"AGENTS.md states no `{COVERAGE_FLOOR_KEY}` number; requirement 7's contract must "
            f"state the floor it claims is enforced",
        )
        problems = coverage_floor_disagreements(declarations, claims, self.allowlist)
        self.assertEqual(
            problems,
            [],
            "the coverage floor is not one fact:\n  "
            + "\n  ".join(problems)
            + lift_instruction("pr-gate.yml", "contract-floor", "<the exact claim text above>"),
        )

    def test_the_floor_pin_reddens_on_every_way_the_two_can_disagree(self):
        """A guard that cannot fail is no guard: drive each branch.

        The shipped files agree, so every row below is a synthetic disagreement
        built from them -- which is also the vacuity demonstration the review
        protocol asks for.
        """
        declarations = coverage_floor_declarations(self.workflows)
        agents = agents_text()
        claims = coverage_floor_claims(agents)
        floor = declarations[0].value
        self.assertEqual(coverage_floor_disagreements(declarations, claims), [])

        raised = [
            FloorDeclaration(d.workflow, d.scope, d.line, str(float(d.value) + 1.0))
            for d in declarations
        ]
        problems = coverage_floor_disagreements(raised, claims)
        self.assertTrue(problems, "a raised gate with an unchanged contract passed")
        self.assertIn("AGENTS.md:", problems[0])
        self.assertIn(".github/workflows/", problems[0])

        lowered = coverage_floor_claims(agents.replace(floor, "1.0"))
        self.assertTrue(lowered, "the mutant must still state a floor")
        self.assertTrue(
            coverage_floor_disagreements(declarations, lowered),
            "a lowered contract claim with an unchanged gate passed",
        )

        self.assertTrue(
            coverage_floor_disagreements(declarations, []),
            "deleting every claim from AGENTS.md passed",
        )
        self.assertTrue(
            coverage_floor_disagreements([], claims),
            "deleting the floor from every workflow passed",
        )
        self.assertTrue(
            coverage_floor_disagreements(
                [*declarations, FloorDeclaration("pr-gate.yml", "job x env", 1, "1.0")], claims
            ),
            "two workflows declaring different floors passed",
        )

        # And the lift reaches exactly the claim it names, by text.
        self.assertEqual(
            coverage_floor_disagreements(
                raised, claims, {("pr-gate.yml", "contract-floor", c.text): "r" for c in claims}
            ),
            [],
        )
        self.assertTrue(
            coverage_floor_disagreements(
                raised,
                claims,
                {("pr-gate.yml", "contract-floor", "some other sentence"): "r"},
            ),
            "a lift naming different text silenced the refusal",
        )
        # ONE claim, deliberately: with the whole set, a lift that wrongly
        # silenced the first would still leave the second reported and this
        # assertion would pass on a broken rule filter. Narrowing the input is
        # what makes the row bite -- it survived the first kill matrix run.
        self.assertTrue(
            coverage_floor_disagreements(
                raised, claims[:1], {("pr-gate.yml", "env-shadow", claims[0].text): "r"}
            ),
            "a lift under another rule silenced the refusal",
        )
        self.assertEqual(
            coverage_floor_disagreements(
                raised, claims[:1], {("pr-gate.yml", "contract-floor", claims[0].text): "r"}
            ),
            [],
            "the positive control: the same subject under the right rule does lift",
        )

    def test_the_floor_search_widens_rather_than_pinning_where_the_number_may_appear(self):
        """Per the liftable-gates directive: behaviour, not inventory.

        A NEW sentence stating the enforced floor must pass without any edit
        here, and the search must not mistake the historical measured figure
        beside it for the floor itself.
        """
        declarations = coverage_floor_declarations(self.workflows)
        floor = declarations[0].value
        widened = agents_text() + (
            f"\n\nA later section may also mention `{COVERAGE_FLOOR_KEY}` at {floor} "
            f"(measured 99.9 when last raised), and that is not a new gate obligation.\n"
        )
        claims = coverage_floor_claims(widened)
        self.assertGreater(len(claims), len(coverage_floor_claims(agents_text())))
        self.assertEqual(coverage_floor_disagreements(declarations, claims), [])
        self.assertNotIn("99.9", [claim.value for claim in claims])

    def test_the_floor_declaration_is_found_by_search_at_every_env_scope(self):
        text = (
            "env:\n"
            "  GO_COVERAGE_FLOOR: '11.1'\n"
            "jobs:\n"
            "  application:\n"
            "    env:\n"
            "      GO_COVERAGE_FLOOR: \"22.2\"\n"
            "    steps:\n"
            "      - name: Enforce\n"
            "        env:\n"
            "          GO_COVERAGE_FLOOR: 33.3\n"
            "        run: true\n"
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "pr-gate.yml"
            path.write_text(text, encoding="utf-8")
            found = coverage_floor_declarations([read_workflow(path)])
        self.assertEqual(
            [(declaration.value, declaration.line) for declaration in found],
            [("11.1", 2), ("22.2", 6), ("33.3", 10)],
        )
        self.assertTrue(coverage_floor_disagreements(found, []))
        # A spelling the reader does not resolve is refused, never compared.
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "pr-gate.yml"
            path.write_text(
                text.replace("GO_COVERAGE_FLOOR: 33.3", "GO_COVERAGE_FLOOR: !!str 33.3"),
                encoding="utf-8",
            )
            workflow = read_workflow(path)
            with self.assertRaises(AssertionError):
                coverage_floor_declarations([workflow])

    def test_allowlist_entries_name_real_workflows(self):
        names = {workflow.name for workflow in self.workflows}
        for (workflow, rule, where) in sorted(self.allowlist):
            with self.subTest(entry=f"{workflow}|{rule}|{where}"):
                self.assertIn(
                    workflow,
                    names,
                    f"{ALLOWLIST.relative_to(ROOT)} exempts a construct in {workflow!r}, "
                    f"which is not a workflow in {WORKFLOWS.relative_to(ROOT)}. Remove "
                    f"the line -- it protects nothing.",
                )

    def test_allowlist_entries_still_have_a_live_subject(self):
        """The other half of the ratchet: the `<where>` subject must still exist
        AND still carry the construct being exempted.

        The test above reads the WORKFLOW field and nothing else, so an entry
        naming a step that does not exist sat green -- while the changelog
        claimed both allowlists ratchet shut. That was true of
        `subcommand-callers-allowlist.txt` and only half true here.
        """
        for (workflow, rule, where) in sorted(self.allowlist):
            with self.subTest(entry=f"{workflow}|{rule}|{where}"):
                reason = stale_reason(self.workflows, workflow, rule, where)
                self.assertIsNone(
                    reason,
                    f"{ALLOWLIST.relative_to(ROOT)} carries an entry that {reason}. "
                    f"Remove the line -- it protects nothing now, and it will "
                    f"silently pre-authorise whatever later takes that name.",
                )

    def test_the_subject_ratchet_refuses_a_stale_entry(self):
        """Drive that ratchet, because the shipped allowlist is EMPTY.

        An empty allowlist makes the loop above vacuous: the ratchet could be
        deleted outright with the suite staying green, which is precisely the
        surviving-mutant class the 0.1.49 review found for the three rules.
        Each row below pairs a LIVE subject with a stale one, so the check
        cannot pass by refusing everything either.
        """
        text = (
            "defaults:\n"
            "  run:\n"
            "    shell: sh\n"
            "env:\n"
            "  IMAGE: an-image\n"
            "jobs:\n"
            "  application:\n"
            "    continue-on-error: true\n"
            "    container:\n"
            "      image: ubuntu:24.04\n"
            "      env:\n"
            "        HELM_VERSION: '0'\n"
            "    defaults:\n"
            "      run:\n"
            "        shell: sh\n"
            "    env:\n"
            "      GO_COVERAGE_FLOOR: 93.2\n"
            "    steps:\n"
            "      - name: Probe\n"
            "        shell: sh\n"
            "        continue-on-error: true\n"
            "        env:\n"
            "          GO_COVERAGE_FLOOR: 0\n"
            "      - name: Plain\n"
            "        run: true\n"
            "  chart:\n"
            "    steps:\n"
            "      - name: Plain\n"
            "        run: true\n"
        )
        workflows = [parse_workflow(text, WORKFLOWS / "pr-gate.yml")]
        live = (
            ("continue-on-error", "application"),
            ("continue-on-error", "application/Probe"),
            ("custom-shell", "application/Probe"),
            ("custom-shell", DEFAULT_SHELL_SUBJECT),
            ("custom-shell", f"application/{DEFAULT_SHELL_SUBJECT}"),
            ("env-shadow", "application/Probe/GO_COVERAGE_FLOOR"),
            ("env-shadow", f"{WORKFLOW_ENV_SUBJECT}/IMAGE"),
            ("env-shadow", f"application/{JOB_ENV_SUBJECT}/GO_COVERAGE_FLOOR"),
            ("env-shadow", f"application/{CONTAINER_ENV_SUBJECT}/HELM_VERSION"),
            # The contract-floor subject lives in AGENTS.md rather than in any
            # job, so it is checked against the real contract text and the
            # synthetic workflow above is irrelevant to it -- which is the
            # point of taking it before the `<job>/...` partition.
            ("contract-floor", coverage_floor_claims(agents_text())[0].text),
        )
        for rule, where in live:
            with self.subTest(live=f"{rule}|{where}"):
                self.assertIsNone(stale_reason(workflows, "pr-gate.yml", rule, where))
        stale = (
            ("continue-on-error", "no-such-job", "does not declare"),
            ("custom-shell", "application/No Such Step", "does not have"),
            ("custom-shell", "application/Plain", "does not set one"),
            ("custom-shell", f"chart/{DEFAULT_SHELL_SUBJECT}", "does not set one"),
            ("continue-on-error", "application/Plain", "does not set it"),
            ("env-shadow", "application/Probe/NOT_DECLARED", "does not declare it"),
            ("env-shadow", "application/Probe", "is missing the"),
            ("env-shadow", f"{WORKFLOW_ENV_SUBJECT}/NOT_DECLARED", "does not declare"),
            ("env-shadow", WORKFLOW_ENV_SUBJECT, "is missing the"),
            ("env-shadow", f"application/{JOB_ENV_SUBJECT}/NOT_DECLARED",
             "does not declare it"),
            ("env-shadow", f"application/{JOB_ENV_SUBJECT}", "is missing the"),
            ("env-shadow", f"chart/{CONTAINER_ENV_SUBJECT}/HELM_VERSION",
             "does not declare it"),
            ("env-shadow", f"application/{CONTAINER_ENV_SUBJECT}", "is missing the"),
            ("contract-floor", "GO_COVERAGE_FLOOR` is 0.0", "no longer states"),
        )
        for rule, where, expected in stale:
            with self.subTest(stale=f"{rule}|{where}"):
                reason = stale_reason(workflows, "pr-gate.yml", rule, where)
                self.assertIsNotNone(reason, "a stale entry was not refused")
                self.assertIn(expected, str(reason))
        # The workflow-level subject needs a workflow that does NOT set one,
        # which the fixture above deliberately does.
        plain = [parse_workflow(self.CLEAN, WORKFLOWS / "pr-gate.yml")]
        reason = stale_reason(plain, "pr-gate.yml", "custom-shell", DEFAULT_SHELL_SUBJECT)
        self.assertIsNotNone(reason, "a stale workflow-level entry was not refused")
        self.assertIn("does not set", str(reason))


if __name__ == "__main__":
    unittest.main()
