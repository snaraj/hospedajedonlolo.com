# The no-artifact classifier — how the verdict is made trustworthy

`AGENTS.md` requirement 10 states the RULE: a range whose every commit is
individually confined to the closed documentation allowlist classifies
no-artifact, advances nothing, and skips the publisher. This document states
the MECHANISM behind that verdict — the reasoning a reviewer needs when the
orchestrator denies, and the attack the current design exists to defeat. It
adds no rule; requirement 10 and `docs/release-governance.md` remain the
contract.

## Why "it re-derives the class from git" was not enough

Saying the orchestrator "re-derives the class from git" is not enough, and it
was disproved by a working attack: the re-derivation is parameterised by the
verdict's claimed base, so a base naming a commit inside the push re-derives a
genuine artifact merge as documentation. A verdict that can choose its own
anchor can choose the answer.

## The three things that make the outcome trustworthy

1. **An anchor the verdict cannot choose.** The newest earlier successful
   protected-main gate run, read from the Actions record, with all four
   release locks (`VERSION`, `chart/Chart.yaml`, `chart/values.yaml`,
   `CHANGELOG.md`) required byte-identical between it and the merged head.
2. **An anchor-advance walk.** It begins at the recovered release boundary
   and steps over that same already released push's artifact commits,
   hard-capped at that gated head so a lock-free artifact commit landing
   after it cannot be stepped over.
3. **A re-classification of the gap the walk leaves behind** — from the
   advanced anchor to the merged head, NOT from the boundary, since the
   prefix the walk consumed is genuine artifact history that already
   released.

Only then is the publisher skipped, with an explicit logged verdict instead
of a dispatch.

The release boundary is recovered for both squash and multi-commit rebase
pushes, which is what lets requirement 10 accept either range shape.

## The two denial modes

Requirement 10 states both denial modes in full, and that passage is pinned
in place by `scripts/ci/test_release_contract.py` precisely so a restatement
elsewhere — including this document — can never rescue a drifted original.
Read them there, not here.

## The CHANGELOG edit the append-only gate closes

`AGENTS.md` "Docs and attribution conventions" states the append-only rule.
The gap it closes is a plausible mechanical edit: an insertion that overwrites
the heading below it, orphaning a shipped release's entries under the next
version's name, with every release control still green. That is why
`release_contract.py` refuses a snapshot whose released ladder is not strictly
descending with non-increasing dates, and refuses any base-to-head range that
removes, reorders, duplicates, or rewrites one byte of a released block.
