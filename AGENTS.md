# Agent contract — hospedajedonlolo.com

This is the CANONICAL, vendor-agnostic agent contract for this repository:
any frontier model — or hurried human — must be able to operate here cold
from this document alone. Tool-specific entrypoints (CLAUDE.md) only import
it; nothing is duplicated elsewhere. The platform repository's deeper
doctrine applies when the two meet.

## Cold start — first-session checklist

A new agent operates from this repository alone; nothing is relayed by
the owner. In order:

1. Read this file end to end — it is the whole briefing; CLAUDE.md only
   imports it.
2. `git fetch origin` and work from `origin/main`. Never trust a local
   `main`, a stale worktree, or another agent's summary of remote state —
   verify remote facts directly (`gh pr view`, `git ls-remote`).
3. Verify identity and tooling: `gh auth status` shows the owner's
   account; commits carry the noreply identity per "Commit identity
   mechanics"; know CI's pinned toolchain (Go 1.26.10 — the gate verifies
   it exactly). Go is the whole toolchain: there is no Node, no npm and no
   frontend build anywhere in this repository, and none may be added.
4. Survey the live state yourself: `gh issue list`, `gh pr list` —
   including the open-agent-PR count against the PR budget below.
5. Claim work through an issue, branch from `origin/main`, and follow
   "Working a change end to end".

## Purpose and architecture

hospedajedonlolo.com is the public page of Hospedaje Don Lolo, a family
farm-stay near Santa Rosa de Cabal, Colombia: one bilingual (Spanish, with an
English switch) static page — rooms, the farm, a film, an area map, and a
booking form that hands the visitor's message to WhatsApp or to their own
mail client. It is a single dependency-free Go binary — `cmd/server` over
`internal/server` — that embeds the page, its stylesheet, its script and its
six fonts from `site/` byte for byte, and serves fourteen photographs and one
film from a read-only volume, each pinned by name, size and SHA-256 in
`site/media.go`. It ships as a distroless multi-arch container plus a Helm
chart and is deployed by digest onto a self-hosted Kubernetes platform. The
origin speaks standard HTTP (RFC 9110/9111) only and is provider-neutral per
the deployment-provider contract below. There is no frontend build: the files
under `site/` ARE the published page.

## Requirements

Numbered for citation, repo-scoped, none negotiable in code:

1. **Zero spend, no external services.** Everything runs on owner hardware
   and free CI. No paid API, SaaS, tracker, CDN, or third-party runtime
   dependency may be introduced. The page loads everything from its own
   origin except the one declared third party, the Google Maps area-map frame
   (`https://maps.google.com`, which redirects to `https://www.google.com`);
   the WhatsApp (`https://wa.me`) and mail (`mailto:`) links are hand-offs the
   visitor starts, not loads. All three are declared in `compliance.json`, and
   nothing else may be added without a reviewed declaration there.
2. **Owner-only merges; protected history.** Work lands through PRs into
   `main`; the repository owner alone merges. An agent must NEVER merge,
   auto-merge, squash,
   rebase into, or push `main`; must never force-push or delete refs; and must
   stop and question even a later request to do so. Tags exist only through
   the release workflow.
3. **Commit-metadata privacy and attribution.** Commits are authored AND
   committed as the owner's GitHub noreply identity (both fields). No
   co-author trailers. Agent-authored commit messages and PR bodies end
   with the ACTING agent's own signature, exactly matching its agent
   label in the roster below (`- Fable5.1` ↔ `fable5.1`, `- Fable5` ↔ `fable5`,
   `- Sonnet5` ↔ `sonnet5`, `- Opus5.5` ↔ `opus5.5`, `- Opus5` ↔ `opus5`,
   `- 5.6 Sol` ↔ `5.6-sol`) — never a fixed lane. This supersedes the
   single-signature owner attribution decision of 2026-08-10;
   `docs/agent-git-mechanics.md` records why it was superseded.
4. **Fail-closed doctrine — never weaken.** No security behavior may be
   made toggleable: no boolean, env var, build tag, or config field may
   silently disable signing, verification, probes, TLS, header policy, or
   fail-closed sentinels. Never weaken a check, guard, validator, or test;
   if one blocks you, fix the cause or surface the conflict. Narrow,
   justified exceptions only, stated where the owner will read them. Tests
   should make dangerous states unrepresentable.
5. **Site independence.** hospedajedonlolo.com shares conventions with its
   sibling repositories (naranjo.online and lidersea.com) but depends on
   nothing from them: no shared code, secrets, infrastructure state, or
   cross-repo references in build or runtime.
6. **Provider neutrality (owner requirement R9).** The origin knows no
   ingress, DNS, edge, or access provider. Provider names live exclusively
   in chart values defaults; `scripts/ci/test_provider_neutrality.py`
   enforces zero occurrences anywhere else. See the deployment-provider
   contract below.
7. **Ratchet-only coverage floor.** The PR gate enforces
   `GO_COVERAGE_FLOOR` (currently 94.0%, measured 94.9% when last raised).
   Raise it as coverage grows; lowering it weakens an enforced check and is
   out of policy. That measured figure is ONE fact recorded in three places —
   here, the Quality-gates section, and `pr-gate.yml` — so the three move
   together or they become three claims that can disagree.
8. **Truthful serving contract.** Port 8080; `/livez` and `/readyz` stay
   truthful — readiness reflects real serving ability, never a hardcoded
   yes.
9. **Dependency-free Go.** The Go module stays standard-library only.
   Adding a dependency is an owner decision, not a convenience.
10. **Every artifact merge releases after the server gate; deploy remains
    separate.** Every PR whose range touches any artifact surface advances
    exactly one patch from its current protected base: numeric `VERSION`,
    chart `version`, `appVersion`, and changelog `X.Y.Z`, plus plain `vX.Y.Z`
    image tag. A range whose every commit is individually confined to the
    closed documentation allowlist — root `AGENTS.md`, `README.md`,
    `.gitignore`, and Markdown files under `docs/` — classifies no-artifact:
    it advances nothing, and the orchestrator proves that class against
    evidence the VERDICT CANNOT CHOOSE before skipping the publisher, then
    logs that verdict explicitly instead of dispatching. The anchor it proves
    against, the anchor-advance walk, and the gap re-classification are
    specified in `docs/release-classifier.md`, with the working attack that
    retired "it re-derives the class from git" as a sufficient answer.
    Removing the release from a documentation-only merge
    weakens nothing: the artifact is unchanged, so there is
    nothing to version, sign, scan, or attest. The classifier has exactly
    two verdicts and no flag, environment variable, or configuration input;
    a non-allowlisted path with an unchanged version, a mixed range without
    its one exact patch, an unparseable diff entry, or a non-regular file
    mode all deny; renames decompose into add plus delete, so a rename
    crossing the allowlist boundary denies through its non-allowlisted side.
    Widening the allowlist is itself an artifact-classified gate change that
    releases. Two denial modes are deliberate and must not be mistaken for
    bugs, and they behave differently — conflating them misleads whoever is
    on the other end of the red build. The BOUNDARY denial, from the
    recovered last release boundary, is STICKY: a documentation merge whose
    retained release never completed fails red, and every later
    documentation merge fails the same way until an artifact merge moves the
    boundary past it. It is reachable under the ordinary rebase convention
    of a separate slot commit, not only under exotic histories. The ANCHOR
    denial, from the four-lock comparison against the newest earlier
    successful protected-main gate run, does not persist the same way: it
    needs no artifact merge to clear, because the denied merge's own gate
    run becomes a later anchor. It is NOT, however, promised to clear on
    the very NEXT merge, and an earlier revision of this contract wrongly
    said it was. Main pushes each get their own concurrency group, so gate
    runs can complete out of order and `select(.id < $current)` can filter
    a newer run out of an older orchestration — two racing documentation
    merges can therefore both deny, reporting the identical anchor. Both
    denials are the intended trade — loud and recoverable, never a wrong
    release — but only the boundary denial requires an artifact merge to
    clear, and neither promises green on any particular next merge.
    Successful main CI publishes that exact SHA as one
    server-locked plain `vX.Y.Z` release, gated by the read-only
    authorization job stated under Releases below, so an ordinary manual
    dispatch, skipped job, or aggregate-only success cannot publish. Squash
    and rebase are both supported: the protected-main push must be one
    merge-free linear base-to-head range whose final snapshot is the exact
    next patch, and that complete final SHA gets one release. There is no
    skip or force path; the owner-observed release-control receipt and the
    separate bypass check that gate the first Release under this path are
    specified in `docs/release-governance.md` and required by Merge
    readiness below. Every created or reused GitHub Release must
    report authoritative `immutable: true` and exactly one canonical evidence
    manifest whose digest and downloaded bytes are verified before and after
    publication. Images deploy by digest; `vX.Y.Z@sha256:<digest>` is a
    reference, never a tag, and publication is never deployment or promotion.
11. **Media stays out of the control plane.** The photographs and the film
    never enter git, the embed, the image, or a ConfigMap/Secret. They live
    on the operator-provisioned read-only volume at
    `immutable/<sha256>/<name>`, are pinned by name, size and SHA-256 in
    `site/media.go`, and are served at `/assets/<name>`. The server hashes
    every pinned byte before `/readyz` answers and refuses to start on any
    mismatch — a missing, extra-linked, symlinked, resized or altered file.
    It then serves only the bytes it verified, held in memory, so nothing
    written, replaced or removed on the volume afterwards reaches a visitor:
    a visitor can only ever see the defined content.
    `scripts/stage-media.sh` is the one way files reach that layout.
12. **No secrets, no noncanonical personal data.** No credential, token,
    private host fact, private contact detail, or new personal data enters this
    repository — including tests, fixtures, and docs. The already-public owner
    name/noreply commit identity and license/portfolio authorship are the narrow
    canonical attribution exceptions; never expand them or use a personal name
    as authorization. Access control is always expressed by role. The
    business's public phone number, email address and street address on the
    page are the business's own defined content, published by its owner —
    not new personal data — and nothing else of that kind enters.

### Deployment-provider contract

The origin speaks standard HTTP (RFC 9110/9111) only. Ingress, DNS, edge,
and access are injected deployment concerns and never appear in application
code, the published site, or chart templates. Provider names live exclusively
in the chart's values defaults — `ingress.peerNamespace`,
`ingress.peerAppName`, and `ingress.peerInstance` in `chart/values.yaml`,
the single binding point the NetworkPolicy consumes — so a provider swap is
a values override, never a template or code edit. The pin test
(`scripts/ci/test_provider_neutrality.py`) enforces this, failing closed on
any provider name under `cmd/`, `internal/`, `site/`, or `chart/templates/`.

The peer identity is all three facts together, and the instance is not
decoration: the peer namespace is shared by several per-site connectors
that carry the SAME app name and are told apart only by
`app.kubernetes.io/instance`, so a namespace+app selector admits every
connector deployed there. `values.schema.json` requires the instance
non-empty — a blank or absent value fails validation instead of rendering a
wide policy — and `scripts/ci/chart-ingress-pin.sh` proves the pin over the
COMPLETE render, never one `--show-only` extract: the default render, refusal
of an unpinned instance, the instance as the separator, the single policy's
ingress sub-tree compared byte for byte against the canonical text built from
values, and fourteen hostile whole-render shapes refused by that extraction
ALONE. `docs/ci-map.md` records what each chart pin proves.

## Testing doctrine

- Coverage is enforced per requirement 7, on every production statement:
  the profile has no exclusion.
- The content invariant is a test: `site/site_test.go` pins every embedded
  file to its delivered SHA-256, proves every reference in the page resolves
  and nothing embedded is orphaned, and pins the media table's shape.
- The media root is deliberately never mocked — it is a security boundary,
  so its faults (wrong bytes, wrong size, symlinks, hard links, a file
  changed after verification) are staged on a real filesystem.
- End-to-end tests boot `run()` over real TCP against a fixture volume and
  drain on cancellation; configuration errors are proven to stop the process
  before any socket opens.
- Tests are stdlib-only with hand-written fakes; no assertion libraries,
  no mock frameworks.

## Package layout

- Each Go package keeps its type/struct declarations and package-level
  const/var blocks in `types.go`; methods stay beside the logic they
  serve. A `utils.go` exists only where a genuinely shared cross-file
  utility does — never create an empty or speculative one.
- `site/` is the published content and its pins (`embed.go`, `media.go`,
  `site_test.go`); `internal/server` is the origin (routing, headers, the
  media store, request logging); `cmd/server` reads the environment, builds
  the origin and serves it. White-box helpers stay in the package they
  observe (`internal/server/testing_test.go`).

## Build, test, and release flows

Build and test in the exact order given under "Quality gates — exact
commands and patterns" below; that battery is canonical and CI enforces the
same one. Two facts belong beside it: there is no build step before Go — the
embed reads `site/` directly — and all THREE chart pin scripts run in CI's
`chart` job at `--kube-version v1.36.0`, because the chart requires the
platform's Kubernetes target and plain `helm template` defaults to older
capabilities. To run the origin locally, stage the media with
`scripts/stage-media.sh <source-dir> <volume-root>` and start
`MEDIA_ROOT=<volume-root> MEDIA_MAX_CONCURRENT=8 go run ./cmd/server`
(README).

Releases: every artifact-classified PR advances numeric `VERSION`, chart
`version`, `appVersion`, and changelog `X.Y.Z`, plus plain `vX.Y.Z`
`image.tag`, by exactly one patch from its current protected base; a
documentation-only range (requirement 10's closed allowlist) advances nothing
and skips release orchestration entirely. Successful main CI creates NO tag: it
explicitly dispatches the protected-main publisher with that successful run's
ID, and the PUBLISHER creates the annotated plain `vX.Y.Z` tag at the exact
merged SHA from inside its privileged job, so no tag exists before
authorization. The split is enforced by permissions, not convention —
`release-after-main.yml`'s only job holds `actions: write` plus `contents:
read` and therefore cannot create a ref at all, while `release-publisher.yml`'s
`publish` job holds `contents: write` and POSTs the tag object and
`refs/tags/`. A token-created tag is never assumed to trigger another push
workflow, which is exactly why the dispatch is explicit rather than
tag-triggered. The publisher's read-only authorization job verifies
the exact run, repository, workflow path, push event, successful conclusion,
main branch, source SHA, exact PR-gate job inventory, and the separate exact-SHA
CodeQL main run and job inventory before its write/packages/OIDC job can start.
The publisher emits the signed multi-arch image, signed OCI chart, and GitHub
Release only after checksum-pinned high/critical source and final-image scans;
source scanning passes `--include-dev-deps` (the Go module has no dependency
at all). It re-resolves the
actual image and chart aliases to the exact produced digests and validates each
raw platform SBOM subject before sealing the manifest.
The Release carries one deterministic manifest binding source/run, artifacts,
aliases, signer/provenance, and scan policy/results; a weekly read-only audit
revalidates that complete chain. Histories and tags are append-only; stale
concurrent PRs must resync
and take the new next patch when they carry an artifact change; a
documentation-only PR has no patch to retake. Deployment RESOLVES digests, never tags. The
Helm chart/OCI tag is the documented numeric `X.Y.Z` exception because Helm
requires its registry tag to equal valid chart SemVer; Git/image/Release tags
remain plain `vX.Y.Z`.
Before the first Release governed by this path, the repository owner must make
the release-control settings receipt exact. The receipt is a required Ready
gate, never permission for an agent to change settings or merge. A failed or
unknown preflight leaves the PR Draft.
The rendered image reference carries both —
`repository:vX.Y.Z@sha256:<hex>` — so a Pod
says which release it is, but only the digest selects bytes, and only the
digest is signed, attested and verified at admission (requirement 10).

## Sanctioned evolution

The following are expected changes, and the suite is built to make them
conscious edits, never fights:

- Content changes. The page bytes are pinned, so any change to the page, its
  stylesheet, its script, a font, a photograph or the film is a reviewed
  change to `site/site_test.go` or `site/media.go` (plus, for media, the new
  file staged on the volume) — see "Content invariant".
- CSP changes happen in lockstep: `contentSecurityPolicy` in
  `internal/server/types.go`, the pinned copy in
  `internal/server/server_test.go`, and `compliance.json` move in the same
  commit.
- Adding a media kind: `mediaTypes` and `mediaName` in
  `internal/server/types.go` together with their tests.
- Ingress provider changes: a values override of the `ingress` block per
  the deployment-provider contract.

None of this relaxes the requirements above: security behavior stays
non-toggleable, provider names stay confined to values defaults, and the
coverage floor only rises.

## Adversarial review protocol

Every substantive PR receives an independent adversarial review BEFORE it
leaves draft. The mechanism is vendor-agnostic: any capable agent — or a
human — runs it with git, a shell, and this repository's own gates; no
step assumes a particular AI tool, and no vendor gets a different protocol.

**Review depth is risk-based.** Not every PR earns identical depth:

- **Security-surface changes** — request/input handling, authn/authz, CI
  workflows, chart/deploy, dependencies, secrets, signing/release
  machinery, binary or vendored assets — take focused tests, one full CI
  cycle, live validation, ONE independent adversarial review, and owner
  merge.
- **Normal code changes** take focused tests and one full local gate; a
  live check only when runtime behavior changes; one review.
- **Docs, comments, and formatting** (requirement 10's no-artifact class)
  run the relevant checks only; adversarial review is the coordinator's
  routing decision, not a mandate.

Exact-head discipline is unchanged for whatever review DOES run: a
verdict binds the head it names.

**Reviewer independence.** The reviewer is a different agent or context
than the author — a fresh session of the same vendor qualifies; a
different lane is better. Independence is established by the POSTING
ACTOR, never by signature wording: a verdict receipt is posted by the
`snaraj-agent-reviews[bot]` GitHub App — a principal distinct from the
account that authors and pushes branches, and one granted Contents
write in no repository, so a compromised review lane can never alter
what it reviews. The signature line is lane provenance, content rather
than identity, so any current or future model name is valid there and
this contract pins no model roster. No rule compares the reviewer's
name to the author's: that textual same-lane denial retired with issue
#64, because a reviewer satisfies it by writing a different-looking
signature. Same-lane review is therefore permitted and stays legible, and
the actor is what a reader verifies. The reviewer works disposably, per
"Parallel agents in one checkout".

**Exact-head receipt.** The receipt binds one exact head, and the bot
actor above is what makes it a second party rather than a self-approval.
The reviewer posts one normal PR comment in this exact shape (replacing
every placeholder):

```text
HEAD: <40-lowercase-hex>
VERDICT: APPROVE

1. <numbered finding, or explicit no-finding scope>

Mutation audit: <hostile mutation results>
Claim audit: <SUPPORTED and OVERSTATED results>
Full-gate and flake evidence: <commands, results, and capability boundaries>
Scratch cleanup: <disposable workspace and residue result>

- <Agent> (adversarial reviewer)
```

The verdict line may instead be exactly `VERDICT: REQUEST-CHANGES`. Any head
change invalidates the receipt. The author replies with reproduction and repair
evidence; a fresh independent context re-reviews the new exact head. If the
owner merges first, record a post-merge audit and classify—not erase—the gap.

**The review must:**

1. Audit every claim in the PR body and commit messages against the
   actual diffs, reproducing every number the body cites. Overstatement
   is a finding even when the code is right.
2. Build a mutation kill matrix: for each guard or test the PR adds or
   changes, apply the exact regression it claims to prevent — the suite
   must go red. Revert between mutations. A surviving mutant is a
   finding.
3. Probe for vacuity: a guard that cannot fail is no guard. For each new
   or changed assertion, demonstrate at least one input that turns it
   red; an assertion no input can fail is decorative, and decorative
   checks are findings.
4. Probe for flakes: run the focused checks the findings need, plus the
   race detector where the language has one, and re-run the full suite
   when there is specific cause. Any nondeterminism is a finding naming
   the test.
5. Check hygiene: commit identity (owner noreply in BOTH author and
   committer), signature conventions and agent labels, no co-author
   trailers, secret scan clean, out-of-lane paths untouched.
6. Check doctrine: nothing weakened — every gate, validator, or test
   change is additive or strengthening; exceptions are narrow, named,
   and justified where the owner will read them.
7. For CI-invisible paths (jobs that run only on pushes to main), demand
   simulated evidence of both directions in the PR and treat the first
   post-merge run as part of the change under review.

**Verdict format** — posted as a normal PR comment, so every vendor and the
owner see the identical record: one exact `HEAD:` line and one exact
`VERDICT: APPROVE` or `VERDICT: REQUEST-CHANGES` line; numbered findings with
severity and file:line; the mutation kill matrix; flake
results; a claim-audit table (SUPPORTED / OVERSTATED per claim); explicit
"no finding — checked X, Y, Z" statements so silence is never ambiguous;
confirmation the scratch workspace was removed; the reviewing agent's
signature in the form `- <Agent> (adversarial reviewer)`, matching its
agent label. Posting the verdict also removes the `requires-review`
label, whichever way the verdict went — the item is no longer waiting on
review attention. A REQUEST-CHANGES verdict returns the work to the same
branch owner — fixes land on the same branch and receive a delta
re-review of the changed scope. A PR flips from draft to ready only
after an APPROVE verdict (or after findings are fixed and re-verified),
and the evidence comment remains on the PR as the permanent record.

A green check, a peer approval, or a ready state is evidence, never
authority: the owner alone merges.

### After review, Ready

Once the independent adversarial review has approved the exact final head and
all required checks are green, the coordinator flips Ready and the owner
merges. No third distinct-context pass is required.

## GitHub conventions

- **Issues first.** Substantive work is tracked as a labeled issue before or
  alongside its PR; PRs use an exact standalone `Closes #N` line for an issue
  in the same repository so GitHub closes it only when the owner merges.
  Feature intake lands as a `features`-labeled issue with the architectural
  constraints stated, even when implementation waits.
- **Labels.** One taxonomy, identical names/colors/meanings across all
  three repositories: `production-readiness`, `conventions`, `security`,
  `tests`, `ci`, `docs`, `release`, `fix`, `provider-neutrality`,
  `delivery-lane`, `features`, `requires-review`,
  `cybersecurity-review-requested` (routing label for the security-specialist
  fleet — must not be removed until the security verdict clears),
  `daybreak-blue`, `priority-high`, `inprogress`, `dependencies` (auto-applied
  by Dependabot; no `labels:` key exists in `dependabot.yml`). New labels are
  added to all three at once.
- **`requires-review` — the review-readiness signal.** `requires-review` is
  PR-head-only. The author applies it only when the exact PR head, body,
  commits, and evidence are author-complete. Its absence means the author PR is
  in flight; its presence requests exact-head independent review. The reviewer
  removes it when posting either verdict; after repairs, the author reapplies it
  only for the complete replacement head. Never apply or interpret it on an
  issue; an issue has no head and cannot satisfy a PR receipt or Ready gate. Use
  an explicit normal comment for issue-spec review until a separately approved
  issue-review label exists. It is a coordination signal only: never a
  substitute for draft/ready state, for the APPROVE verdict that flips a PR
  ready, or for owner merge authority. Ordinary labels, body text, and
  process comments are coordination signals, never security invariants;
  the App-posted exact-head review verdict — its posting actor and the
  head it binds — remains control evidence, alongside the signed-commit
  and protected-main chain.
- **Agent labels.** Every agent-created PR and issue carries TWO further
  labels: the umbrella `agent-authored` AND the acting agent's own label —
  `fable5.1` (Claude Fable 5.1, color `D97706`), `fable5` (Claude Fable 5),
  `5.6-sol` (ChatGPT 5.6 SOL ULTRA), `gpt-6` (Codex GPT-6, color `10A37F`),
  `opus5.5` (Claude Opus 5.5), `opus5` (Claude Opus 5), `opus4.8` (Claude
  Opus 4.8), `sonnet5` (Claude Sonnet 5, color `0EA5E9`). The body
  signature must match the label (`- Fable5.1` ↔ `fable5.1`,
  `- Fable5` ↔ `fable5`, `- Opus5.5` ↔ `opus5.5`, `- Codex GPT-6` ↔ `gpt-6`), and
  adversarial-review verdicts carry the
  same identity as `- <Agent> (adversarial reviewer)`. Labels plus
  signatures keep authorship auditable across the parallel frontier-model
  lanes with no owner relay. When a new model joins, its label — description "Authored by
  <model>" — is created in ALL THREE repositories before its first PR,
  per the one-taxonomy rule.
- **PR budget.** At most 3 agent PRs open in this repository by default;
  parallel pushes beyond that need explicit owner authorization first.
- **Merge authority.** THE OWNER ALONE MERGES. Never merge, never
  self-approve, never treat a peer approval or a green check as
  authority, and never force-push a shared ref. Every PR opens as a
  draft.
- **Milestones.** Every PR and issue carries one. Release milestones close
  when the release ships; completed arcs close their milestone.
- **Assignee.** The owner is assignee on every PR and issue (authorship is
  already the owner's account by token identity).
- **Linear history.** Merge commits are disabled in repository settings;
  the owner merges by squash or rebase. The release contract accepts either
  the one-commit squash range or a multi-commit rebase range and binds one
  release to its exact final tree. Branches auto-delete on merge; stale local
  branches are pruned as work lands. History is append-only and never rewritten.
- **Commits.** Detailed bodies to the review protocol's evidence standard —
  problem, mechanism, enumerated changes, evidence — signed per lane.
- **Dependabot.** Dependency PRs obey the same issue/milestone/assignee,
  next-patch, changelog, exact-head review, CI, and base-freshness controls.
  Infrastructure/tool outages are reported as infrastructure failures; they do
  not waive a real product failure or justify lowering this repository's
  coverage floor. When Dependabot splits a version-locked pair into
  separate PRs, one agent PR supersedes BOTH, bundling the pair AND fixing
  the root cause in the same commit with a `dependabot.yml` `groups:` stanza
  scoped to that pair, so the split cannot recur; the precedents that
  produced the rule are listed in `docs/agent-git-mechanics.md`. This
  repository's Dependabot covers `github-actions` (the CodeQL action's
  `init`/`analyze` pair grouped) and `gomod` only.
- **Merge readiness.** Draft remains Draft until every check is successful at
  the exact head, the base equals current protected `main`, all discussions and
  findings are resolved, a fresh exact-head APPROVE receipt exists, the next patch
  still follows that base for an artifact-classified PR (a documentation-only
  PR reserves no patch at all), the automatic release consequence is proven, the
  owner-observed release-control receipt proves strict exact required checks,
  the owner-verified commands prove immutable releases and the other settings
  the job token cannot read, and the owner's separate bypass check reports
  no core bypass actor — the receipt carries no bypass field. Only the
  coordinator flips Ready. The author and reviewer never do.

## Parallel agents in one checkout

Several agents — different models and vendors, executors and reviewers — work
this repository at once, sometimes on one machine. Git worktrees are the
isolation mechanism, and these rules bind every lane whether or not any
vendor-specific tooling is present.

- **The shared checkout is nobody's workspace.** It stays on `main`, clean, and
  is used only for coordination — `git fetch`, worktree creation and removal,
  ceremony reads. No agent builds, edits, or checks out a branch there. It may
  lag `origin/main` harmlessly: every actor works from `origin/main` after its
  own `git fetch origin`, never from a local `main`.
- **One worktree per acting context, named for its lane.** Branch names
  follow the grammar in "Working a change end to end" step 2. Executors run
  `git worktree add .claude/worktrees/<lane>-<effort>-<issue#>-<topic> -b
  <lane>-<effort>/<issue#>-<topic> origin/main`; the legacy
  `git worktree add .claude/worktrees/<lane>-<topic> -b <lane>/<topic>
  origin/main` form remains accepted during the transition. Either way, the
  directory and the branch carry the SAME lane, because the
  cleanup rule below depends on ownership being legible to every other agent.
  A worktree whose name and branch disagree, or a branch with no lane prefix,
  is a contract violation.
- **Reviewers work disposably.** A detached-HEAD worktree at the exact pull
  request head (`git worktree add .claude/worktrees/<lane>-review-<PR#>
  <headSHA>`), removed once the receipt posts. A reviewer stays read-only
  toward every other workspace and reverts every experiment inside its own.
- **One writer per branch, one branch per worktree.** A worktree that is not
  yours is a worktree you never write to. Treat reads with care: a tree that
  advances under you mid-operation is a live executor, not stale state.
- **Some git state is shared — that is the trap.** HEAD, index, and working
  tree are per-worktree; refs, remotes, config, and stash are repository-wide.
  So `git fetch`, `git branch -d/-D`, and `git worktree prune` act on every lane
  at once: run them only from the main checkout during deliberate cleanup,
  never mid-task. Never `git config` anything — identity is env-pinned per
  command per "Commit identity mechanics", and one lane's config write poisons
  all of them. A branch checked out in any worktree cannot be deleted or
  checked out elsewhere; that lock marks live ownership.
- **Clean only your own lane, and only after the owner merges.** Confirm the
  merge against the remote, then remove your worktree and delete your branch
  from the main checkout with `git worktree remove` and `git branch -d` — no
  `--force`, no `-D`. Those refusals are the safety net: a dirty tree or an
  unmerged branch is somebody's live work, very possibly another lane running
  right now. Another lane's leftovers are that lane's to remove.
- **Shared machines contend.** Heavy suites in several worktrees compete for CPU
  and load-sensitive tests can flake under contention. Treat a contention flake
  as an environment finding — name it, rerun it, never weaken the test — and
  stagger the heaviest batteries when many lanes run at once. A local origin
  run on a shared machine sets `PORT` to a private port, because the default
  is 8080 and cross-lane servers answer another lane's probes.

## Working a change end to end

The complete delivery loop, each step gated by the sections around it:

1. **Claim the work.** File (or take) the issue; state intent and
   constraints. Label it — including both agent labels — assign the
   owner, set a milestone. Never apply or interpret `requires-review` on the
   issue; use an explicit normal comment when its specification needs review.
2. **Branch from `origin/main`** after `git fetch origin`; branch names
   are lane-prefixed. The preferred grammar for new branches is
   `<lane>-<effort>/<issue#>-<topic>` (e.g. `sonnet5-med/12-media-pin`,
   `opus5.5-high/14-stage-media`), carrying the dispatched reasoning effort
   (`low | med | high | xhigh | max`; `xhigh` admitted by owner ruling,
   2026-09-03) and the tracking issue number; `<lane>` is
   parsed by longest match against the repository-registered label set
   (`fable5.1`, `fable5`, `5.6-sol`, `gpt-6`, `opus5.5`, `opus5`, `opus4.8`,
   `sonnet5`), then the `-<effort>` suffix — longest match is what lets
   `fable5.1-high/…` and `fable5-high/…`, or `opus5.5-high/…` and
   `opus5-high/…`, coexist. A branch with genuinely no issue states why in its
   PR body. The legacy form (`<lane>/<topic>`, e.g. `sonnet5/contracts-0.1.2`)
   remains accepted during the transition. One writer
   per branch, always —
   a branch that is not yours is a branch you never push to. Reserve the exact
   next patch from that base when the change touches any artifact surface; a
   documentation-only change (requirement 10's closed allowlist) reserves no
   patch and must leave every release lock untouched. If another PR lands, create a fresh branch from
   current main, carry the still-valid diff without rewriting published
   history, take the new next patch, and close/supersede the stale PR.
3. **Build the change** inside the requirements and doctrine above.
   Docs-only diffs still run the gates.
4. **Run the full local gate** ("Quality gates" below), then both secret
   scans, then commit under the pinned identity with a body to the
   evidence standard, ending with your signature.
5. **Push and open a DRAFT PR**: `Closes #N`, the same labels, owner as
   assignee, a milestone, body signed. Every number in the body must be
   reproducible — the adversarial review will reproduce it. Apply
   `requires-review` once the PR is complete-from-author — every commit
   pushed, the body final; until it carries that label, nobody reviews
   it.
6. **Adversarial review** per the protocol above; findings are fixed on
   the same branch by the same writer and delta re-reviewed before the
   flip to ready.
7. **Prove server release controls.** For an automatic-release change, the
   repository owner runs the GET-only preflight in
   `docs/release-governance.md` AND, separately, that document's owner-verified
   commands — the Administration-only settings the job token cannot read, and
   the standalone bypass command; the preflight reads no bypass field under any
   credential. Immutable releases and strict current-base required checks must
   be exact, and the core bypass-actor list must be empty, before Ready.
   `Protect-Main` is the only active repository-owned branch ruleset (see
   release governance).
8. **Owner comments** are handled per the owner review protocol below.
9. **The owner merges.** Nothing you can do — approval, green checks,
   ready state — substitutes for that.

## Commit identity mechanics

Requirement 3, made operational. The identity — BOTH author and
committer, on every outgoing commit — is exactly:

    Samuel Naranjo <39077795+snaraj@users.noreply.github.com>

- Pin it per command with environment variables, never with `git config`
  (repository or global): configuration outlives the session, leaks into
  unrelated work, and hides identity decisions from review.

      GIT_AUTHOR_NAME='Samuel Naranjo' \
      GIT_AUTHOR_EMAIL='39077795+snaraj@users.noreply.github.com' \
      GIT_COMMITTER_NAME='Samuel Naranjo' \
      GIT_COMMITTER_EMAIL='39077795+snaraj@users.noreply.github.com' \
      git commit ...

- Agent commits are SSH-signed per command with the owner-registered
  signing key, never via `git config`. **Select that key explicitly.** The
  obvious form is broken:

      # BROKEN whenever more than one ed25519 key is loaded
      -c user.signingkey="key::$(ssh-add -L | grep ssh-ed25519)"

  `grep` matches EVERY ed25519 line, so `key::` receives a multi-line
  value and signing fails on a malformed key — not an exotic setup, and
  `docs/agent-git-mechanics.md` records how often it has bitten. Ask GitHub
  which key is registered for SIGNING, intersect that with what the agent
  actually holds, and require exactly one match. That selection names no key
  comment, no hostname, and no ordering, so it works unchanged from any
  machine the owner signs on:

      signing_key() {
        local matched
        matched="$(comm -12 \
          <(gh api /users/snaraj/ssh_signing_keys --jq '.[].key' | sort) \
          <(ssh-add -L | awk '{print $1, $2}' | sort))"
        test "$(printf '%s' "${matched}" | grep -c '')" -eq 1 || {
          printf 'expected exactly one registered signing key in the agent\n' >&2
          return 1
        }
        printf '%s' "${matched}"
      }

      git -c gpg.format=ssh \
          -c user.signingkey="key::$(signing_key)" \
          commit -S ...

  Every agent commit must show as Verified. Signature enforcement on
  `main` is a protected-branch setting, not repository-wide, so it never
  blocks the owner's own merges from a machine without this key.
- **Verifying a signature locally needs a SPACE-FREE principal — and the
  negative control lies when it is wrong.** Local verification reads an
  allowed-signers file whose first field is a principal:

      printf '%s %s\n' '39077795+snaraj@users.noreply.github.com' \
        "$(signing_key)" > "${allowed}"
      git -c gpg.ssh.allowedSignersFile="${allowed}" \
          log --format='%H %G? %GS' -1 <sha>

  Use the BARE email: a name-plus-angle-brackets principal makes ssh read
  the space as a field break and match nothing, and that failure is
  indistinguishable from a genuine wrong key. Run BOTH controls and require
  them to DIFFER — the positive control must print `G`, and the negative
  control, with only some OTHER key in the file, must print `U`. If the
  positive control is not `G`, the file is broken; repair it before
  believing anything the negative one says. `docs/agent-git-mechanics.md`
  records the trap in full.
- EVERY authorized commit runs under the same pinned environment. Agents do
  not amend, rebase, cherry-pick onto a published branch, or rewrite history;
  use additive commits or a fresh branch from current main.
- No `Co-Authored-By` trailers, ever. Agent-authored commit bodies, PR
  bodies, and issue bodies end with the ACTING agent's own signature,
  matching its agent label per the roster (`- Fable5.1` ↔ `fable5.1`,
  `- Fable5` ↔ `fable5`, `- Sonnet5` ↔ `sonnet5`, `- Opus5.5` ↔ `opus5.5`,
  `- Opus5` ↔ `opus5`, `- 5.6 Sol` ↔ `5.6-sol`, `- Codex GPT-6` ↔ `gpt-6`) —
  never a different lane's name and never a fixed default.
- Treat the Git index as public (requirement 12): no hostname, IP
  address, machine or account identifier, username, workspace path,
  token, or private operational fact enters any commit, message,
  fixture, or doc — what reaches history cannot be unpublished.

## Owner review protocol

Comments the owner leaves on PRs ARE code reviews — address each
promptly, reply IN-THREAD per comment describing the resolution, then
notify the owner the PR is ready to re-check; never mark a PR ready
with unaddressed owner comments.

## Dependent pull requests

Dependent work may be described as a merge order, but every eventual
artifact-classified PR to protected main must independently carry its next
patch release; a documentation-only PR carries none and is never a release
dependency. Keep a
dependent PR Draft until its predecessor lands. Then fetch current main, create
a fresh branch without force/rebase, port only the residual diff, allocate the
new exact patch, rerun every gate, open a replacement Draft PR, and obtain a
fresh exact-head review. Never retarget or merge a dependency stack in a way
that duplicates predecessor content.

## Quality gates — exact commands and patterns

The full local gate, in order, before every push — docs-only diffs
included; it is the same battery CI enforces:

    test -z "$(gofmt -l .)"
    GOTOOLCHAIN=local go vet ./...
    GOTOOLCHAIN=local CGO_ENABLED=0 go test ./...
    GOTOOLCHAIN=local go test -race ./...
    python3 -I -B -m unittest discover -s scripts/ci -p 'test_*.py' -v
    python3 -I -B scripts/ci/dependabot_contract.py .github/dependabot.yml
    python3 -I -B scripts/ci/compliance_manifest.py check
    helm lint chart && helm template smoke chart \
      --kube-version v1.36.0                    # chart changes
    ./scripts/ci/chart-ingress-pin.sh           # chart changes
    ./scripts/ci/chart-egress-pin.sh            # chart changes
    ./scripts/ci/chart-media-pin.sh             # chart changes
    actionlint                                  # workflow changes
    shellcheck scripts/*.sh scripts/ci/*.sh     # script changes
    docker build .                              # Dockerfile/build-input changes
    gitleaks git --no-banner --redact --max-target-megabytes=2 .
    gitleaks dir --no-banner --redact .

The coverage figure CI enforces is read the same way locally:

    CGO_ENABLED=0 go test -covermode=atomic -coverprofile=cover.out ./... && \
      go tool cover -func=cover.out | tail -n 1 && rm -f cover.out

The full local gate does not substitute for the server boundary. Automatic
release work additionally requires the owner-observed, value-only receipt in
`docs/release-governance.md`; because the current branch has no authority to
repair its own protection, an inexact receipt is an intentional Ready blocker.

- **Coverage floor.** `GO_COVERAGE_FLOOR` is 94.0 (measured 94.9 when
  last raised), enforced in `.github/workflows/pr-gate.yml` on total
  statements with no exclusion at all; none may ever be added to cover a
  production package. Ratchet only (requirement 7).
- **Bounds are tests.** The origin's limits live as constants in
  `internal/server/types.go` and are exercised as refusals, never as
  documentation: the range-abuse caps (`maxRangeHeaderBytes` 4096,
  `maxRangeParts` 16) by `TestAbusiveRangesAreRefusedButPreconditionsStillWin`,
  the media transfer budget by `TestCapacityExhaustionAnswers503`, and the
  operator's ceiling (`MaxMediaConcurrency` 256) by
  `TestMediaConcurrencyIsRequiredAndBounded`. A revised bound stays
  refuse-not-truncate and lands with its test.
- **Ratchet pairs.** When a stated requirement and shipped behavior
  disagree across lanes, record the gap loudly instead of greenwashing
  it: one green test pins current behavior, and a paired
  expected-failure test asserts the pending contract, flipping the
  suite red the day the implementation tightens — which forces the
  marker's removal and turns the note into an enforced rule. Go suites here
  express that pair as a behavior pin plus a named pending-contract test
  documented in its comment.
- **Secret scan, both modes.** `gitleaks git` (full history) AND
  `gitleaks dir` (working tree) run before every push — the same scans
  CI runs. Exceptions live only in `.gitleaksignore` as commit-scoped
  fingerprints (`commit:file:rule:line`) with an in-file justification,
  admitted only for verified false positives already in pushed history;
  the working tree must always scan clean WITHOUT them. This repository
  keeps no `.gitleaksignore`.
- **Flake probe.** The author runs the complete local gate ONCE on the
  final head; the reviewer runs the focused checks its findings need and
  MAY re-run the full suite when it has specific cause. Any
  nondeterminism is a finding naming the test.

## CI map

- **pr-gate.yml** — pull requests AND pushes to `main` (plus manual
  dispatch): `security` (the Python contract suites under `scripts/ci/` —
  `unittest discover -s scripts/ci`, the same command the local gate above
  lists — the Dependabot contract, the commit identity and co-author
  contract over the contributed range, the exact one-patch transition and
  its published verdict, checksum-verified tool install, `trivy fs` and
  `trivy config` at HIGH/CRITICAL, actionlint, `gitleaks git` over full
  history, `gitleaks dir`), `dependency-review` (PRs only; fails on high
  severity), `application` (toolchain pinned AND verified — Go 1.26.10;
  gofmt/vet/tests/race; the coverage floor, reported in the step summary),
  `chart` (the three chart pin scripts; helm lint + render at
  `--kube-version v1.36.0`; the numeric VERSION ↔ numeric chart `version` ↔
  numeric `appVersion` ↔ plain-v chart `image.tag` four-way lock, plus a
  render assertion that the emitted reference still carries a full digest),
  `container` (PRs only, like `dependency-review`; both production
  architectures built, never published). `container` remains a REQUIRED
  pull-request check; `EXPECTED_MAIN_JOBS` in `scripts/ci/release_contract.py`
  expects `container` and `dependency-review` `skipped` on a main push and
  the other three successful, exact in both directions. What each chart pin
  proves, and why the two PR-only jobs carry no main trigger, is in
  `docs/ci-map.md`.
- **codeql.yml** — pull requests, `main` pushes, weekly cron: `go`
  (manual build), `javascript-typescript` (it analyses `site/app.js`) and
  `python` (`scripts/ci`).
- **release-after-main.yml** — success-only exact-SHA main-CI completion;
  performs no publication mutation and explicitly dispatches the publisher
  definition on protected `main` with the exact completed-run ID.
  It re-proves the gate's published transition class against an anchor the
  verdict cannot choose — not from the claimed base alone, which is
  forgeable — and gates every release-effect step on `artifact`; a
  no-artifact range logs its verdict and dispatches nothing. Distinct main
  SHAs share no cancellation group.
- **release-publisher.yml** — explicit dispatch on protected `main`. Its
  read-only authorization job, its read-only `repository_settings` preflight
  under the job's own `github.token` (no App, no stored credential), exact
  source/tag/lock checks, checksum-pinned vulnerability gates, post-push
  image/chart alias resolution, raw per-platform SBOM binding, exact
  one-asset manifest staging, and terminal immutable Release/manifest/tag
  state are stated under Releases above; an ordinary manual/unmerged
  dispatch, skip flag, or force path cannot publish (requirement 10).
- **compliance-live.yml** — weekly, manual, and pull requests that change the
  judge: GETs production and judges what the edge serves
  against `compliance.json` with `scripts/ci/compliance_manifest.py live` (a
  complete answer, CSP origins exactly the declared ones, framing, HSTS,
  nosniff, Referrer-Policy, no cookie, reporting endpoints, scripts in the
  served HTML, published legal pages). It holds `contents: read` and no
  secret, and it is not a required context. The manifest's schema, its
  storage list against the writes `site/app.js` makes, its hand-offs against
  the URLs that script builds, and the judge's rules run in the PR gate's
  contract suites. Lift: the `compliance.json` entry a liftable refusal
  prints, with a written reason; header, cookie, on-load-write and
  incomplete-answer refusals have no manifest lift. `docs/ci-map.md` records
  what the checks prove.
- **release-audit.yml** — weekly and manual, read-only audit of the latest
  immutable Release. It re-binds the successful run, annotated tag, exact
  manifest bytes, image/chart semantic aliases and digests, signatures,
  per-platform provenance/SBOM, chart source tree, and final image scan.
- **GitHub event basis.** Documented GitHub behaviour for
  `GITHUB_TOKEN`-created refs, `workflow_run` context, and concurrency
  ordering is why the success check, payload `head_sha`, tag-ref dispatch,
  and independent per-SHA paths are load-bearing. `docs/ci-map.md` states
  each documented behaviour and cites the three references.
- **Zero-spend guardrails.** Workflows declare top-level
  `permissions: {}` with narrow per-job read grants;
  `persist-credentials: false` on every checkout; GitHub-hosted
  `ubuntu-24.04` runners only; every action pinned to a full commit SHA
  with a version comment; third-party tools installed only through the
  checksum-verifying `scripts/ci/install-tools.sh`. No external service
  ever receives repository content or measurements.

## Content invariant

The published page is the business's defined content, and its bytes are
pinned rather than described:

- `site/site_test.go` pins `index.html`, `style.css`, `app.js` and the six
  fonts to the SHA-256 of the delivered export. No refactor, formatter, lint
  fix or "small copy edit" may change them; a content change is a reviewed
  change to that table in the same commit as the new bytes.
- `site/media.go` pins the fourteen photographs and the film by name, size
  and SHA-256. A new or replaced photograph is a reviewed change to that
  table plus the new file staged on the volume with
  `scripts/stage-media.sh`; the server refuses to start until the volume
  matches the table exactly.
- `compliance.json` moves with the content whenever a change adds a third
  party, a hand-off, or anything written to a visitor's device.

## Security invariants beyond the numbered requirements

- **No egress.** The origin makes no outbound connection, and the chart's
  NetworkPolicy denies all egress: `scripts/ci/chart-egress-pin.sh` proves
  the policy carries `Egress` with no rule over the complete render.
- **Media is verified, not trusted.** Construction hashes every pinned byte
  through a rooted filesystem capability, refusing symlinks and (on Linux)
  hard links, and a file that changes after verification is refused at
  serve time. Media responses carry their own `default-src 'none'; sandbox`
  policy.
- **Logs keep no visitor identity.** One record per request — request id,
  method, path, status, size, duration, protocol, and W3C trace ids when a
  well-formed `traceparent` arrives — and never the client address, the
  query string, a cookie or the user agent.

## Docs and attribution conventions

- **CHANGELOG discipline.** Keep a Changelog format; every artifact-classified
  PR immediately follows an empty `[Unreleased]` heading with its exact
  next-version and ISO date, matching every source lock; a documentation-only
  PR leaves `CHANGELOG.md` untouched (the file sits outside the documentation
  allowlist precisely so a no-release range can never claim one). There is no
  later release PR. Released history below that new heading is APPEND-ONLY and
  the gate proves it: `release_contract.py` refuses a snapshot
  whose released ladder is not strictly descending with non-increasing dates,
  and refuses any base-to-head range that removes, reorders, duplicates, or
  rewrites one byte of a released block; `docs/release-classifier.md` records
  the plausible mechanical edit this closes. Exactly one narrow lift exists: a released heading's
  DATE may move from one stated value to another through a reasoned line in
  `scripts/ci/changelog-correction-allowlist.txt`, which is spent the moment it
  lands. Nothing lifts a deletion, a reorder, or a rewritten entry.
- **Truthful README.** Claims report only what CI actually measured or the
  repository can demonstrate, and prose never advertises a capability or
  deployment state that does not exist yet. This repository publishes no
  badge.
- **Attribution for third-party assets.** Every third-party asset lands
  with its reviewed license. The six fonts under `site/assets/` (DM Sans,
  Libre Baskerville, Cormorant Garamond) are SIL OFL 1.1, recorded in
  `ATTRIBUTION.md` with their copyright lines and the licence text in
  `LICENSES/OFL-1.1.txt`. The code is MIT (`LICENSE`); the page's text, the
  photographs and the film belong to the business and are not covered by
  that licence.
