# Release-control readiness receipt

Every protected-`main` integration must remain able to publish one release,
including a one-commit squash and a multi-commit linear rebase. Repository code
validates either topology, but code on a pull-request branch cannot make its own
checks mandatory, require the branch to contain the latest protected base, or
make a GitHub Release immutable. Those are server controls and are therefore a
separate readiness boundary.

The automatic-release pull request must remain Draft until the repository owner
has configured and observed all of these controls:

- GitHub immutable releases enabled before the first affected Release is
  published. Enabling the control later does not retrofit a release that was
  already published.
- Exactly squash and rebase enabled and merge commits disabled in the active
  `Protect-Main` ruleset. That ruleset is what enforces merge behaviour on
  `refs/heads/main`, so it is the receipt's authoritative `merge_methods`
  source. The repository-settings merge toggles stay an owner-configured
  expectation the receipt deliberately does not read: GitHub returns them only
  to credentials carrying Contents write, and the settings job's token holds
  contents read alone.
- Pull requests and linear history required on `main`; zero platform approvals,
  no stale-review dismissal, no required reviewers/code-owner/latest-push
  approval, resolved review threads required, and only squash/rebase allowed.
- Signed commits required on `main`.
- Every required PR and CodeQL job bound to the GitHub Actions integration,
  with strict current-branch testing enabled.
- Creation, force pushes, and deletion denied.
- No ruleset bypass actor and no `update` restriction that would require the
  repository owner to bypass the rules merely to merge a passing pull request.
  `Protect-Main` is the only active repository-owned branch ruleset, so the
  `update` half is the whole story and is CI-proven; the bypass half is
  owner-verified with the standalone command below, because GitHub returns
  `bypass_actors` only to a credential with write access to the ruleset. See
  "Which side proves which invariant" below.
- Actions enabled with full-SHA pinning required, default workflow-token
  permissions read-only, and workflow tokens unable to approve pull requests.
- Private Vulnerability Reporting, secret scanning, and push protection
  enabled.
- Exact CodeQL merge protection (`high_or_higher` security alerts and `errors`
  analysis alerts), Code Quality `errors`, and Code Coverage minimum 80 with no
  maximum-drop threshold. These preview rules are retained, not silently
  discarded to fit a narrower API.

The repository owner remains the only person who chooses squash or rebase and
performs the merge. The settings receipt grants no merge authority.

## Publication authority

The successful-main orchestrator dispatches `release-publisher.yml` on
protected `main` and passes both the exact source SHA and the authoritative
completed PR-gate run ID. It creates no tag, registry object, Release, or other
publication state. The publisher first runs an unprivileged authorization job
with only Actions/content read access. That job
GETs the run by ID and requires the exact repository and head repository,
workflow name and path, `push` event, completed/success state, `main` branch,
and source SHA. It also GETs the exact run's complete job inventory and requires
exactly successful `application`, `chart`, and `security` jobs plus the two
context-appropriate skipped jobs, `container` and `dependency-review`, both of
which run on pull requests only. This repository publishes no coverage badge,
so nothing else belongs in that inventory, and a sixth job is refused as
foreign whatever it concluded. Those two are
pinned in the skipped direction as strictly as the rest are in the successful
one: a `container` job reporting success on a main push means its
pull-request condition is gone, and the inventory refuses that run rather than
authorizing a release against a changed gate.
Workflow-level success alone is insufficient. In the same bounded authorization
window it resolves the separate `codeql.yml` `push` run for that exact source
SHA, then requires the completed/success matrix jobs `analyze (go, manual)`,
`analyze (javascript-typescript, none)`, and `analyze (python, none)`. Missing, duplicate,
foreign, skipped, failed, cancelled, wrong-SHA, or still-pending records fail
closed before publication authority exists.

Before any tag, registry, or Release side effect, a separate
`repository_settings` job enters the `platform-release` environment. The
environment must use custom selected-branch policy exactly `main`, never the
broader protected-branches mode. The job reads zero variables and zero secrets
from it; a variable or secret left there is unused, and the contract suite
refuses any workflow that reads one. Its one GET-only settings-preflight step runs under the
job's own short-lived workflow token, declared as `GH_TOKEN: ${{ github.token }}`
under job permissions `contents: read` and nothing else. No GitHub App
credential is used and none is stored, so the receipt states exactly what that
token can read on a public repository: the repository record, private
vulnerability reporting, and the complete ruleset endpoints below. No output
carries the token into the separate publisher job. That publisher depends on
both read-only jobs, uses only its ordinary short-lived `GITHUB_TOKEN` for
contents/packages/OIDC publication, and cannot start when the settings GET is
denied, malformed, or inexact.

That publisher's first source-bound check also requires the explicit production
identity tuple `snaraj/hospedajedonlolo.com`, `ghcr.io/snaraj/hospedajedonlolo-com`, and
`ghcr.io/snaraj/charts/hospedajedonlolo-com`. The dotted GitHub repository name is
never reused or heuristically rewritten as a registry package name. A missing,
dotted, foreign, or otherwise changed package input fails before annotated-tag
or registry publication begins.

No settings of this repository have been observed yet. Creating the
`platform-release` environment and the `Protect-Main` ruleset, and enabling the
Administration-only controls, is the owner's work, and any preview rule input
GitHub's public REST and GraphQL mutation schemas cannot represent takes a
signed-in owner UI transaction. Until the owner posts the exact receipt from
the preflight below together with the owner-verified results below, the
release-control receipt remains an external Ready blocker for the first
automatic release.

`workflow_dispatch` remains callable through GitHub's normal interfaces, but
callability is not publication authority: an unmerged branch, pull-request
run, foreign workflow or repository, failed or incomplete run, stale SHA, and
mismatched run ID all fail before a privileged job starts. The protected-main
workflow identity signs the resulting artifacts; the annotated tag and every
artifact statement independently bind the authorized source SHA.

The publisher verifies the complete annotated-tag REST identity before
artifact work, but GitHub does not lock that tag until its Release becomes
immutable. PR/main CI scans source dependencies with `--include-dev-deps`, so a
development dependency can never hide from it (this repository has no Node and
no npm, and its Go module requires nothing), and the publisher scans the final
image digest with direct checksum-verified Trivy v0.72.0, severity set exactly
`HIGH,CRITICAL`, `ignore-unfixed=false`. After registry publication or exact
reuse and immediately before manifest construction, the publisher re-fetches
image alias `vX.Y.Z` and chart alias `X.Y.Z`; each response body digest,
registry digest header, and the produced/reused expected digest must be
identical. It then reads the raw OCI attestation carriers and SPDX in-toto
statements for exactly `linux/amd64` and `linux/arm64`, rejecting null,
malformed, duplicate, extra, foreign-platform, or foreign-subject payloads. The
deterministic JSON manifest binds the source SHA, successful-main run ID,
version/tag, exact image/chart repositories, semantic aliases and digests,
two-platform signer and provenance contract, and both scan policies/results.

New publication creates a draft Release with exactly that one manifest asset,
requires the closed REST asset metadata/digest, downloads and compares the
bytes, and only then publishes the draft. Every observed draft, retry winner,
and immutable Release must identify `github-actions[bot]` with numeric ID
`41898282` as its author; every staged or published manifest asset must identify
that same login and ID as its sole uploader. Missing, null, or foreign writers
fail closed. An exact zero-asset `prepared` draft
is the sole recoverable response-loss state: the publisher uploads without
clobber, re-reads the one-asset `staged` state, and continues. Existing,
response-lost, and concurrent-winner paths may resume only from those exact
states. The terminal step
re-fetches the authoritative `immutable: true` Release, revalidates the closed
one-asset inventory, downloads and compares the manifest again, and then
re-fetches both live tag records. It binds ref type/object SHA, tag, source
commit, message, tagger identity, and tagger instant to the signed source one
last time. No mutation follows. A moved, lightweight, missing, foreign,
malformed, response-lost, or byte-mismatched record fails closed even if the
immutable Release has already exposed the race. That terminal `immutable: true`
requirement is also what enforces the immutable-release switch per Release:
the settings job cannot read the switch, but a publication whose Release
GitHub does not report immutable never completes.

`release-audit.yml` runs weekly and manually with contents/packages read only.
For the latest Release it repeats the exact Release/manifest/successful-run/tag
bindings; resolves image `vX.Y.Z` and chart `X.Y.Z` aliases and requires the
manifest digests; verifies both Cosign identities, the exact two-platform SLSA
and strict raw SBOM set, the chart archive against the release source tree with
that Release's own image digest substituted exactly as the publisher does, and
the final image vulnerability policy. That policy is the publisher's own —
`trivy image --scanners vuln --severity HIGH,CRITICAL --exit-code 1
--ignore-unfixed=false` — and it carries no development-dependency scope:
`--include-dev-deps` is a source/lockfile concept that `trivy fs` understands
and that the installed Trivy rejects as an unknown flag on `trivy image`.
Development dependencies are covered where they can be, by the PR/main CI
source scan named above, and the audit does not restate that coverage as its
own. The image-digest substitution named at the head of this
paragraph is why the chart comparison still binds: the published chart carries the
released digest while the committed source keeps the fail-closed sentinel, so
the audit proves the published chart deploys the exact image the Release,
signature, and provenance are about. This
scheduled detection is defense in depth, never a substitute for the post-push
pre-manifest alias/SBOM proof. It has no settings token, OIDC, or publication
method.

## Read-only authoritative preflight

The preflight uses `gh api --method GET` only, with GitHub REST API version
`2026-03-10`. It reads exactly four endpoints: the repository record (identity
and default branch), `/private-vulnerability-reporting`, the exhaustive ruleset
inventory, and the single active repository-owned branch ruleset
`Protect-Main`. It reads no Administration-only endpoint, because the settings
job's token cannot. It does not create, update, or delete a setting, ref,
Release, package, or other resource. An authentication or schema error is a
denial.

Run it only after the repository owner has made the required settings change in
GitHub. Keep the value-only receipt outside the repository and remove it after
recording the result on the pull request:

```bash
receipt="$(mktemp)"
trap 'rm -f -- "${receipt}"' EXIT
python3 -I -B scripts/ci/release_contract.py settings-preflight \
  --repository snaraj/hospedajedonlolo.com > "${receipt}"
python3 -I -B scripts/ci/release_contract.py settings-receipt \
  --receipt "${receipt}" --repository snaraj/hospedajedonlolo.com
sha256sum "${receipt}"
```

The first command emits no receipt unless every live value is exact. The second
command revalidates the closed schema offline. Post the canonical receipt and
its digest as the bounded observation; never post API tokens, actor IDs, or a
raw ruleset response.

The exact successful receipt is:

```json
{
  "active_main_branch_ruleset_count": 1,
  "allow_deletions": false,
  "allow_force_pushes": false,
  "branch": "main",
  "code_quality_severity": "errors",
  "code_scanning_tools": [
    {
      "alerts_threshold": "errors",
      "security_alerts_threshold": "high_or_higher",
      "tool": "CodeQL"
    }
  ],
  "dismiss_stale_reviews_on_push": false,
  "maximum_code_coverage_drop": null,
  "merge_methods": ["rebase", "squash"],
  "minimum_code_coverage": 80,
  "private_vulnerability_reporting": true,
  "repository": "snaraj/hospedajedonlolo.com",
  "require_code_owner_review": false,
  "require_extra_approval_for_unattributed_changes": true,
  "require_last_push_approval": false,
  "require_linear_history": true,
  "require_pull_request": true,
  "required_approving_review_count": 0,
  "required_review_thread_resolution": true,
  "required_reviewers": [],
  "require_signed_commits": true,
  "required_status_checks": [
    {"context": "analyze (go, manual)", "integration_id": 15368},
    {"context": "analyze (javascript-typescript, none)", "integration_id": 15368},
    {"context": "application", "integration_id": 15368},
    {"context": "chart", "integration_id": 15368},
    {"context": "container", "integration_id": 15368},
    {"context": "dependency-review", "integration_id": 15368},
    {"context": "security", "integration_id": 15368}
  ],
  "restrict_creations": true,
  "restrict_updates": false,
  "strict_status_checks": true
}
```

Missing, extra, duplicated, name-only, foreign-integration, inverted, or stale
state fails closed. A successful receipt is necessary but not sufficient for
Ready: exact-head CI, current base, resolved findings, and a fresh independent
approval are still required.

### Which side proves which invariant

The receipt above is built by the same code on both sides, but the two sides
run it under different credentials, and GitHub does not show both credentials
the same fields. The split is therefore recorded rather than blurred, and the
preflight makes no conditional assertion: it asserts exactly what the enforcing
surface exposes to the settings job's token, under any credential.

**CI-proven** (asserted by the release publisher's `repository_settings` job on
every dispatch, under that job's read-only workflow token): repository identity
and default branch; the inventory holding exactly one active repository-owned
branch ruleset; private vulnerability reporting; the `Protect-Main` ruleset's
identity, source, enforcement and `refs/heads/main`-only condition; and every
field of its `rules[]` — required pull request and its exact parameters
(including `allowed_merge_methods`, the authoritative merge-method source, and
`require_extra_approval_for_unattributed_changes`), required status checks and
their GitHub-Actions integration binding, linear history, signatures,
creation/deletion/non-fast-forward restrictions, and the CodeQL/code-quality/
code-coverage rules. The code-coverage rule is admitted in exactly two
spellings of the same control, minimum 80 and no maximum-drop threshold:
`max_coverage_drop` absent, which is how GitHub returns a ruleset written
since its API began refusing an explicit `null`, or present as `null`.

That pull-request parameter set is compared for exact equality in both
directions, so GitHub adding a field is as fatal as GitHub dropping one: the
sibling repositories stopped publishing for exactly that reason when
`require_extra_approval_for_unattributed_changes` appeared on the live surface.
The remedy is always the same: re-anchor the pin in
`EXPECTED_PULL_REQUEST_PARAMETERS` to the deliberate value — never widen the
compare, never allow unknown fields through. The receipt field above and that
pin move together, and both this document's receipt and the contract tests are
part of that lockstep.

**Owner-verified** (asserted only by the repository owner, GET-only, under
their own credential, with the standalone commands below):

- The Administration-only settings the settings job's token cannot read at
  all: immutable releases enabled; Actions enabled with full-SHA pinning
  required; default workflow-token permissions read-only and workflow tokens
  unable to approve pull requests; secret scanning and push protection
  enabled. The receipt carries none of these fields — a receipt that does is
  foreign — and the preflight GETs none of their endpoints, because under the
  job token every such GET is a denial. The contract suite pins both
  absences.
- That `Protect-Main` has no bypass actor, below.

```bash
settings="$(mktemp)"
trap 'rm -f -- "${settings}"' EXIT
gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/snaraj/hospedajedonlolo.com/immutable-releases > "${settings}"
python3 -I -B scripts/ci/release_contract.py immutable-settings \
  --settings-json "${settings}"
# must print: exact
gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/snaraj/hospedajedonlolo.com/actions/permissions \
  --jq '"\(.enabled) \(.sha_pinning_required)"'
# must print: true true
gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/snaraj/hospedajedonlolo.com/actions/permissions/workflow \
  --jq '"\(.default_workflow_permissions) \(.can_approve_pull_request_reviews)"'
# must print: read false
gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/snaraj/hospedajedonlolo.com \
  --jq '.security_and_analysis | "\(.secret_scanning.status) \(.secret_scanning_push_protection.status)"'
# must print: enabled enabled
```

GitHub's REST reference for "Get a repository ruleset" states that "to prevent
leaking sensitive information, the bypass_actors property is only returned if
the user making the API request
has write access to the ruleset." The settings job's least-privilege token
carries no such write access, so the property is absent from its response;
asserting it in CI would make the receipt unbuildable and deny every release
before `rules[]` was read at all.

The receipt therefore carries no bypass field — and the deletion is
credential-independent, so the preflight above reads the property for nobody.
Re-running that preflight under the owner credential proves nothing about
bypass actors. The owner runs this instead, resolving the ruleset id in the
same block:

```bash
ruleset_id="$(gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/snaraj/hospedajedonlolo.com/rulesets \
  --jq '.[] | select(.name == "Protect-Main") | .id')"
gh api --method GET -H "X-GitHub-Api-Version: 2026-03-10" \
  "/repos/snaraj/hospedajedonlolo.com/rulesets/${ruleset_id}" --jq '.bypass_actors'
# must print: []
```

The property is returned only at ruleset write-access-level visibility, which
the owner credential has and the publisher's does not, per the redaction rule
quoted above. The command prints the value rather than a count because a
redacted property reads as `null` here, and `length` would reduce that same
`null` to the `0` an empty list gives — a count cannot tell "no bypass actor"
from "you cannot see bypass actors". Exactly `[]` passes. `null` means the
credential lacks that visibility and the check has not been performed. Any
other output is a bypass actor: the owner clears it before Ready and posts only
the `[]` result, never the actor entries, per the value-only rule above. This
is the observation "Working a change end to end" step 7 requires; CI cannot
make it and will not pretend to.

The Main Worker gate retired with issue #190. After the final author push,
exact-head adversarial approval, and green required checks, no further
distinct-context receipt is required: the coordinator alone changes the
Draft/Ready state, and the repository owner alone merges.

GitHub documents the immutable-release control and its protected tag/asset
behavior in [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
and documents strict required checks in the
[repository rulesets REST contract](https://docs.github.com/en/rest/repos/rules).

## One branch ruleset, and no owner-account merge restriction

The current threat model is public source for a privately operated, single-owner
homelab. Review this boundary before granting another collaborator, administrator,
automation principal, or tenant access. An agent holding the owner's credentials
has the owner's GitHub identity; these rules cannot distinguish that agent from
an interactive owner. Agents still have no delegated merge authority.

`Protect-Main` is the one active repository-owned branch ruleset. It keeps
every security check and signature requirement, denies creation, deletion and
force pushes, contains no `update` rule, and must carry an empty bypass list —
the invariant the receipt states as `restrict_updates: false` and the owner
command above proves as `[]`. Immutable tag protection and its own empty bypass
list remain separate.

The sibling repositories once carried a second branch ruleset, an
owner-account `update` restriction whose sole bypass actor was the repository
owner, so every ordinary merge of a passing pull request went around the rules
instead of through them. It was retired there and is never created here. The
receipt records the inventory itself — `active_main_branch_ruleset_count`
above — which is what makes those two statements cover the whole
branch-protection surface. A second active branch ruleset denies the preflight
rather than being described by it: `restrict_updates` reads `Protect-Main`
alone, so an `update` rule — and the bypass actor such a rule needs in order
to stay mergeable — could otherwise sit beside it unread. Introducing any
owner-account merge restriction is an owner decision that must first restore a
validator for it here; no step in this document merges a pull request or
changes a setting.
