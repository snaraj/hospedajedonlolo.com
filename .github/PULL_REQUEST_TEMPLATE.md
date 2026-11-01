<!-- Agent-authored PRs open Draft. Delete no section; write "none" where empty. -->

## Summary

## Issue

Closes #<!-- same-repository issue number -->

## Exact identity and release consequence

- Protected base: `main` @ <!-- 40-hex sha -->
- Exact head: <!-- 40-hex sha; update after every author push -->
- Next patch release: `vX.Y.Z`
- numeric `VERSION`/chart/changelog `X.Y.Z` maps exactly to plain `vX.Y.Z`
  Git/image tags and numeric Helm OCI chart tag: yes/no
- Release publication is separate from deployment/promotion: confirm

## Scope and exclusions

- Files owned:
- Deliberately excluded:
- Predecessors / successors / collision paths: none

## Evidence

| Command or check | Result |
| --- | --- |
| Release transition and hostile event/state suite | |
| Exact PR-gate jobs + exact-SHA CodeQL run/jobs and manual/unmerged dispatch denial | |
| Post-push image/chart alias rebind + strict raw platform SBOM hostile suite | |
| Deterministic manifest, dev-dependency vulnerability policy, and recurring alias-audit hostile suite | |
| Required CI, coverage, security, and quality checks | |

## Exact-head review

- Author applies `requires-review` only after exact-head/body/evidence completion;
  the independent reviewer removes it with either verdict: pending/yes
- Immutable-release + strict required-checks/no-bypass settings receipt: pending/exact
- Independent normal-comment verdict has exactly one `HEAD: <exact reviewed 40-lowercase-hex>`,
  one `VERDICT: APPROVE` or `VERDICT: REQUEST-CHANGES`, mutation and claim-audit
  evidence, and final `- <Agent> (adversarial reviewer)`: pending
- Base freshness and successful required checks re-verified before Ready: pending

## Residual risks

## Rollback
