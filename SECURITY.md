# Security

## Reporting

Report suspected vulnerabilities privately via GitHub's security advisory
form for this repository ("Report a vulnerability"). Please do not open a
public issue for anything security-sensitive. Reports are read by the
owner; you should normally hear back within a week.

## Supported versions

Only the latest released version (the newest `vX.Y.Z` tag) is supported.
Fixes ship as new versions, never as re-tags. Existing Releases that predate
GitHub's immutable-release control are not retroactively described as
immutable; no automatic release completes unless GitHub reports its Release
immutable, and the repository owner verifies the control read-only before the
first one.

## Posture (what you can rely on)

- The service is a single static Go binary in a shell-less distroless
  image, running as a non-root user, serving embedded static content and
  SHA-256-verified media from a read-only volume on port 8080, with no
  runtime dependencies and no outbound calls; the chart denies all egress.
- Images and charts are published only after successful main CI by an
  exact-SHA orchestrator that explicitly dispatches the protected-main
  publisher with that completed run's ID; the publisher creates the version
  tag. A read-only job
  validates the authoritative PR-gate record and exact job inventory plus the
  separate exact-SHA successful CodeQL main run and job inventory before the
  privileged publisher can start, so a manual/unmerged dispatch or skipped
  security job cannot mint artifacts. Readiness
  requires strict current-base checks, no ruleset bypass actor, and GitHub
  immutable releases enabled. The settings preflight runs under the job's own
  read-only token; no GitHub App credential exists for this repository. The
  publisher checksum-pins Trivy, rejects high/critical source findings
  (development dependencies included) and final-image findings, re-resolves both public aliases to the produced
  digests, validates each strict raw platform SBOM subject, and stages exactly one canonical
  evidence manifest, verifies its REST digest and downloaded bytes before
  publication, and terminally re-reads the immutable Release, manifest bytes,
  and annotated tag. The publisher remains multi-arch and keyless-signed
  (Cosign), with SBOM and SLSA provenance. A weekly read-only audit later re-binds
  public semantic aliases to those immutable records but is not publication
  authorization. Deployment consumes
  immutable digests.
- CI is secretless on pull requests; all third-party actions are pinned to
  full commit SHAs; scanners are checksum-pinned; secret scanning covers
  full history on every PR.
- Security behaviors have no toggles: there is no flag, env var, or config
  path that disables verification, probes, signing, or the fail-closed
  defaults — by design, and by review policy.

## Out of scope

Site content licensing, third-party services the page links or embeds
(Google Maps, WhatsApp, the visitor's mail client), the hosting platform's
infrastructure (tracked in its own repository), and reports requiring
physical or LAN access to the origin host.
