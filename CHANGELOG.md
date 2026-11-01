# Changelog

All notable changes to hospedajedonlolo.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `VERSION`, chart
metadata, these headings, and Helm's strict OCI chart tag use numeric SemVer.
Git, image, and GitHub Release tags use the exact plain `vX.Y.Z` form.

## [Unreleased]

## [0.1.1] - 2026-11-01

### Added

- The Hospedaje Don Lolo page, in Spanish with an English switch: the rooms,
  the farm, the film, the area map and the booking form, which hands the
  visitor's message to WhatsApp or to their own mail client. The page, its
  stylesheet, its script and its six fonts are embedded in the server exactly
  as delivered, and a test pins every byte.
- A standard-library Go server on port 8080: a closed set of routes, a
  Content-Security-Policy that admits only this origin, the inline `data:`
  favicon and the Google Maps frame, the usual security headers, truthful `/livez` and `/readyz`, and one
  log record per request with no client address and no query string.
- The fourteen photographs and the film are served at `/assets/<name>` from a
  read-only volume laid out as `immutable/<sha256>/<name>`. Each file is pinned
  by name, size and SHA-256, and the server hashes every pinned byte before it
  reports ready, so it refuses to start rather than show anything else. It
  then serves those verified bytes from memory, so nothing changed on the
  volume afterwards ever reaches a visitor. The film is verified the same way
  but withheld from delivery for now: public video through the edge needs the
  owner's decision under the platform's zero-spend boundary, so the page shows
  its poster until that decision lifts it.
  `scripts/stage-media.sh` copies the files into that layout and verifies them.
- A Helm chart: two replicas that roll one at a time, the media claim mounted
  read-only, ingress only from the one named tunnel connector, and no egress at
  all.
- The release path: every merge that changes the shipped artifact releases
  exactly one patch, authorized against the closed job inventory of the
  successful protected-main gate run and the same commit's CodeQL run. The
  publisher builds both architectures, scans the final image, signs the image
  and the chart without a stored key, binds provenance and
  strict raw two-platform SBOM schemas to the image, and publishes one
  immutable GitHub Release carrying one deterministic evidence manifest. A
  weekly read-only audit re-checks the latest Release.
- `compliance.json`: what the site records, that it stores nothing on a
  visitor's device, the Google Maps frame and its pending consent question,
  and the WhatsApp and email hand-offs, kept honest against the source and
  the live site.

## [0.1.0] - 2026-11-01

### Added

- Repository seed: the protected base the first release transition is measured
  from. It carries no application and publishes nothing.
