# Changelog

All notable changes to hospedajedonlolo.com. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `VERSION`, chart
metadata, these headings, and Helm's strict OCI chart tag use numeric SemVer.
Git, image, and GitHub Release tags use the exact plain `vX.Y.Z` form.

## [Unreleased]

## [0.1.7] - 2026-11-10

### Fixed

- Opening the area map no longer tells Google which page the visitor came
  from: the map frame sends no referrer, like every other request the page
  makes (#16).
- In Firefox before version 121 the page no longer scrolls behind an open
  photograph, and in Safari before version 15.4 "Ask by email" opens an email
  instead of WhatsApp. Current browsers behave exactly as before.

### Changed

- The page looks and reads exactly as before but loads about half as much on
  a first visit. The room and gallery tiles show smaller copies of their
  photographs, at twice the size they are drawn; the large photograph at the
  top offers 1280- and 1600-pixel copies to screens that do not need all of
  its 2000 pixels; and the film's poster is a lighter copy. Tapping a photograph
  still opens the full original. Measured locally in Chromium, a first visit
  at 390 pixels wide fell from 4.41 MB to 1.79 MB (2.04 MB on a 3x phone
  screen, which still gets the full top photograph), and at 1440 pixels from
  6.27 MB to 2.91 MB.
- After a release, a visitor can no longer see the new page with an older
  stylesheet or script. Every file the page loads is now named by its content
  (`name.<sha256>.ext`) and may be kept for a year, while the page itself is
  still checked on every visit; an outdated name is refused rather than
  answered with other bytes.
- The fifteen smaller copies are new pinned media. They must be on the media
  volume, staged as `docs/media-derivatives.md` describes, before this release
  is promoted: the server refuses to start without them.
- A change confined to workflows, CI scripts or Go tests no longer cuts a
  release, since no byte of the image or chart can come from those paths. The
  container build now runs the tests in a stage of their own that the shipped
  binary is never built from, which is what makes that true; the binary is
  byte-identical to the one the old build produced.
- CodeQL moves to v4.39.3 and the signing tool installer to v4.1.3, carrying
  Dependabot #14 and #15 under the signed release identity. The release audit's
  action pins are checked against the publisher's instead of fixed values, tool
  downloads retry before their checksums are verified, and the release
  orchestrator no longer starts an empty run for every pull request.

## [0.1.6] - 2026-11-02

### Changed

- The CodeQL analysis workflow moves its `init`/`analyze` pair to
  `github/codeql-action` v4.39.1, the pin naranjo.online already runs. This
  carries Dependabot PR #4 under the signed release identity (#12).

## [0.1.5] - 2026-11-02

### Changed

- The privacy notice no longer says the visitor's browser may send
  network-error reports, in Spanish or in English: the delivery network
  stopped requesting them on 2026-11-02. `compliance.json` drops the matching
  reporting-endpoint observation, which the live check would otherwise refuse
  as stale (#10).

## [0.1.4] - 2026-11-02

### Added

- A short privacy notice in Spanish and English, folded above the footer
  (`/#privacidad`): no cookies or device storage, minimal server records
  without the visitor's address, Cloudflare as the delivery network, the map
  on request, the WhatsApp and email hand-offs, and how to ask about one's
  data under Colombia's Ley 1581 and, for EU visitors, the GDPR. The owner
  decided on 2026-11-02 to publish it (issue #2, option 2).

### Changed

- The area map loads only when the visitor asks for it: its frame waits
  behind a "Mostrar el mapa / Show the map" button, and the place buttons
  load it as before, so Google is contacted only on that request.
  `compliance.json` now records Google Maps as needing no prior consent and
  the privacy page as published.

## [0.1.3] - 2026-11-02

### Changed

- The compliance gate knows a third kind of edge observation,
  `injected-script-origin`: an external script the edge injects from another
  origin. Like an injected inline script, a declaration passes only while an
  enforced policy blocks scripts from that origin, and it is stale once the
  script is gone. There, `'self'` means the fetched document's own host after
  any redirect, whatever the scheme or port.
- The gate parses a Content-Security-Policy as browsers do: only ASCII
  whitespace separates sources, and a directive carrying a non-ASCII code
  point is ignored, so it never counts as blocking anything.
- `compliance.json` declares the edge's free Web Analytics beacon this way.
  The owner decided on 2026-11-02 to keep it as it is; this origin's CSP
  blocks it, so it never runs and collects nothing. The live check now passes.

## [0.1.2] - 2026-11-02

### Changed

- The film is delivered. The owner decided on 2026-11-02 to serve it from the
  site's own volume like the photographs, with Range support, accepting the
  platform's recorded risk for public video on a self-serve edge plan.
- The page opens in the visitor's browser language: the first Spanish or
  English preference wins, and any other browser gets English. Location is not
  used. The language switch works exactly as before.
- `compliance.json` declares the two edge behaviours naranjo.online declares:
  the bot-detection loader this origin's CSP blocks, and the NEL reporting
  endpoint.

### Removed

- The withheld-media mechanism (`site.Withheld` and the server's `Withheld`
  option), unused once the film is delivered.

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
