# hospedajedonlolo.com

The public page of Hospedaje Don Lolo, a family farm-stay on the road to the
hot springs near Santa Rosa de Cabal, Colombia: one bilingual page (Spanish
and English, opening in the visitor's browser language, with a switch)
showing the rooms, the farm, a short film and an area
map, with a booking form that hands the visitor's message to WhatsApp or to
their own mail client.

It is a single standard-library Go server. The page, its stylesheet, its
script and its six fonts (`site/`) are embedded in the binary byte for byte,
except two lines the owner asked for that pick the opening language;
the fourteen photographs, fifteen smaller copies made from them for the tiles,
the hero and the film's poster (`docs/media-derivatives.md`), and the film live
on a read-only volume and are served at `/assets/<name>`. The page names every
file it loads by its content address, `<name>.<sha256>.<ext>`, which the
server answers immutable only while the digest is the file's own. Every one of those files is pinned by SHA-256 —
the embedded ones in `site/site_test.go`, the volume ones in `site/media.go` —
and the server refuses to start if the volume does not match, then serves
the verified bytes from memory, with Range support for the film. There is no
frontend build, no Node and no npm.

## Run it locally

Requires Go 1.26 or newer. Make the smaller copies from the photographs
(`docs/media-derivatives.md`), stage all thirty files into the volume layout
the server reads (`immutable/<sha256>/<name>`), then start it:

```bash
scripts/stage-media.sh <directory-with-the-30-media-files> /tmp/donlolo-media
MEDIA_ROOT=/tmp/donlolo-media MEDIA_MAX_CONCURRENT=8 go run ./cmd/server
```

The page is then at <http://localhost:8080/>. `scripts/stage-media.sh` makes a
real copy of each pinned file and verifies its size and digest before and
after copying; it refuses anything that does not match `site/media.go`, and
running it again changes nothing. `PORT`, `LOG_FORMAT` (`json` or `text`) and
`LOG_LEVEL` are optional; `/livez` and `/readyz` are the health endpoints.

## Repository layout

- `site/` — the published content and its pins.
- `cmd/server`, `internal/server` — the origin: routing, security headers and
  Content-Security-Policy, the verified media store, request logging.
- `chart/` — the Helm chart: two replicas, the media claim mounted read-only,
  ingress from one named tunnel connector only, no egress.
- `compliance.json` — what the site records, stores and hands to third
  parties, kept honest against the source and the live site by
  `scripts/ci/compliance_manifest.py`.
- `scripts/ci/` — the contract suites and pins the PR gate runs.

`AGENTS.md` is the contract for anyone changing this repository, including
the exact local gate under "Quality gates".

## Releases

Every merge that changes the shipped artifact advances exactly one patch and
is released by CI alone, after the protected-main gate run and the
exact-SHA successful CodeQL run for the same commit are both verified. The
publisher builds both architectures, scans source dependencies
with `--include-dev-deps` and the final image with a checksum-pinned Trivy
binary at HIGH/CRITICAL, signs the image and the chart without a stored key,
and validates each platform's provenance and SBOM against a
strict raw SBOM schema. After the pre-manifest alias and SBOM proof re-binds
both public aliases to the produced digests, it publishes one immutable
GitHub Release carrying one canonical JSON evidence manifest. A weekly read-only audit
re-checks the latest Release. `docs/release-governance.md` is the runbook.

## Licence

The code is MIT-licensed (`LICENSE`). The fonts are SIL Open Font License 1.1
(`ATTRIBUTION.md`, `LICENSES/OFL-1.1.txt`). The page's text, the photographs
and the film belong to Hospedaje Don Lolo and are not covered by the MIT
licence.
