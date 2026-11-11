# CI map — what each pin proves, and why the triggers are what they are

`AGENTS.md` "CI map" names the workflows, their triggers, and the rules that
bind an author. This document carries the per-pin detail and the reasoning
behind the trigger decisions. It adds no rule.

## What the three chart pins prove

Each pin reads the COMPLETE `helm template smoke chart --kube-version v1.36.0`
render through `scripts/ci/chart_render_census.py`'s document reader, never
one `--show-only` extract, so a second object, a quoted or escaped key, or an
object wrapped in a List cannot hide from it.

- **`scripts/ci/chart-ingress-pin.sh`** — the ingress peer-identity pin.
  Beyond the default render, the refusal of an unpinned instance, and the
  proof that the instance is what separates one connector from another, it
  extracts the single policy's ingress sub-tree and compares it byte for
  byte against the canonical text built from values, and refuses fourteen
  hostile whole-render shapes by that extraction ALONE — among them a second
  policy spelled `kind :`, quoted, escaped, or wrapped in a List, each of
  which a raw-line extraction never saw.
- **`scripts/ci/chart-egress-pin.sh`** — the whole-render egress census:
  exactly one NetworkPolicy, bound to the workload, whose `policyTypes`
  carries `Egress` with no egress rule at all, so the origin can open no
  outbound connection. The deny-all is carried by the `Egress` entry alone
  (the API server drops an empty `egress: []`), which is why removing that
  entry, adding any rule, or adding a second policy is refused.
- **`scripts/ci/chart-media-pin.sh`** — the media pin. Media is always on
  in this chart; there is no switch. Over the complete render it proves:
  (a) the default render is exactly the media shape — one Pod-bearing
  object, a Deployment with exactly one container and no init or ephemeral
  containers; no PersistentVolume or PersistentVolumeClaim created by the
  chart; the pod's volumes exactly the 16Mi in-memory `tmp` emptyDir plus
  one claim named by `media.claimName`, read-only at the volume; the
  container's mounts exactly `tmp` at `/tmp` plus that claim at
  `media.mountPath`, read-only at the mount, with no `subPath`,
  `volumeDevices` or `envFrom`; the only `MEDIA_*` variables `MEDIA_ROOT`
  equal to the mount path and `MEDIA_MAX_CONCURRENT` equal to the budget,
  both plain values; `readOnlyRootFilesystem: true` — compared whole-list
  and type-exact, so `readOnly: 1` is not `true`; (b) every incomplete or
  foreign media value — a blank or absent claim, a relative, dot-dot,
  `/tmp` or absent mount path, a budget of 0, 257, a string or none, a
  foreign `enabled` key, no media block — refused by the schema, each by
  name; (c) a mount-path override moves the mount and `MEDIA_ROOT`
  together; (d) claim and budget overrides move the volume and the variable
  with them; (e) a built-in battery of 32 hostile renders all refused by
  (a).

## Why `container` has no main-push trigger

`container` remains a REQUIRED pull-request check. What it does not do is
rebuild the identical tree a second time on the main push, where it would
gate nothing: squash/rebase-only merges under strict required checks land the
exact tree it already built, and the released bytes are still built, scanned,
signed and attested by `release-publisher.yml`.

## Why there is no coverage badge

The gate enforces the coverage floor and reports the measured total in the
`application` job's step summary, and that is all. A badge would need a write
path, and a write path inside `pr-gate.yml` would sit in the very job
inventory the release publisher authorizes against. The contract suite
refuses a badge job, a write grant, or a hand-off artifact in the gate.

## What the compliance gate proves, and where it cannot reach

`compliance.json` states what the site records, what it stores on a
visitor's device and when (nothing), which third-party origins a page may
contact (the Google Maps frame, whose consent question is `pending` on a
named decision issue), which hand-offs the visitor can start (WhatsApp and
mail), which legal pages exist, and which edge behaviours are known and why.
Two checks hold the site to it, and each answers a different question:

- `scripts/ci/test_compliance_manifest.py`, in the PR gate's contract suites,
  keeps the manifest valid and current: a closed schema (a present section,
  `null` included, must be a list); a storage entry only while a file under
  `site/` still WRITES that name as that kind, and no write the manifest
  leaves undeclared; evidence files that still exist; a third party's
  `consent` either `not-required` (with no `decision`) or `pending` (with the
  issue URL that holds the decision, and nothing else admitted); a hand-off
  `target` that is a bare https origin, `mailto:` or `tel:`, declared once,
  still built by the site's script, and every URL the script builds declared
  as a third party or a hand-off; and the judging rules themselves, each
  refused on its own. A write, and a built URL, is what
  `compliance_manifest.py` reads in code only — a comment, a regular
  expression or markup builds and writes nothing — and a file whose meaning
  depends on whether an ambiguous `/` divides or opens a regular expression
  is read both ways.
- `compliance-live.yml`, weekly and on demand, GETs production and judges
  what the edge serves: the answer read whole (a body past 2 MiB, or short of
  its `Content-Length`, fails rather than being judged by its prefix); CSP
  fetch directives admit exactly the declared origins, `data:` only where
  it names no host (images, fonts, media), and no wildcard, bare scheme or
  `'unsafe-inline'` script source; a declared injected script passes only
  while some enforced policy blocks every inline script; framing is denied;
  HSTS lasts a year; nosniff and a Referrer-Policy are present; the document
  sets no cookie; every reporting endpoint and every script, stylesheet or
  embed in the served HTML is this origin's or declared; every published
  legal page answers 200. Hand-offs are visitor-started navigations, not
  loads, so the live judge notes them and judges nothing about them. It also
  runs on a pull request that changes the judge, but not on one that only
  edits the manifest, which usually declares what the next deployment ships.

A declared entry that no longer occurs is refused as stale, so no exemption
outlives its case. A refusal a manifest line can lift prints that line; the
rest — a missing header, a cookie on the document, a write on load, an
injected script the CSP can let run, an incomplete answer — print none,
because they need a code, policy or owner decision. What neither check can
see: what Google's frame does inside the visitor's browser, a screen
reader's actual reading, and anything only a lawyer can judge.

## The documented GitHub behaviours the release path depends on

GitHub documents that `GITHUB_TOKEN`-created refs suppress recursive workflow
events except explicit dispatch, that `workflow_run` fires regardless of
conclusion and uses default-branch context, and that concurrency ordering is
not a release ledger. Therefore the success check, payload `head_sha`, tag-ref
dispatch, and independent per-SHA paths are load-bearing. The orchestrator's
`branches: [main]` filter only spares the empty runs a pull request's gate
used to start: it matches the triggering run's head branch by name, which a
fork's branch can also carry, so the job's own conditions (success, push
event, branch `main`) remain the guard.

- <https://docs.github.com/en/actions/concepts/security/github_token>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run>
- <https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency>
