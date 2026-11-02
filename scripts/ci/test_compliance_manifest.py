"""Behaviour of `compliance_manifest.py`: one compliant answer passes, and each
construct the gate exists to refuse turns it red on its own.

Every case starts from the same compliant manifest and document and changes
exactly one thing, so a refusal is attributable to that one change and a
passing baseline proves the refusal is not the gate's default answer.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import io
import json
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import compliance_manifest as gate

ROOT = Path(__file__).resolve().parents[2]
SITE = "https://site.example/"
REPORTS = "https://reports.example"
MARKER = "/edge-injected/"


def manifest() -> dict:
    return {
        "schema": "compliance/v1",
        "liveUrl": SITE,
        "dataCollected": [
            {"what": "request paths", "where": "pod log", "purpose": "operating the site", "evidence": "evidence.go"}
        ],
        "storage": [
            {"name": "theme", "kind": "cookie", "writtenWhen": "visitor-action", "purpose": "reading mode"},
            {"name": "width", "kind": "localStorage", "writtenWhen": "visitor-action", "purpose": "column width"},
        ],
        "thirdParties": [],
        "legalPages": [{"id": "privacy", "status": "pending", "decision": "https://github.com/owner/site/issues/1"}],
        "edgeObservations": [
            {"kind": "injected-inline-script", "marker": MARKER, "reason": "edge", "issue": "https://github.com/owner/infra/issues/2"},
            {"kind": "reporting-endpoint", "origin": REPORTS, "reason": "edge", "issue": "https://github.com/owner/infra/issues/2"},
        ],
        "handOffs": [],
    }


INJECTED_BODY = f"(function(){{var s='{MARKER}main.js'}})();"
INJECTED = f"<script>{INJECTED_BODY}</script>"
HTML = (
    "<!doctype html><html lang=en><head>"
    '<script type="module" src="/assets/index.js"></script>'
    '<link rel="stylesheet" href="/assets/index.css">'
    '<link rel="icon" href="/favicon.svg">'
    "</head><body><main><a href=\"https://elsewhere.example/\">a link is not a load</a></main>"
    f"{INJECTED}"
    "</body></html>"
)


# The site's own policy, copied from `contentSecurityPolicy` in
# internal/server/types.go; `test_the_fixture_policy_is_the_servers_policy`
# fails the day the two differ.
SITE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; media-src 'self'; "
    "frame-src https://maps.google.com https://www.google.com; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)
# The site's page in miniature: an inline data: favicon, its own stylesheet,
# photographs and film, the Google Maps frame waiting behind its button (no
# src until the visitor asks, issue #2), the privacy notice, hand-off links
# that are not loads, its one script, and the edge's injected script the
# fixture declares.
SITE_HTML = (
    '<!doctype html><html lang="es"><head>'
    '<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27%3E%3C/svg%3E">'
    '<link rel="stylesheet" href="style.css">'
    "</head><body><main>"
    '<a class="button small" href="https://wa.me/570000000000">Reservar</a>'
    '<a href="mailto:owner@site.example">correo</a> <a href="tel:+570000000000">llamar</a>'
    '<img src="assets/hero.webp" alt=""><img loading="lazy" src="assets/garden.webp" alt="">'
    '<video controls playsinline><source src="assets/film.mp4" type="video/mp4"></video>'
    '<div class="map-frame"><iframe id="area-map" title="map" loading="lazy" '
    'data-src="https://maps.google.com/maps?q=Somewhere&amp;z=12&amp;output=embed"></iframe>'
    '<button id="show-map" class="button" type="button">Mostrar el mapa</button></div>'
    '<section class="section privacy" id="privacidad"><details><summary>Privacidad</summary></details></section>'
    '</main><script src="app.js"></script>'
    f"{INJECTED}"
    "</body></html>"
)


def site_manifest() -> dict:
    """The shipped manifest, pointed at the fixture site with the fixture edge's observations."""
    value = json.loads(gate.MANIFEST.read_text(encoding="utf-8"))
    value["liveUrl"] = SITE
    value["edgeObservations"] = manifest()["edgeObservations"]
    return value


def headers(**overrides: str | None) -> list[tuple[str, str]]:
    base = {
        "Content-Security-Policy": "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Report-To": json.dumps({"group": "edge", "max_age": 60, "endpoints": [{"url": REPORTS + "/report?s=x"}]}),
        "NEL": '{"report_to":"edge","max_age":60}',
        "Content-Type": "text/html; charset=utf-8",
    }
    for key, value in overrides.items():
        base[key.replace("_", "-")] = value
    return [(key, value) for key, value in base.items() if value is not None]


def document(html: str = HTML, status: int = 200, **overrides: str | None) -> gate.Fetched:
    return gate.Fetched(SITE, status, headers(**overrides), html.encode())


class JudgeTests(unittest.TestCase):
    def assertRefused(self, verdict: gate.Verdict, fragment: str) -> None:
        self.assertTrue(
            any(fragment in refusal for refusal in verdict.refusals),
            f"expected a refusal containing {fragment!r}, got {verdict.refusals}",
        )

    def test_the_compliant_baseline_passes(self) -> None:
        verdict = gate.judge(manifest(), document(), {})
        self.assertEqual(verdict.refusals, [])
        self.assertIn(f"declared injected script seen: {MARKER}", verdict.notes)

    def test_a_non_200_document_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(status=403), {}), "answered 403")

    def test_a_missing_csp_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=None), {}), "no Content-Security-Policy")

    def test_a_csp_without_default_src_is_refused(self) -> None:
        verdict = gate.judge(manifest(), document(Content_Security_Policy="script-src 'self'; frame-ancestors 'none'"), {})
        self.assertRefused(verdict, "no default-src")

    def test_an_undeclared_origin_in_any_fetch_directive_is_refused_with_its_lift(self) -> None:
        for directive in ("script-src", "font-src", "connect-src", "img-src", "style-src", "frame-src"):
            with self.subTest(directive=directive):
                csp = f"default-src 'self'; {directive} 'self' https://cdn.example; frame-ancestors 'none'"
                verdict = gate.judge(manifest(), document(Content_Security_Policy=csp), {})
                self.assertRefused(verdict, f"{directive} admits the undeclared origin https://cdn.example")
                self.assertRefused(verdict, '"origin": "https://cdn.example"')

    def test_a_declared_origin_passes_and_an_unused_declaration_is_stale(self) -> None:
        declared = manifest()
        declared["thirdParties"] = [
            {"origin": "https://cdn.example", "purpose": "fonts", "consent": "not-required", "reason": "self-hosting is planned"}
        ]
        csp = "default-src 'self'; font-src https://cdn.example; frame-ancestors 'none'"
        self.assertEqual(gate.judge(declared, document(Content_Security_Policy=csp), {}).refusals, [])
        self.assertRefused(gate.judge(declared, document(), {}), "https://cdn.example, which the live CSP no longer admits")

    def test_wildcards_and_bare_schemes_are_refused(self) -> None:
        for source, directive, fragment in (
            ("*", "img-src", "names no single origin"),
            ("https:", "connect-src", "names no single origin"),
            ("*.example", "script-src", "names no single origin"),
            ("data:", "script-src", "admits the bare scheme data:"),
        ):
            with self.subTest(source=source):
                csp = f"default-src 'self'; {directive} {source}; frame-ancestors 'none'"
                self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), fragment)

    def test_data_images_are_ordinary(self) -> None:
        csp = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])

    def test_inline_or_eval_script_sources_are_refused_but_hashes_pass(self) -> None:
        for source, fragment in (
            ("'unsafe-inline'", "runs code no file of this repository shipped"),
            ("'unsafe-eval'", "runs code no file of this repository shipped"),
            ("'strict-dynamic'", "a keyword this gate does not admit"),
        ):
            with self.subTest(source=source):
                csp = f"default-src 'self'; script-src 'self' {source}; frame-ancestors 'none'"
                self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), fragment)
        # Inline style is not script: the gate leaves it to the CSP tests that own it.
        csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])
        # A hash names bytes, not a place, so it admits no origin. With no
        # exempted script on the page there is nothing it could let run.
        quiet = manifest()
        quiet["edgeObservations"] = quiet["edgeObservations"][1:]
        html = HTML.replace(INJECTED, "")
        csp = "default-src 'self'; script-src 'self' 'sha256-abc='; frame-ancestors 'none'"
        self.assertEqual(gate.judge(quiet, document(html=html, Content_Security_Policy=csp), {}).refusals, [])

    def test_a_declared_injected_script_passes_only_while_every_inline_script_is_blocked(self) -> None:
        # The exemption's stated reason is that the CSP blocks the script. A
        # policy that can admit inline code -- a nonce, a hash, or
        # 'unsafe-inline' in the directive that governs <script> elements --
        # no longer proves that, whether or not it names this script's bytes.
        digest = base64.b64encode(hashlib.sha256(INJECTED_BODY.encode()).digest()).decode()
        probe = f'<script nonce="bm9uY2U=">/* {MARKER} */ window.reviewProbe=1;</script>'
        for csp, html in (
            ("default-src 'self'; script-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'", HTML.replace("</body>", probe + "</body>")),
            ("default-src 'self'; script-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'", HTML),
            (f"default-src 'self'; script-src 'self' 'sha256-{digest}'; frame-ancestors 'none'", HTML),
            (f"default-src 'self'; script-src-elem 'self' 'sha384-abc='; frame-ancestors 'none'", HTML),
            ("default-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'", HTML),
            ("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", HTML),
            # An engine without script-src-elem reads script-src.
            ("default-src 'self'; script-src-elem 'self'; script-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'", HTML),
            # No directive governs scripts at all, so nothing blocks them.
            ("frame-ancestors 'none'; object-src 'none'", HTML),
        ):
            with self.subTest(csp=csp, probe=probe in html):
                verdict = gate.judge(manifest(), document(html=html, Content_Security_Policy=csp), {})
                self.assertRefused(verdict, f"declared injected script marked {MARKER!r}, which this CSP can let run")
        # Every enforced policy must admit a script for it to run, so one
        # policy that blocks all inline code is enough to keep it inert.
        nonce = "default-src 'self'; script-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'"
        both = [("Content-Security-Policy", nonce), *headers()]
        self.assertEqual(gate.judge(manifest(), gate.Fetched(SITE, 200, both, HTML.encode()), {}).refusals, [])
        # script-src-elem governs <script> elements, so a nonce confined to
        # attribute handlers leaves the element blocked.
        attr = "default-src 'self'; script-src-attr 'nonce-bm9uY2U='; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=attr), {}).refusals, [])

    def test_a_declared_injected_script_origin_passes_only_while_the_csp_blocks_it(self) -> None:
        # The edge's analytics beacon, as the edge injects it: an external
        # module script with SRI. Declared, it passes only while an enforced
        # policy refuses scripts from its origin, because that block is the
        # declaration's whole reason.
        beacon = "https://beacon.example"
        tag = f'<script type="module" src="{beacon}/beacon.min.js" integrity="sha512-abc=" crossorigin="anonymous"></script>'
        html = HTML.replace("</body>", tag + "</body>")
        declared = manifest()
        declared["edgeObservations"].append(
            {"kind": "injected-script-origin", "origin": beacon, "reason": "edge", "issue": "https://github.com/owner/infra/issues/3"}
        )
        verdict = gate.judge(declared, document(html=html), {})
        self.assertEqual(verdict.refusals, [])
        self.assertIn(f"declared injected script origin seen: {beacon}", verdict.notes)
        self.assertRefused(gate.judge(manifest(), document(html=html), {}), f"loads script from the undeclared origin {beacon}")
        message = f"declared injected origin {beacon}, which this CSP can let run"
        for csp in (
            f"default-src 'self'; script-src 'self' {beacon}; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' beacon.example/beacon.min.js; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' http://beacon.example; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' https:; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' *.example; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' 'strict-dynamic'; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' 'nonce-bm9uY2U='; frame-ancestors 'none'",
            "default-src 'self'; script-src 'self' 'sha512-abc='; frame-ancestors 'none'",
            f"default-src 'self' {beacon}; frame-ancestors 'none'",
            # No directive governs scripts at all, so nothing blocks them.
            "frame-ancestors 'none'; object-src 'none'",
            # An engine without script-src-elem reads script-src.
            f"default-src 'self'; script-src-elem 'self'; script-src 'self' {beacon}; frame-ancestors 'none'",
        ):
            with self.subTest(csp=csp):
                self.assertRefused(gate.judge(declared, document(html=html, Content_Security_Policy=csp), {}), message)
        # One enforced policy that blocks it is enough, as for inline scripts.
        admitting = f"default-src 'self'; script-src 'self' {beacon}; frame-ancestors 'none'"
        both = gate.Fetched(SITE, 200, [("Content-Security-Policy", admitting), *headers()], html.encode())
        self.assertFalse(any(message in refusal for refusal in gate.judge(declared, both, {}).refusals))
        # Another origin's host never admits it, and a stylesheet from the
        # declared origin is not the declared script.
        other = "default-src 'self'; script-src 'self' https://elsewhere.example; frame-ancestors 'none'"
        self.assertFalse(any(message in r for r in gate.judge(declared, document(html=html, Content_Security_Policy=other), {}).refusals))
        sheet = HTML.replace("</body>", f'<link rel="stylesheet" href="{beacon}/x.css"></body>')
        self.assertRefused(gate.judge(declared, document(html=sheet), {}), f"loads link stylesheet from the undeclared origin {beacon}")
        # A declaration whose script no longer occurs is stale.
        self.assertRefused(gate.judge(declared, document(), {}), f"injected script origin {beacon}, which no longer occurs")
        # Check mode requires the origin.
        broken = manifest()
        broken["edgeObservations"].append({"kind": "injected-script-origin", "reason": "edge", "issue": "https://github.com/owner/infra/issues/3"})
        self.assertTrue(any("injected script loads from" in refusal for refusal in gate.validate(broken)))

    def test_framing_must_be_denied_somewhere(self) -> None:
        csp = "default-src 'self'"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp, X_Frame_Options=None), {}), "framing")
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])
        wide = "default-src 'self'; frame-ancestors https://other.example"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=wide), {}), "frame-ancestors admits")

    def test_hsts_must_last_a_year(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Strict_Transport_Security="max-age=86400"), {}), "Strict-Transport-Security")
        self.assertRefused(gate.judge(manifest(), document(Strict_Transport_Security=None), {}), "Strict-Transport-Security")

    def test_nosniff_and_referrer_policy_are_required(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(X_Content_Type_Options=None), {}), "nosniff")
        self.assertRefused(gate.judge(manifest(), document(Referrer_Policy="unsafe-url"), {}), "Referrer-Policy")
        self.assertRefused(gate.judge(manifest(), document(Referrer_Policy=None), {}), "Referrer-Policy")

    def test_a_cookie_on_the_document_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Set_Cookie="tracker=1; Path=/"), {}), "'tracker'")

    def test_an_undeclared_reporting_endpoint_is_refused_and_a_vanished_one_is_stale(self) -> None:
        other = json.dumps({"group": "x", "endpoints": [{"url": "https://collector.example/r"}]})
        self.assertRefused(gate.judge(manifest(), document(Report_To=other), {}), "undeclared origin https://collector.example")
        self.assertRefused(gate.judge(manifest(), document(Report_To=other), {}), f"reporting endpoint {REPORTS}, which no longer occurs")
        endpoints = 'default="https://collector.example/r"'
        self.assertRefused(gate.judge(manifest(), document(Reporting_Endpoints=endpoints), {}), "https://collector.example")
        csp = "default-src 'self'; frame-ancestors 'none'; report-uri https://collector.example/csp"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), "https://collector.example")

    def test_an_undeclared_inline_script_is_refused_and_a_vanished_one_is_stale(self) -> None:
        html = HTML.replace(MARKER, "/something-else/")
        verdict = gate.judge(manifest(), document(html=html), {})
        self.assertRefused(verdict, "inline script this repository did not build")
        self.assertRefused(verdict, f"marked {MARKER!r} that no longer occurs")

    def test_a_remote_script_stylesheet_or_embed_in_the_html_is_refused(self) -> None:
        for snippet in (
            '<script src="https://cdn.example/x.js"></script>',
            '<link rel="stylesheet" href="https://fonts.example/css">',
            '<link rel="preconnect" href="https://fonts.example">',
            '<img src="https://pixel.example/p.gif" alt="">',
            '<iframe src="https://widget.example/"></iframe>',
            '<img srcset="/a.png 1x, https://pixel.example/b.png 2x" alt="">',
        ):
            with self.subTest(snippet=snippet):
                html = HTML.replace("</body>", snippet + "</body>")
                self.assertRefused(gate.judge(manifest(), document(html=html), {}), "loads")

    def test_a_published_legal_page_must_answer_html(self) -> None:
        published = manifest()
        published["legalPages"] = [{"id": "privacy", "status": "published", "path": "/privacy"}]
        ok = gate.Fetched(SITE + "privacy", 200, [("Content-Type", "text/html")], b"<p>notice</p>")
        self.assertEqual(gate.judge(published, document(), {"/privacy": ok}).refusals, [])
        missing = gate.Fetched(SITE + "privacy", 404, [("Content-Type", "text/plain")], b"")
        self.assertRefused(gate.judge(published, document(), {"/privacy": missing}), "answered 404")
        wrong = gate.Fetched(SITE + "privacy", 200, [("Content-Type", "application/json")], b"{}")
        self.assertRefused(gate.judge(published, document(), {"/privacy": wrong}), "not served as text/html")

    def site(self, value: dict | None = None, html: str = SITE_HTML, csp: str = SITE_CSP) -> gate.Verdict:
        # The privacy notice is a section of the page itself, so its path answers with the page.
        page = document(html=html, Content_Security_Policy=csp)
        return gate.judge(site_manifest() if value is None else value, page, {"/#privacidad": page})

    def test_the_sites_own_policy_and_page_pass_with_the_shipped_declarations(self) -> None:
        verdict = self.site()
        self.assertEqual(verdict.refusals, [])
        # Issue #2 is decided: the map waits for the visitor and the notice is published.
        self.assertFalse([note for note in verdict.notes if "pending" in note], verdict.notes)
        for target in ("https://wa.me", "mailto:"):
            self.assertTrue(any(note.startswith(f"hand-off {target} (") for note in verdict.notes), verdict.notes)

    def test_each_google_origin_must_be_declared_on_its_own(self) -> None:
        for origin, fragments in (
            ("https://www.google.com", ("frame-src admits the undeclared origin https://www.google.com",)),
            # The page no longer loads the frame on its own, so only the CSP names it.
            ("https://maps.google.com", ("frame-src admits the undeclared origin https://maps.google.com",)),
        ):
            with self.subTest(origin=origin):
                value = site_manifest()
                value["thirdParties"] = [entry for entry in value["thirdParties"] if entry["origin"] != origin]
                verdict = self.site(value)
                for fragment in fragments:
                    self.assertRefused(verdict, fragment)

    def test_the_sites_policy_still_refuses_a_widened_source(self) -> None:
        for old, new, fragment in (
            ("script-src 'self'", "script-src 'self' 'unsafe-inline'", "runs code no file of this repository shipped"),
            ("script-src 'self'", "script-src 'self' 'unsafe-eval'", "runs code no file of this repository shipped"),
            ("script-src 'self'", "script-src 'self' data:", "admits the bare scheme data:"),
            ("frame-src https://maps.google.com", "frame-src https://*.google.com", "names no single origin"),
            ("frame-src https://maps.google.com", "frame-src https:", "names no single origin"),
            ("img-src 'self' data:", "img-src 'self' data: *", "names no single origin"),
            ("img-src 'self' data:", "img-src 'self' data: https://pixel.example", "undeclared origin https://pixel.example"),
            ("frame-ancestors 'none'", "frame-ancestors https://other.example", "frame-ancestors admits"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, SITE_CSP)
                self.assertRefused(self.site(csp=SITE_CSP.replace(old, new, 1)), fragment)

    def test_the_fixture_policy_is_the_servers_policy(self) -> None:
        source = (ROOT / "internal" / "server" / "types.go").read_text(encoding="utf-8")
        _, found, tail = source.partition("\tcontentSecurityPolicy = ")
        self.assertTrue(found, "internal/server/types.go no longer declares contentSecurityPolicy")
        pieces = []
        for line in tail.splitlines():
            pieces.extend(json.loads(literal) for literal in re.findall(r'"(?:[^"\\]|\\.)*"', line))
            if not line.rstrip().endswith("+"):
                break
        self.assertEqual("".join(pieces), SITE_CSP)


class ValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        (self.repo / "evidence.go").write_text("package x\n")
        self.source = self.repo / "site"
        self.source.mkdir(parents=True)
        # The repository's own shapes: a cookie assigned by literal name, and
        # a storage key bound to a constant and written through a store seam.
        (self.source / "theme.ts").write_text(
            "document.cookie = 'theme=' + id;\n"
            "export const widthKey = 'width';\n"
            "const store = window.localStorage;\n"
            "store.setItem(widthKey, v);\n"
        )

    def refusals(self, value: object) -> list[str]:
        return gate.validate(value, source_root=self.source, repo_root=self.repo)

    def test_the_baseline_validates(self) -> None:
        self.assertEqual(self.refusals(manifest()), [])

    def test_the_schema_is_closed(self) -> None:
        extra = manifest()
        extra["thirdparties"] = []
        self.assertTrue(any("unknown key 'thirdparties'" in r for r in self.refusals(extra)))
        missing = manifest()
        del missing["legalPages"]
        self.assertTrue(any("'legalPages'" in r for r in self.refusals(missing)))
        nested = manifest()
        nested["storage"][0]["expires"] = "1y"
        self.assertTrue(any("unknown key 'expires'" in r for r in self.refusals(nested)))
        handed = manifest()
        handed["handOffs"] = [{"target": "mailto:", "carries": "c", "purpose": "p", "reason": "r", "consent": "x"}]
        self.assertIn("handOffs[0] carries the unknown key 'consent'", self.refusals(handed))
        self.assertEqual(self.refusals([]), ["compliance.json must be one JSON object"])

    def test_every_field_needs_words(self) -> None:
        blank = manifest()
        blank["storage"][0]["purpose"] = " "
        self.assertTrue(any("storage[0].purpose" in r for r in self.refusals(blank)))

    def test_storage_must_be_written_by_the_visitor_and_still_written_somewhere(self) -> None:
        on_load = manifest()
        on_load["storage"][0]["writtenWhen"] = "on-load"
        self.assertTrue(any("needs consent" in r for r in self.refusals(on_load)))
        stale = manifest()
        stale["storage"][1]["name"] = "renamed"
        self.assertTrue(any("'renamed', which no file" in r for r in self.refusals(stale)))
        (self.source / "theme.ts").write_text("document.cookie = 'theme=' + id;\n")
        self.assertTrue(any("'width', which no file" in r for r in self.refusals(manifest())))

    def test_every_present_section_is_a_list_and_null_is_not_absent(self) -> None:
        for section in gate.ENTRY_KEYS:
            for value in (None, {}, "none"):
                with self.subTest(section=section, value=value):
                    changed = manifest()
                    changed[section] = value
                    self.assertIn(f"{section} must be a list", self.refusals(changed))

    def test_the_schema_version_is_pinned(self) -> None:
        changed = manifest()
        changed["schema"] = "compliance/v2"
        self.assertIn("compliance.json schema must be 'compliance/v1'", self.refusals(changed))

    def test_every_entry_is_an_object(self) -> None:
        changed = manifest()
        changed["storage"] = ["theme", *changed["storage"]]
        self.assertIn("storage[0] must be an object", self.refusals(changed))

    def test_every_required_field_is_present(self) -> None:
        valid = {
            "dataCollected": manifest()["dataCollected"][0],
            "storage": manifest()["storage"][0],
            "thirdParties": {"origin": "https://cdn.example", "purpose": "p", "consent": "not-required", "reason": "r"},
            "legalPages": manifest()["legalPages"][0],
            "edgeObservations": manifest()["edgeObservations"][0],
            "handOffs": {"target": "https://wa.me", "carries": "c", "purpose": "p", "reason": "r"},
        }
        for section, (required, _) in gate.ENTRY_KEYS.items():
            for key in sorted(required):
                with self.subTest(section=section, key=key):
                    entry = dict(valid[section])
                    del entry[key]
                    changed = manifest()
                    changed[section] = [entry]
                    self.assertIn(f"{section}[0] lacks {key!r}", self.refusals(changed))

    def test_the_storage_kind_is_closed(self) -> None:
        changed = manifest()
        changed["storage"][1]["kind"] = "indexedDB"
        self.assertIn("storage[1].kind must be one of ['cookie', 'localStorage', 'sessionStorage']", self.refusals(changed))

    def test_only_a_write_of_the_declared_kind_keeps_a_storage_entry_alive(self) -> None:
        for source in (
            # A bare literal and a read: the reproduction from the review.
            'const a = "theme"; localStorage.getItem("width");',
            # Reads of both stores.
            "if (document.cookie === 'theme=dark') {}\nconst w = window.localStorage.getItem('width');\n",
            # Writes that survive only as comments.
            "// document.cookie = 'theme=' + id;\n/* window.localStorage.setItem('width', v) */\n",
            # A line comment that ends the file, with no line terminator after it.
            "// document.cookie = 'theme=1'; localStorage.setItem('width', value)",
            "<!-- document.cookie = 'theme=1'; window.localStorage.setItem('width', v) -->\n",
            # Each name written, but to the other kind of storage.
            "window.localStorage.setItem('theme', v);\ndocument.cookie = 'width=' + v;\n",
            "window.sessionStorage.setItem('width', v);\n",
            # The write's own receiver decides, not another store the file names.
            "window.sessionStorage.setItem('width', v);\nwindow.localStorage.getItem('width');\n",
            # Writes that exist only as the text of a string, a template or a
            # regular expression never execute (the first is the review's own).
            "const a = \"document.cookie = 'theme=dark'\"; const store = localStorage; "
            "const b = \"store.setItem('width', '1')\";",
            "const t = `document.cookie = 'theme=1'; localStorage.setItem('width', v)`;\n",
            "const r = /document.cookie = 'theme=1'; localStorage.setItem\\('width', v\\)/;\n",
            # A read with a second argument, which getItem ignores, is a read.
            "localStorage.getItem('width', undefined);\n",
        ):
            with self.subTest(source=source):
                (self.source / "theme.ts").write_text(source)
                refusals = self.refusals(manifest())
                self.assertTrue(any("cookie 'theme', which no file under site/ writes" in r for r in refusals), refusals)
                self.assertTrue(any("localStorage 'width', which no file under site/ writes" in r for r in refusals), refusals)

    def test_a_write_only_a_test_file_makes_keeps_nothing_alive(self) -> None:
        (self.source / "theme.test.ts").write_text((self.source / "theme.ts").read_text())
        (self.source / "theme.ts").write_text("export {};\n")
        refusals = self.refusals(manifest())
        self.assertTrue(any("'theme', which no file" in r for r in refusals), refusals)
        self.assertTrue(any("'width', which no file" in r for r in refusals), refusals)

    def test_a_write_by_literal_or_through_a_bound_name_counts(self) -> None:
        for source in (
            "document.cookie = `theme=${id}`;\nwindow.localStorage.setItem('width', v);\n",
            'document.cookie = "theme=" + id; // not \'width\'\nconst key: string = "width";\n'
            "const s = localStorage;\ns.setItem(key, v);\n",
            # Code inside a template's ${...} is code.
            "document.cookie = `theme=${id}`;\nconst t = `${window.localStorage.setItem('width', v)}`;\n",
            # A quote or backtick inside a regular expression opens nothing,
            # and a division is no regular expression.
            "const quote = /'/g; document.cookie = 'theme=' + id; window.localStorage.setItem('width', v);\n",
            "const tick = /`/;\ndocument.cookie = 'theme=' + id;\nwindow.localStorage.setItem('width', v);\n",
            "const half = a / 2; document.cookie = 'theme=1'; window.localStorage.setItem('width', v); const c = b / 3;\n",
        ):
            with self.subTest(source=source):
                (self.source / "theme.ts").write_text(source)
                self.assertEqual(self.refusals(manifest()), [])

    def test_in_a_component_only_script_and_expressions_are_code(self) -> None:
        (self.source / "theme.ts").write_text("export {};\n")
        component = self.source / "Panel.svelte"
        # An apostrophe in a sentence opens no string, and a block's closing
        # `{/if}` opens no regular expression, so the handlers after them count.
        component.write_text(
            "<script lang=\"ts\">\n  const key = 'width';\n</script>\n"
            "<p>Don't</p> <button onclick={() => window.localStorage.setItem(key, v)}>Save</button>\n"
            "{#if open}{label}{/if}<a href=\"/x\">Don't</a> <button onclick={() => (document.cookie = 'theme=1')}>Dark</button>\n"
            "<style>p { color: red; }</style>\n"
        )
        self.assertEqual(self.refusals(manifest()), [])
        # Markup text, an HTML comment and a stylesheet are not code.
        component.write_text(
            "<p>document.cookie = 'theme=1'; window.localStorage.setItem('width', v)</p>\n"
            "<!-- {window.localStorage.setItem('width', v)} -->\n"
            "<style>.x { --a: document.cookie = 'theme=1'; }</style>\n"
        )
        refusals = self.refusals(manifest())
        self.assertTrue(any("cookie 'theme', which no file" in r for r in refusals), refusals)
        self.assertTrue(any("localStorage 'width', which no file" in r for r in refusals), refusals)

    # A script file, a component's script, and a component's markup expression.
    PLACES = (
        ("probe.js", "", "\n"),
        ("Probe.svelte", "<script>\n", "\n</script>\n"),
        ("Handler.svelte", "<button onclick={() => {\n", "\n}}>x</button>\n"),
    )

    def ambiguous(self, name: str, refusals: list[str]) -> bool:
        return any(f"site/{name}: the storage scan cannot tell whether the `/`" in r for r in refusals)

    def test_a_slash_that_can_divide_or_open_a_regex_refuses_when_the_reading_matters(self) -> None:
        # After `)`, `}`, `++`, `--` or `of` a `/` can divide or open a regular
        # expression; only a parser knows which. Each file is read both ways,
        # and a file whose writes depend on the reading is refused.
        for line in (
            # The review's: a division read as a regex hides a write, and a
            # regex read as a division opens a string that hides one.
            "const a = {} / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "if (true) /'/.test('x'); localStorage.setItem('undeclared','1');",
            # The same after a block, and after a postfix increment or decrement.
            "{}\n/'/.test('x'); localStorage.setItem('undeclared', '1');",
            "let i = 0; const a = i++ / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "let i = 0; const a = i-- / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            # The readings differ only in a key neither can read.
            "const a = {} / 2; localStorage.setItem(key, '1'); const b = 3 / 4;",
            # Read all one way or all the other, neither finds the write; the
            # mixed reading, which is the real one, does. Each reading meets
            # two such slashes in one of these, and only one in the other.
            "if (x) /`/.test(s);\nconst a = {} / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "for (const k of (a) / (b)) /'/.test(k); localStorage.setItem('undeclared', '1');",
            # `of` is a name as often as it is a keyword, and `)!` can end a
            # call TypeScript asserts non-null or begin a negated regex.
            "const of = 4; const a = of / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "const a = f()! / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    self.assertTrue(self.ambiguous(name, refusals), refusals)
                    (self.source / name).unlink()
        # The review's third: no write executes, so nothing it holds keeps a
        # declaration alive.
        (self.source / "theme.ts").write_text("export {};\n")
        for name, before, after in self.PLACES:
            with self.subTest(place=name):
                (self.source / name).write_text(
                    before + "if (true) /document.cookie = 'theme=1'; localStorage.setItem('width', value)/.test('x');" + after
                )
                refusals = self.refusals(manifest())
                self.assertTrue(self.ambiguous(name, refusals), refusals)
                self.assertTrue(any("cookie 'theme', which no file" in r for r in refusals), refusals)
                self.assertTrue(any("localStorage 'width', which no file" in r for r in refusals), refusals)
                (self.source / name).unlink()

    def test_a_negation_after_a_line_break_is_no_non_null_assertion(self) -> None:
        # On one line `x!` is TypeScript's non-null assertion and a `/` after
        # it divides. With a line terminator between them, a comment's
        # included, `x` ends its statement and the `!` negates, so the `/`
        # opens a regex: the scan calls that `!` ambiguous.
        for gap in ("\n", " /* a\n b */ ", " /* a\u2028b */ ", "\u2028", "\u2029"):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, gap=gap):
                    (self.source / name).write_text(
                        before + "let x = 1;\nx" + gap + "!/'/.test('x'); localStorage.setItem('undeclared', '1');" + after
                    )
                    refusals = self.refusals(manifest())
                    self.assertTrue(self.ambiguous(name, refusals), refusals)
                    (self.source / name).unlink()
        # The inverse: the write-shaped text is the regex, so it keeps no
        # declaration alive.
        (self.source / "theme.ts").write_text("export {};\n")
        for name, before, after in self.PLACES:
            with self.subTest(place=name, inverse=True):
                (self.source / name).write_text(
                    before + "let x = 1;\nx\n!/document.cookie = 'theme=1'; localStorage.setItem('width', value)/.test('x');"
                    + after
                )
                refusals = self.refusals(manifest())
                self.assertTrue(self.ambiguous(name, refusals), refusals)
                self.assertTrue(any("cookie 'theme', which no file" in r for r in refusals), refusals)
                self.assertTrue(any("localStorage 'width', which no file" in r for r in refusals), refusals)
                (self.source / name).unlink()

    def test_a_division_after_a_property_or_a_non_null_assertion_hides_no_write(self) -> None:
        # A property may be called anything, and TypeScript's `x!` ends an
        # operand where `!x` begins one: each `/` here can only divide.
        for line in (
            "const a = map.delete / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "const a = map. delete / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "const a = el.offsetWidth! / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "const a = x!/2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            # `this` is an operand, a name continues across a line break, and
            # a name on the line after `break` is no label.
            "const a = this / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "let x = 4;\nconst y = x\n/ 2 / 1; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "while (go()) { if (stop) break\nx / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4; }",
            "while (go()) { if (stop) break /* \u2028 */ x / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4; }",
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    self.assertTrue(any(f"{name} writes localStorage 'undeclared'" in r for r in refusals), refusals)
                    self.assertFalse(self.ambiguous(name, refusals), refusals)
                    (self.source / name).unlink()

    def test_a_regex_after_a_statement_ending_keyword_hides_no_write(self) -> None:
        # `debugger` is a whole statement, `break` and `continue` take at
        # most a label on the same line, and `export default` and `extends`
        # want an expression: a `/` after any of them opens a regex.
        statements = (
            "debugger\n/'/.test('x'); localStorage.setItem('undeclared', '1');",
            "while (go()) { if (stop) break\n/'/.test('x'); localStorage.setItem('undeclared', '1'); }",
            "while (go()) { if (skip) continue\n/'/.test('x'); localStorage.setItem('undeclared', '1'); }",
            "outer: while (go()) { if (stop) break outer\n/'/.test('x'); localStorage.setItem('undeclared', '1'); }",
            "outer: while (go()) { if (skip) continue outer\n/'/.test('x'); localStorage.setItem('undeclared', '1'); }",
            "class A extends /'/ {} localStorage.setItem('undeclared', '1');",
        )
        module = (("probe.js", "", "\n"),)  # `export default` belongs to a module's top level
        for places, line in [(self.PLACES, line) for line in statements] + [
            (module, "export default /'/; localStorage.setItem('undeclared', '1');")
        ]:
            for name, before, after in places:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    self.assertTrue(any(f"{name} writes localStorage 'undeclared'" in r for r in refusals), refusals)
                    self.assertFalse(self.ambiguous(name, refusals), refusals)
                    (self.source / name).unlink()
        # The inverse: the write-shaped text is the regex, so it keeps no
        # declaration alive.
        (self.source / "theme.ts").write_text("export {};\n")
        for name, before, after in self.PLACES:
            with self.subTest(place=name, inverse=True):
                (self.source / name).write_text(
                    before + "debugger\n/document.cookie = 'theme=1'; localStorage.setItem('width', value)/.test('x');"
                    + after
                )
                refusals = self.refusals(manifest())
                self.assertTrue(any("cookie 'theme', which no file" in r for r in refusals), refusals)
                self.assertTrue(any("localStorage 'width', which no file" in r for r in refusals), refusals)
                self.assertFalse(self.ambiguous(name, refusals), refusals)
                (self.source / name).unlink()

    def test_a_name_spelled_with_a_unicode_escape_is_refused(self) -> None:
        # An escape can spell a label the slash rule must see, or the very
        # names the write patterns look for; the scan refuses it instead.
        for line in (
            "outer: for (;;) {\n  if (stop) break \\u006futer\n  /'/.test('x'); localStorage.setItem('undeclared', '1');\n}",
            "outer: for (;;) {\n  if (stop) break \\u{6f}uter\n  /'/.test('x'); localStorage.setItem('undeclared', '1');\n}",
            "outer: for (;;) {\n  if (skip) continue \\u006futer\n  /'/.test('x'); localStorage.setItem('undeclared', '1');\n}",
            "outer: for (;;) {\n  if (skip) continue \\u{6f}uter\n  /'/.test('x'); localStorage.setItem('undeclared', '1');\n}",
            "document.\\u0063ookie = 'theme=1';\nlocal\\u0053torage.setItem('undeclared', '1');",
            "localStorage.set\\u{49}tem('undeclared', '1');",
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    first = (before + line).index("\\")
                    at = (before + line)[:first].count("\n") + 1
                    expected = f"site/{name} spells a name with a Unicode escape on line {at}; write the name plainly"
                    self.assertIn(expected, refusals)
                    (self.source / name).unlink()

    def test_a_name_may_hold_any_non_ascii_character_but_white_space(self) -> None:
        # Every JavaScript punctuator is ASCII, so in code a non-ASCII
        # character that is not white space belongs to a name: a combining
        # mark, a joiner or a middle dot inside a label keeps it a label,
        # and a byte order mark between `break` and its label is white space.
        for label, gap in (("a\u0301", " "), ("a\u200db", " "), ("a\u00b7b", " "), ("outer", "\ufeff")):
            for keyword in ("break", "continue"):
                line = (f"{label}: for (;;) {{ if (go) {keyword}{gap}{label}\n"
                        "/'/.test('x'); localStorage.setItem('undeclared', '1'); }")
                for name, before, after in self.PLACES:
                    with self.subTest(place=name, label=label, keyword=keyword):
                        (self.source / name).write_text(before + line + after)
                        refusals = self.refusals(manifest())
                        self.assertTrue(any(f"{name} writes localStorage 'undeclared'" in r for r in refusals), refusals)
                        self.assertFalse(self.ambiguous(name, refusals), refusals)
                        (self.source / name).unlink()
        # A byte order mark before a line break leaves `debugger` a statement
        # end, and one after a line break leaves the `!` after it ambiguous.
        for line, ambiguous in (
            ("debugger\ufeff\n/'/.test('x'); localStorage.setItem('undeclared', '1');", False),
            ("let x = 1;\nx\n\ufeff!/'/.test('x'); localStorage.setItem('undeclared', '1');", True),
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    self.assertEqual(self.ambiguous(name, refusals), ambiguous, refusals)
                    if not ambiguous:
                        self.assertTrue(any(f"{name} writes localStorage 'undeclared'" in r for r in refusals), refusals)
                    (self.source / name).unlink()
        # A non-ASCII operand still divides.
        for line in (
            "const \u00e9 = 4; const a = \u00e9 / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
            "const x\u0301 = 4; const a = x\u0301 / 2; localStorage.setItem('undeclared', '1'); const b = 3 / 4;",
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    refusals = self.refusals(manifest())
                    self.assertTrue(any(f"{name} writes localStorage 'undeclared'" in r for r in refusals), refusals)
                    self.assertFalse(self.ambiguous(name, refusals), refusals)
                    (self.source / name).unlink()

    def test_a_slash_whose_reading_changes_nothing_passes(self) -> None:
        # The fixture's theme.ts writes only the cookie here, so each case
        # passes only if its own width write is found.
        (self.source / "theme.ts").write_text("document.cookie = 'theme=' + id;\n")
        for line in (
            # No regular expression can start there, so both readings are one.
            "const o = {} / 2;\nconst m = (a + b) / 2;\nlet i = 0; const n = i++ / 2;\n"
            "window.localStorage.setItem('width', v);",
            # One can, and both readings find the same write after it.
            "const c = (a - b) / 2 - w / 2; window.localStorage.setItem('width', v);",
            # A regular expression made unambiguous, after a negation, after a
            # keyword, or at the very start, then a write.
            "if (true) (/'/).test('x'); window.localStorage.setItem('width', v);",
            "if (!/'/.test(s)) window.localStorage.setItem('width', v);",
            "function f(s) { return /'/.test(s); } window.localStorage.setItem('width', v);",
            "/'/.test(s); window.localStorage.setItem('width', v);",
            # A negation that starts a statement or a line stays one.
            "let x = 1;\n!/'/.test(s); window.localStorage.setItem('width', v);",
            "if (a ||\n!/'/.test(s)) window.localStorage.setItem('width', v);",
            # A backslash inside a string, a template, a regex or a comment
            # spells no name.
            "const s = '\\u0041' + `\\u0041` + /\\u0041/.source; // \\u0041\n/* \\u0041 */ "
            "window.localStorage.setItem('width', v);",
            # A line comment ends at any line terminator, not only "\n".
            "let x = 1; // note\u2028window.localStorage.setItem('width', v);",
            "let x = 1; // note\u2029window.localStorage.setItem('width', v);",
        ):
            for name, before, after in self.PLACES:
                with self.subTest(place=name, line=line):
                    (self.source / name).write_text(before + line + after)
                    self.assertEqual(self.refusals(manifest()), [])
                    (self.source / name).unlink()

    def test_an_undeclared_write_is_refused_with_its_lift(self) -> None:
        with (self.source / "theme.ts").open("a") as source:
            source.write("window.sessionStorage.setItem('draft', v);\ndocument.cookie = 'seen=1';\n")
        refusals = self.refusals(manifest())
        self.assertTrue(any("theme.ts writes sessionStorage 'draft', which compliance.json does not declare" in r for r in refusals), refusals)
        self.assertTrue(any("theme.ts writes cookie 'seen', which compliance.json does not declare" in r for r in refusals), refusals)
        self.assertTrue(any('{"name": "draft", "kind": "sessionStorage"' in r for r in refusals), refusals)

    def test_a_write_whose_key_or_store_cannot_be_read_is_refused(self) -> None:
        base = (self.source / "theme.ts").read_text()
        for call in (
            "function put(key, v) { window.localStorage.setItem(key, v); }\n",
            # A key built at run time is no literal, whatever literal it starts with.
            "window.localStorage.setItem('wid' + 'th', v);\n",
            "window.localStorage.setItem(`${prefix}width`, v);\n",
            "window.localStorage.setItem(keys.width, v);\n",
            # A binding that exists only as text binds nothing.
            "const note = \"const key = 'width'\"; // const key = 'width'\nwindow.localStorage.setItem(key, v);\n",
        ):
            with self.subTest(call=call):
                (self.source / "theme.ts").write_text(base + call)
                refusals = self.refusals(manifest())
                self.assertTrue(any("whose key this gate cannot read" in r for r in refusals), refusals)
        # A store named only in a sentence or a string is not named by code.
        (self.source / "theme.ts").write_text(
            "document.cookie = 'theme=1';\nconst note = 'kept in localStorage'; // or localStorage\n"
            "export function put(s, v) { s.setItem('width', v); }\n"
        )
        self.assertTrue(any("whose storage this gate cannot name" in r for r in self.refusals(manifest())), self.refusals(manifest()))

    def test_collection_evidence_must_exist(self) -> None:
        (self.repo / "evidence.go").unlink()
        self.assertTrue(any("evidence 'evidence.go' no longer exists" in r for r in self.refusals(manifest())))

    def test_third_parties_need_a_bare_origin_and_no_consent_requirement(self) -> None:
        bad = manifest()
        bad["thirdParties"] = [{"origin": "https://cdn.example/path", "purpose": "p", "consent": "required", "reason": "r"}]
        refusals = self.refusals(bad)
        self.assertTrue(any("bare https origin" in r for r in refusals))
        self.assertTrue(any("consent mechanism" in r for r in refusals))

    PENDING = {
        "origin": "https://maps.example",
        "purpose": "p",
        "consent": "pending",
        "decision": "https://github.com/owner/site/issues/7",
        "reason": "r",
    }

    def test_a_pending_consent_question_names_the_issue_that_holds_it(self) -> None:
        value = manifest()
        value["thirdParties"] = [dict(self.PENDING)]
        self.assertEqual(self.refusals(value), [])
        for decision in (None, "soon", "https://example.com/issues/7", "https://github.com/owner/site/pull/7", " "):
            with self.subTest(decision=decision):
                entry = dict(self.PENDING)
                if decision is None:
                    del entry["decision"]
                else:
                    entry["decision"] = decision
                value["thirdParties"] = [entry]
                refusals = self.refusals(value)
                self.assertIn(
                    "thirdParties[0].consent is pending, so it needs the issue URL that holds the decision as its decision",
                    refusals,
                )

    def test_a_not_required_third_party_carries_no_decision(self) -> None:
        value = manifest()
        entry = {**self.PENDING, "consent": "not-required"}
        value["thirdParties"] = [entry]
        self.assertIn(
            "thirdParties[0].consent is not-required, so it carries no decision: a decision belongs only to a "
            "pending consent question",
            self.refusals(value),
        )
        del entry["decision"]
        self.assertEqual(self.refusals(value), [])

    HANDOFF = {"target": "https://wa.me", "carries": "a message", "purpose": "p", "reason": "r"}

    def handoffs(self, source: str, *targets: str) -> list[str]:
        (self.source / "app.js").write_text(source)
        value = manifest()
        value["handOffs"] = [{**self.HANDOFF, "target": target} for target in targets]
        return self.refusals(value)

    def test_a_hand_off_target_is_a_bare_https_origin_or_a_mail_or_phone_scheme(self) -> None:
        built = "const a = 'https://wa.me/1?text=' + m; const b = 'mailto:x@site.example'; const c = 'tel:+1';\n"
        self.assertEqual(self.handoffs(built, "https://wa.me", "mailto:", "tel:"), [])
        for target in (
            "https://wa.me/path",
            "http://wa.me",
            "javascript:",
            "https://WA.ME",
            "mailto:x@site.example",
            "sms:",
            "wa.me",
            "https://*.wa.me",
        ):
            with self.subTest(target=target):
                self.assertTrue(
                    any(r.startswith("handOffs[0].target must be a bare https origin") for r in self.handoffs(built, target)),
                    self.handoffs(built, target),
                )
        self.assertIn("handOffs[1].target 'mailto:' is declared twice", self.handoffs(built, "mailto:", "mailto:", "https://wa.me", "tel:"))

    def test_a_declared_hand_off_the_script_never_builds_is_stale(self) -> None:
        for source in (
            "export {};\n",
            # Text that only looks like the URL: a comment, a regex, markup.
            "// window.location.href = 'https://wa.me/1';\n/* 'mailto:x' */\n",
            "const r = /https:\\/\\/wa\\.me/; const m = /mailto:/;\n",
            # The scheme alone, never the origin.
            "const a = 'https://wa.me.example/'; const b = 'https://www.wa.me/';\n",
        ):
            with self.subTest(source=source):
                refusals = self.handoffs(source, "https://wa.me", "mailto:")
                for target in ("https://wa.me", "mailto:"):
                    self.assertIn(
                        f"handOffs[{['https://wa.me', 'mailto:'].index(target)}] declares the hand-off {target!r}, which "
                        "no file under site/ builds a URL with: the entry is stale",
                        refusals,
                    )

    def test_every_url_the_script_builds_is_declared_as_a_third_party_or_a_hand_off(self) -> None:
        for source, target in (
            ("location.href = 'https://evil.example/x?y=' + v;\n", "https://evil.example"),
            ("location.href = `https://evil.example:8443/${v}`;\n", "https://evil.example:8443"),
            ('a.href = "tel:" + number;\n', "tel:"),
            ("a.href = `MAILTO:${address}`;\n", "mailto:"),
            ("a.href = `${base}?next=${'https://evil.example/'}`;\n", "https://evil.example"),
        ):
            with self.subTest(source=source):
                refusals = self.handoffs(source)
                lift = f'(lift: add to handOffs {{"target": "{target}", "carries": "...", "purpose": "...", "reason": "..."}})'
                self.assertIn(
                    f"site/app.js builds a URL with {target!r}, which compliance.json declares neither as a third "
                    f"party nor as a hand-off {lift}",
                    refusals,
                )
                # Declared as a hand-off, the same file passes.
                self.assertEqual(self.handoffs(source, target), [])
        # An https origin may instead be a declared third party: the frame the
        # map buttons point at is one.
        value = manifest()
        value["thirdParties"] = [dict(self.PENDING)]
        (self.source / "app.js").write_text("map.src = 'https://maps.example/maps?q=' + q;\n")
        self.assertEqual(self.refusals(value), [])
        # An insecure origin is reported with no lift: no manifest line admits it.
        refusals = self.handoffs("location.href = 'http://plain.example/';\n")
        self.assertIn(
            "site/app.js builds a URL with 'http://plain.example', which compliance.json declares neither as a third "
            "party nor as a hand-off",
            refusals,
        )
        # A test file builds nothing the site ships.
        (self.source / "app.js").unlink()
        (self.source / "app.test.js").write_text("fetch('https://evil.example/');\n")
        self.assertEqual(self.refusals(manifest()), [])

    def test_a_url_only_in_a_comment_regex_or_markup_builds_nothing(self) -> None:
        for name, source in (
            ("app.js", "// location.href = 'https://evil.example/';\n/* tel:+1 */ const ok = 1;\n"),
            ("app.js", "const r = /https:\\/\\/evil\\.example\\//; const t = /tel:/;\n"),
            ("Panel.svelte", '<a href="https://evil.example/">x</a> <!-- mailto: -->\n<script>const a = 1;</script>\n'),
        ):
            with self.subTest(source=source):
                (self.source / name).write_text(source)
                self.assertEqual(self.refusals(manifest()), [])
                (self.source / name).unlink()

    def test_the_shipped_script_builds_exactly_the_shipped_declarations(self) -> None:
        self.assertEqual(
            gate.built_targets(gate.SOURCE_ROOT),
            {"https://maps.google.com": "app.js", "https://wa.me": "app.js", "mailto:": "app.js"},
        )
        self.assertEqual(gate.storage_writes(gate.SOURCE_ROOT), ({}, []))

    def test_legal_pages_are_published_with_a_path_or_pending_with_a_decision(self) -> None:
        for page, fragment in (
            ({"id": "privacy", "status": "published"}, "needs the absolute path"),
            ({"id": "privacy", "status": "pending"}, "needs the issue URL"),
            ({"id": "privacy", "status": "pending", "decision": "soon"}, "needs the issue URL"),
            ({"id": "privacy", "status": "drafted", "path": "/p"}, "status must be one of"),
        ):
            with self.subTest(page=page):
                value = manifest()
                value["legalPages"] = [page]
                self.assertTrue(any(fragment in r for r in self.refusals(value)), self.refusals(value))
        twice = manifest()
        twice["legalPages"] = twice["legalPages"] * 2
        self.assertTrue(any("declared twice" in r for r in self.refusals(twice)))

    def test_edge_observations_name_what_they_are_and_where_the_decision_lives(self) -> None:
        for change, fragment in (
            ({"kind": "cookie"}, "kind must be one of"),
            ({"issue": "later"}, "issue URL that holds the decision"),
        ):
            with self.subTest(change=change):
                value = manifest()
                value["edgeObservations"][0].update(change)
                self.assertTrue(any(fragment in r for r in self.refusals(value)))
        no_marker = manifest()
        del no_marker["edgeObservations"][0]["marker"]
        self.assertTrue(any("needs the marker" in r for r in self.refusals(no_marker)))
        no_origin = manifest()
        no_origin["edgeObservations"][1]["origin"] = "reports.example"
        self.assertTrue(any("bare https origin the reports go to" in r for r in self.refusals(no_origin)))

    def test_the_live_url_must_be_https(self) -> None:
        value = manifest()
        value["liveUrl"] = "http://site.example/"
        self.assertTrue(any("liveUrl" in r for r in self.refusals(value)))


class ShippedManifestTests(unittest.TestCase):
    def test_the_repository_manifest_validates(self) -> None:
        manifest_value = json.loads(gate.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(gate.validate(manifest_value), [])

    def test_check_mode_reports_its_decision(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(gate.main(["check"]), 0)
        self.assertIn("SUMMARY mode=check decision=pass refusals=0", output.getvalue())

    def test_check_mode_fails_on_an_unreadable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            broken = Path(scratch) / "compliance.json"
            broken.write_text("{")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.main(["check", "--manifest", str(broken)]), 1)
        self.assertIn("decision=fail", output.getvalue())


# Past the byte cap, the review's reproduction: the compliant page padded to
# exactly the cap, then an undeclared inline script only a complete read sees.
PAST_CAP = SITE_HTML.encode().ljust(gate.BODY_CAP_BYTES) + b"<script>window.reviewProbe=1</script>"

# The edge's beacon, injected into an otherwise empty page of this site.
BEACON = "https://beacon.example"


def beacon_page(origin: str) -> bytes:
    return f'<!doctype html><html><body><script defer src="{origin}/beacon.js"></script>{INJECTED}</body></html>'.encode()


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - the stdlib names it
        status = 404 if self.path == "/missing" else 200
        body = {
            "/at-cap": SITE_HTML.encode().ljust(gate.BODY_CAP_BYTES),
            "/past-cap": PAST_CAP,
            "/beacon": beacon_page(BEACON),
            "/nbsp": beacon_page(BEACON),
            "/own-port": beacon_page("https://site.example:443"),
        }.get(self.path, SITE_HTML.encode())
        # "/cut-short" promises more bytes than it sends, then closes.
        promised = len(body) + (100 if self.path == "/cut-short" else 0)
        # "/nbsp" ends both script-governing directives with a U+00A0 byte.
        csp = SITE_CSP
        if self.path == "/nbsp":
            csp = SITE_CSP.replace("'none'; script-src 'self';", "'none'\xa0; script-src 'self'\xa0;", 1)
        self.send_response(status)
        for key, value in headers(Content_Security_Policy=csp):
            self.send_header(key, value)
        self.send_header("Content-Length", str(promised))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        return


class LiveModeTests(unittest.TestCase):
    """The fetch layer and `live` end to end, against a loopback server."""

    def setUp(self) -> None:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def test_fetch_keeps_an_error_answer_instead_of_raising(self) -> None:
        answer = gate.fetch(self.base + "/missing")
        self.assertEqual(answer.status, 404)
        self.assertEqual(answer.first("x-frame-options"), "DENY")

    def test_live_mode_passes_the_compliant_site_and_fails_a_regression(self) -> None:
        base = self.base

        def fetcher(url: str) -> gate.Fetched:
            answer = gate.fetch(base + "/" + url.split("/", 3)[3])
            return gate.Fetched(url, answer.status, answer.headers, answer.body)

        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "compliance.json"
            value = site_manifest()
            # The shipped map needs no prior consent (issue #2); a pending question is still noted.
            value["thirdParties"][1].update(consent="pending", decision="https://github.com/owner/site/issues/1")
            path.write_text(json.dumps(value))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.run_live(path, fetcher=fetcher), 0, output.getvalue())
            self.assertIn("START mode=live", output.getvalue())
            self.assertIn("decision=pass", output.getvalue())
            self.assertIn("NOTE third party https://www.google.com consent pending:", output.getvalue())
            self.assertIn("NOTE hand-off https://wa.me (", output.getvalue())

            # A third party the page still frames, no longer declared.
            value["thirdParties"] = value["thirdParties"][:1]
            path.write_text(json.dumps(value))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.run_live(path, fetcher=fetcher), 1)
            self.assertIn("frame-src admits the undeclared origin https://www.google.com", output.getvalue())
            value = site_manifest()

            value["edgeObservations"] = []
            path.write_text(json.dumps(value))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.run_live(path, fetcher=fetcher), 1)
            self.assertIn("decision=fail refusals=2", output.getvalue())

    def test_live_mode_fails_closed_when_the_site_cannot_be_read(self) -> None:
        for error in (OSError("connection refused"), http.client.IncompleteRead(b"", 100)):
            with self.subTest(error=type(error).__name__):

                def unreachable(url: str) -> gate.Fetched:
                    raise error

                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(gate.run_live(gate.MANIFEST, fetcher=unreachable), 1)
                self.assertIn("could not be read", output.getvalue())

    def live(self, path: str, value: dict | None = None, landed: str | None = None) -> tuple[int, str]:
        """`live` against the compliant manifest, or `value`, with the site served at `path`.

        `landed` stands in for the URL a redirect left the document at.
        """
        base = self.base

        def fetcher(url: str) -> gate.Fetched:
            answer = gate.fetch(base + path)
            return gate.Fetched(landed or url, answer.status, answer.headers, answer.body)

        with tempfile.TemporaryDirectory() as scratch:
            manifest_path = Path(scratch) / "compliance.json"
            manifest_path.write_text(json.dumps(site_manifest() if value is None else value))
            output = io.StringIO()
            with redirect_stdout(output):
                code = gate.run_live(manifest_path, fetcher=fetcher)
        return code, output.getvalue()

    def test_an_answer_past_the_byte_cap_is_refused_not_judged_by_its_prefix(self) -> None:
        # Judged whole, the answer is refused for the script past the cap.
        past_cap = gate.Fetched(SITE, 200, headers(Content_Security_Policy=SITE_CSP), PAST_CAP)
        whole = gate.judge(site_manifest(), past_cap, {"/#privacidad": past_cap})
        self.assertEqual(len(whole.refusals), 1, whole.refusals)
        self.assertIn("inline script this repository did not build", whole.refusals[0])
        with self.assertRaisesRegex(ValueError, f"larger than the {gate.BODY_CAP_BYTES}-byte cap"):
            gate.fetch(self.base + "/past-cap")
        code, output = self.live("/past-cap")
        self.assertEqual(code, 1, output)
        self.assertIn("could not be read", output)
        # The cap itself is still a complete answer.
        self.assertEqual(len(gate.fetch(self.base + "/at-cap").body), gate.BODY_CAP_BYTES)
        self.assertEqual(self.live("/at-cap")[0], 0)

    def test_an_injected_script_origin_is_judged_against_the_fetched_document(self) -> None:
        # The review of #8, end to end through validation, the stdlib fetch and
        # `live`, from the shipped manifest with one injected origin declared.
        def declaring(origin: str) -> dict:
            value = site_manifest()
            value["edgeObservations"].append(
                {"kind": "injected-script-origin", "origin": origin, "reason": "edge", "issue": "https://github.com/owner/infra/issues/3"}
            )
            return value

        let_run = "which this CSP can let run"
        # Control: the site's own ASCII policy blocks an ordinary cross-origin beacon.
        code, output = self.live("/beacon", declaring(BEACON))
        self.assertEqual(code, 0, output)
        self.assertIn(f"declared injected script origin seen: {BEACON}", output)
        # 'self' is the document's origin after a redirect, and the same host
        # spelled with its default port is the same origin: neither is blocked.
        for path, origin, landed in (("/beacon", BEACON, BEACON + "/landing"), ("/own-port", "https://site.example:443", None)):
            with self.subTest(origin=origin, landed=landed):
                code, output = self.live(path, declaring(origin), landed)
                self.assertEqual(code, 1, output)
                self.assertIn(f"declared injected origin {origin}, {let_run}", output)
        # Browsers ignore a directive carrying a non-ASCII code point, which the
        # stdlib header parser keeps, so neither ignored directive blocks it.
        self.assertIn("'none'\xa0", gate.fetch(self.base + "/nbsp").first("content-security-policy"))
        code, output = self.live("/nbsp", declaring(BEACON))
        self.assertEqual(code, 1, output)
        self.assertIn(f"declared injected origin {BEACON}, {let_run}", output)
        self.assertIn("the CSP has no default-src", output)
        self.assertEqual(gate.parse_csp("default-src 'self';\tscript-src 'self' b\xe9.example; img-src 'self'"),
                         {"default-src": ["'self'"], "img-src": ["'self'"]})
        self.assertFalse(gate.script_origin_blocked([f"default-src {BEACON}; script-src 'self' b\xe9.example"], BEACON, SITE))

    def test_an_answer_shorter_than_its_content_length_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "declared [0-9]+ bytes and delivered [0-9]+"):
            gate.fetch(self.base + "/cut-short")
        code, output = self.live("/cut-short")
        self.assertEqual(code, 1, output)
        self.assertIn("could not be read", output)


if __name__ == "__main__":
    unittest.main()
