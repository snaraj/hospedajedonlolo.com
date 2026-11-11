package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

// pinnedPolicy is the reviewed browser policy, repeated here so a change to
// the constant is a change two files must agree on.
const pinnedPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; media-src 'self'; " +
	"frame-src https://maps.google.com https://www.google.com; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"

func TestPagesAreServedWithTheirPinnedTypesAndCaching(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	cases := []struct{ target, body, contentType, cache string }{
		{"/", "<!doctype html><title>t</title>", "text/html; charset=utf-8", "no-cache"},
		{"/index.html", "<!doctype html><title>t</title>", "text/html; charset=utf-8", "no-cache"},
		{"/style.css", "body{}", "text/css; charset=utf-8", "no-cache"},
		{"/app.js", "void 0", "text/javascript; charset=utf-8", "no-cache"},
		{"/assets/font.ttf", "font-bytes", "font/ttf", "public, max-age=86400"},
	}
	for _, c := range cases {
		w := do(t, h, http.MethodGet, c.target, nil)
		if w.Code != http.StatusOK || w.Body.String() != c.body {
			t.Fatalf("%s: %d %q", c.target, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Content-Type"); got != c.contentType {
			t.Errorf("%s content type %q", c.target, got)
		}
		if got := w.Header().Get("Cache-Control"); got != c.cache {
			t.Errorf("%s cache %q", c.target, got)
		}
		if etag := w.Header().Get("ETag"); len(etag) != 66 || w.Header().Get("Last-Modified") != "" {
			t.Errorf("%s validators: etag %q last-modified %q", c.target, etag, w.Header().Get("Last-Modified"))
		}
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	for _, target := range []string{"/", "/missing", "/livez", "/assets/photo.webp"} {
		w := do(t, h, http.MethodGet, target, nil)
		want := map[string]string{
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Permissions-Policy":           "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
			"Referrer-Policy":              "no-referrer",
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
		}
		for key, value := range want {
			if got := w.Header().Get(key); got != value {
				t.Errorf("%s %s = %q", target, key, got)
			}
		}
		policy := w.Header().Get("Content-Security-Policy")
		if target == "/assets/photo.webp" {
			if policy != "default-src 'none'; sandbox" {
				t.Errorf("media policy %q", policy)
			}
		} else if policy != pinnedPolicy {
			t.Errorf("%s policy %q", target, policy)
		}
		if w.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s sent HSTS without a forwarded https scheme", target)
		}
	}
	if contentSecurityPolicy != pinnedPolicy {
		t.Fatal("the policy constant and its pinned copy disagree")
	}
}

func TestHSTSOnlyForForwardedHTTPS(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	w := do(t, h, http.MethodGet, "/", map[string]string{"X-Forwarded-Proto": "https"})
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("hsts %q", got)
	}
	w = do(t, h, http.MethodGet, "/", map[string]string{"X-Forwarded-Proto": "HTTPS"})
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("hsts must require the exact lowercase scheme")
	}
}

func TestForwardedHTTPIsRedirectedPermanently(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	w := do(t, h, http.MethodGet, "/style.css?v=1", map[string]string{"X-Forwarded-Proto": "http"})
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://example.com/style.css?v=1" {
		t.Fatalf("redirect %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestHealthEndpoints(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	for _, target := range []string{"/livez", "/readyz"} {
		w := do(t, h, http.MethodGet, target, nil)
		if w.Code != http.StatusOK || w.Body.String() != "ok\n" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %q %q", target, w.Code, w.Body.String(), w.Header().Get("Cache-Control"))
		}
		w = do(t, h, http.MethodHead, target, nil)
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("HEAD %s: %d %q", target, w.Code, w.Body.String())
		}
	}
}

func TestOnlyReadMethodsAreAllowed(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "TRACE"} {
		w := do(t, h, method, "/", nil)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: %d allow %q", method, w.Code, w.Header().Get("Allow"))
		}
	}
	if w := do(t, h, http.MethodHead, "/", nil); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD /: %d %d", w.Code, w.Body.Len())
	}
}

func TestUnknownAndNonCanonicalPathsAreRefused(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	for _, target := range []string{
		"/missing", "/assets/", "/assets", "/embed.go", "/assets/../index.html",
		"//index.html", "/./index.html", "/index.html/", "/assets/missing.webp",
		"/immutable/x", "/.git/config", "/assets%5cfont.ttf", "/index.html%00",
	} {
		if w := do(t, h, http.MethodGet, target, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
}

// TestContentAddressedNamesAreImmutableAndExact pins the versioned URLs the
// page uses. A name carrying a file's own SHA-256 is that file, kept for a
// year, with the same validator and policy as its plain name. Any other digest
// is a 404 that no cache may keep, and the page itself has no such name, so it
// is always revalidated.
func TestContentAddressedNamesAreImmutableAndExact(t *testing.T) {
	f := newFixture(t)
	h := f.site(t).Handler()
	photo, film := f.objects[0], f.objects[1]
	style := hexDigest(f.pages["style.css"].Data)
	cases := []struct{ target, digest, contentType, policy string }{
		{"/style." + style + ".css", style, "text/css; charset=utf-8", pinnedPolicy},
		{"/app." + hexDigest(f.pages["app.js"].Data) + ".js", hexDigest(f.pages["app.js"].Data), "text/javascript; charset=utf-8", pinnedPolicy},
		{"/assets/font." + hexDigest(f.pages["assets/font.ttf"].Data) + ".ttf", hexDigest(f.pages["assets/font.ttf"].Data), "font/ttf", pinnedPolicy},
		{"/assets/photo." + photo.SHA256 + ".webp", photo.SHA256, "image/webp", "default-src 'none'; sandbox"},
		{"/assets/film." + film.SHA256 + ".mp4", film.SHA256, "video/mp4", "default-src 'none'; sandbox"},
	}
	for _, c := range cases {
		w := do(t, h, http.MethodGet, c.target, nil)
		if w.Code != http.StatusOK || hexDigest(w.Body.Bytes()) != c.digest {
			t.Fatalf("%s: %d, body digest %s", c.target, w.Code, hexDigest(w.Body.Bytes()))
		}
		if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s cache %q", c.target, got)
		}
		if w.Header().Get("ETag") != `"`+c.digest+`"` || w.Header().Get("Content-Type") != c.contentType ||
			w.Header().Get("Content-Security-Policy") != c.policy {
			t.Errorf("%s: etag %q type %q policy %q", c.target, w.Header().Get("ETag"), w.Header().Get("Content-Type"), w.Header().Get("Content-Security-Policy"))
		}
		if again := do(t, h, http.MethodGet, c.target, map[string]string{"If-None-Match": w.Header().Get("ETag")}); again.Code != http.StatusNotModified {
			t.Errorf("%s revalidation: %d", c.target, again.Code)
		}
	}
	part := do(t, h, http.MethodGet, "/assets/film."+film.SHA256+".mp4", map[string]string{"Range": "bytes=0-9"})
	if part.Code != http.StatusPartialContent || part.Body.String() != "0123456789" ||
		part.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("film range: %d %q %q", part.Code, part.Body.String(), part.Header().Get("Cache-Control"))
	}
	zero := strings.Repeat("0", 64)
	for _, target := range []string{
		"/style." + zero + ".css",                                   // a digest no file has
		"/style." + photo.SHA256 + ".css",                           // another file's digest
		"/assets/photo." + style + ".webp",                          // a page file's digest on media
		"/assets/film." + photo.SHA256 + ".mp4",                     // another media object's digest
		"/missing." + style + ".css",                                // nothing published under the name
		"/index." + hexDigest(f.pages["index.html"].Data) + ".html", // the page is always revalidated
		"/assets/photo." + zero + ".webp",
	} {
		w := do(t, h, http.MethodGet, target, nil)
		if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d cache %q", target, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	// A digest that is not 64 lowercase hex is no address at all: it is an
	// ordinary unknown name, refused like any other.
	for _, target := range []string{"/style." + strings.ToUpper(style) + ".css", "/style." + style[:63] + ".css", "/style." + style + "0.css"} {
		if w := do(t, h, http.MethodGet, target, nil); w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "" {
			t.Errorf("%s: %d cache %q, want the plain 404 of an unknown name", target, w.Code, w.Header().Get("Cache-Control"))
		}
	}
}

// TestThePagesOwnAddressesAreServedImmutable boots the real embedded page and
// follows it: the stylesheet and script addresses in the HTML, then the font
// addresses in that stylesheet, each answer 200 with the immutable policy,
// and the same names under a stale digest are refused. Media addresses are
// held to their pins by the site package's reference test, because the
// volume here is a fixture.
func TestThePagesOwnAddressesAreServedImmutable(t *testing.T) {
	cfg := newFixture(t).config()
	cfg.Pages = site.Pages
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()
	address := regexp.MustCompile(`(?:assets/)?[a-z0-9][a-z0-9-]*\.([0-9a-f]{64})\.(?:css|js|ttf)`)
	pending := address.FindAllString(do(t, h, http.MethodGet, "/", nil).Body.String(), -1)
	served := map[string]bool{}
	for len(pending) > 0 {
		target := pending[0]
		pending = pending[1:]
		if served[target] {
			continue
		}
		served[target] = true
		w := do(t, h, http.MethodGet, "/"+target, nil)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: %d cache %q", target, w.Code, w.Header().Get("Cache-Control"))
		}
		if strings.HasSuffix(target, ".css") {
			pending = append(pending, address.FindAllString(w.Body.String(), -1)...)
		}
		stale := strings.Replace(target, address.FindStringSubmatch(target)[1], strings.Repeat("0", 64), 1)
		if w := do(t, h, http.MethodGet, "/"+stale, nil); w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d cache %q", stale, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	if len(served) != 8 { // the stylesheet, the script and six fonts
		t.Fatalf("followed %d addresses, want 8: %v", len(served), served)
	}
}

// TestAContentChangeMovesItsAddress proves why a year-long cache is safe: the
// address of the old bytes stops resolving the moment the bytes change, and
// the new bytes answer only at their own address.
func TestAContentChangeMovesItsAddress(t *testing.T) {
	f := newFixture(t)
	before := f.site(t).Handler()
	oldAddress := "/style." + hexDigest(f.pages["style.css"].Data) + ".css"
	f.pages["style.css"] = &fstest.MapFile{Data: []byte("body{color:red}")}
	after := f.site(t).Handler()
	newAddress := "/style." + hexDigest(f.pages["style.css"].Data) + ".css"
	if oldAddress == newAddress {
		t.Fatal("the address did not move with the bytes")
	}
	for _, c := range []struct {
		h      http.Handler
		target string
		code   int
		body   string
	}{
		{before, oldAddress, http.StatusOK, "body{}"},
		{before, newAddress, http.StatusNotFound, ""},
		{after, oldAddress, http.StatusNotFound, ""},
		{after, newAddress, http.StatusOK, "body{color:red}"},
	} {
		w := do(t, c.h, http.MethodGet, c.target, nil)
		if w.Code != c.code || (c.code == http.StatusOK && w.Body.String() != c.body) {
			t.Errorf("%s: %d %q", c.target, w.Code, w.Body.String())
		}
	}
}

func TestConditionalRequestsRevalidate(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	first := do(t, h, http.MethodGet, "/style.css", nil)
	w := do(t, h, http.MethodGet, "/style.css", map[string]string{"If-None-Match": first.Header().Get("ETag")})
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("revalidation: %d", w.Code)
	}
}

func TestConstructionRefusesIncompletePages(t *testing.T) {
	f := newFixture(t)
	cfg := f.config()
	cfg.Pages = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("nil pages accepted")
	}
	cfg.Pages = fstest.MapFS{"style.css": {Data: []byte("x")}}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("missing index accepted: %v", err)
	}
	cfg.Pages = fstest.MapFS{"index.html": {Data: []byte("x")}, "logo.svg": {Data: []byte("<svg/>")}}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "reviewed content type") {
		t.Fatalf("unreviewed type accepted: %v", err)
	}
	cfg.Pages = fstest.MapFS{"index.html": {Data: []byte("x")}, "assets/photo.webp": {Data: []byte("x")}}
	if _, err := New(cfg); err == nil {
		t.Fatal("an embedded .webp has no reviewed page type and must be refused")
	}
}

func TestEmbeddedNameMayNotShadowMedia(t *testing.T) {
	f := newFixture(t)
	pageTypes[".webp"] = pageType{"image/webp", assetCacheControl}
	defer delete(pageTypes, ".webp")
	f.pages["assets/photo.webp"] = &fstest.MapFile{Data: []byte("shadow")}
	if _, err := New(f.config()); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("collision accepted: %v", err)
	}
}

func TestRequestsAreLoggedWithoutClientAddressOrQuery(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	cfg := f.config()
	cfg.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	do(t, s.Handler(), http.MethodGet, "/style.css?email=guest@example.com", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	line := buf.String()
	for _, forbidden := range []string{"203.0.113.9", "guest@example.com", "email=", "192.0.2.1"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("log line leaks %q: %s", forbidden, line)
		}
	}
	for _, required := range []string{`"url.path":"/style.css"`, `"http.response.status_code":200`, `"request_id":"`} {
		if !strings.Contains(line, required) {
			t.Fatalf("log line lacks %s: %s", required, line)
		}
	}
}
