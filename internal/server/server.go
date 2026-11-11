// Package server is the HTTP origin for hospedajedonlolo.com.
//
// It answers exactly three kinds of request: the page files embedded in the
// binary, the pinned photographs and film on the read-only media volume, and
// two health endpoints. Everything else is refused. Every response, refusals
// included, carries the security headers set in securityHeaders; none of them
// has a runtime switch.
package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

// Config is everything a Site needs. Every field is required: New refuses an
// incomplete configuration rather than serve the page without its photographs
// while reporting healthy.
type Config struct {
	// Pages is the embedded page: index.html, style.css, app.js and fonts.
	Pages fs.FS
	// Media is the closed, digest-pinned set of files on the volume.
	Media []site.Object
	// MediaRoot is the absolute mount path of the read-only media volume.
	MediaRoot string
	// MediaMaxConcurrent bounds simultaneous media transfers per Pod.
	MediaMaxConcurrent int
	// Logger receives one record per request; nil discards them.
	Logger *slog.Logger
}

// Site is a constructed, verified origin. It is safe for concurrent use.
type Site struct {
	files   map[string]embeddedFile
	media   *mediaStore
	handler http.Handler
}

type embeddedFile struct {
	data         []byte
	digest       string
	contentType  string
	cacheControl string
}

// New verifies the configuration and every published byte before returning,
// so a Site that exists is a Site whose readiness answer is true: a missing,
// altered, linked or wrongly sized media file is a construction error, not a
// broken image a visitor discovers later.
func New(cfg Config) (*Site, error) {
	if cfg.Pages == nil {
		return nil, errors.New("page files are missing")
	}
	files, err := loadPages(cfg.Pages)
	if err != nil {
		return nil, err
	}
	media, err := openMediaStore(cfg.MediaRoot, cfg.MediaMaxConcurrent, cfg.Media)
	if err != nil {
		return nil, err
	}
	for name := range media.objects {
		if _, clash := files[assetsPrefix+name]; clash {
			media.Close()
			return nil, fmt.Errorf("media %s collides with an embedded file", name)
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Site{files: files, media: media}
	s.handler = requestLog(logger, securityHeaders(idleDeadline(redirectForwardedHTTP(http.HandlerFunc(s.route)))))
	return s, nil
}

// Handler returns the complete, wrapped origin handler.
func (s *Site) Handler() http.Handler { return s.handler }

// Close ends the Site's lifecycle. The media volume was already released when
// New finished reading it.
func (s *Site) Close() error { return s.media.Close() }

// loadPages reads every embedded file once. The content types form a closed
// table: a file whose extension is not in it fails construction, so nothing
// is ever served with a sniffed or guessed type.
func loadPages(pages fs.FS) (map[string]embeddedFile, error) {
	files := make(map[string]embeddedFile)
	err := fs.WalkDir(pages, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || strings.HasSuffix(name, ".go") {
			return nil
		}
		kind, known := pageTypes[path.Ext(name)]
		if !known {
			return fmt.Errorf("embedded file %s has no reviewed content type", name)
		}
		data, err := fs.ReadFile(pages, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[name] = embeddedFile{
			data:         data,
			digest:       hex.EncodeToString(sum[:]),
			contentType:  kind.contentType,
			cacheControl: kind.cacheControl,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("page files are unreadable: %w", err)
	}
	if _, ok := files[indexName]; !ok {
		return nil, errors.New("page files have no index.html")
	}
	return files, nil
}

// route dispatches a request whose path already passed redirectForwardedHTTP.
func (s *Site) route(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}
	requestPath := r.URL.Path
	if !cleanPath(requestPath) {
		http.NotFound(w, r)
		return
	}
	switch requestPath {
	case "/livez", "/readyz":
		// Readiness is a constant, and that is truthful: New verified every
		// input, and the page and media are served from the verified bytes in
		// memory, so nothing on the volume can later change or remove them.
		// There is no database or upstream to lose.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("ok\n"))
		}
		return
	case "/":
		requestPath = "/" + indexName
	}
	name := strings.TrimPrefix(requestPath, "/")
	immutable := false
	if published, digest, ok := contentAddressed(name); ok {
		// The page names its files by digest. Only the file's own digest is
		// served, and never for the page itself, which must stay revalidated;
		// an old, unknown or foreign digest is a miss, never a fallback to the
		// current bytes under a name that claims other ones.
		if published == indexName || s.digestOf(published) != digest {
			w.Header().Set("Cache-Control", missCacheControl)
			http.NotFound(w, r)
			return
		}
		name, immutable = published, true
	}
	if object, ok := s.media.lookup(name); ok {
		s.media.serve(w, r, object, cachePolicy(immutable, assetCacheControl))
		return
	}
	file, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", cachePolicy(immutable, file.cacheControl))
	w.Header().Set("ETag", `"`+file.digest+`"`)
	w.Header().Set("Content-Type", file.contentType)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(file.data))
}

// contentAddressed splits a name such as assets/hero.<sha256>.webp into the
// published name it addresses, assets/hero.webp, and the digest it claims.
// Published names carry no inner dot, so the split is unambiguous.
func contentAddressed(name string) (published, digest string, ok bool) {
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	dot := strings.LastIndexByte(stem, '.')
	if dot < 0 || !sha256Hex.MatchString(stem[dot+1:]) {
		return "", "", false
	}
	return stem[:dot] + ext, stem[dot+1:], true
}

// digestOf is the SHA-256 of a published file's verified bytes, or "" for a
// name nothing is published under.
func (s *Site) digestOf(name string) string {
	if object, ok := s.media.lookup(name); ok {
		return object.SHA256
	}
	return s.files[name].digest
}

func cachePolicy(immutable bool, otherwise string) string {
	if immutable {
		return immutableCacheControl
	}
	return otherwise
}

// cleanPath accepts only canonical absolute paths: no backslash, no NUL, no
// dot segments, no doubled or trailing slash. Anything that a proxy or file
// API might normalize differently is refused instead of reinterpreted.
func cleanPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\\x00") && path.Clean(p) == p
}

// allowReadMethod admits GET and HEAD. The site has no write surface at all,
// so every other method is answered 405 before any routing happens.
func allowReadMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// securityHeaders sets the site-wide policy on every response. The CSP admits
// only the page's own origin plus the Google Maps frame the page embeds (the
// maps.google.com URL redirects to www.google.com, so both are named). The
// page carries no inline script or style, so neither 'unsafe-inline' nor a
// nonce is needed; `data:` appears only in img-src for the inline favicon.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cross-Origin-Resource-Policy", "same-origin")
		header.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
		header.Set("Referrer-Policy", "no-referrer")
		if r.Header.Get(forwardedProtoHeader) == "https" {
			header.Set("Strict-Transport-Security", "max-age=31536000")
		}
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// redirectForwardedHTTP upgrades a request the edge forwarded as plain HTTP.
// The edge already redirects every http:// request, so this is a second
// layer for a misconfigured zone, never the primary control.
func redirectForwardedHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(forwardedProtoHeader) == "http" {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// idleDeadline bounds how long any response may stall between writes. A
// fixed WriteTimeout would cut off a visitor on a slow connection halfway
// through the film; a per-write idle deadline only drops a client that stops
// reading.
func idleDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &idleDeadlineWriter{ResponseWriter: w, timeout: writeIdleTimeout}
		writer.refresh()
		next.ServeHTTP(writer, r)
	})
}

type idleDeadlineWriter struct {
	http.ResponseWriter
	timeout time.Duration
}

// Unwrap lets http.ResponseController reach the connection beneath.
func (w *idleDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *idleDeadlineWriter) WriteHeader(status int) {
	w.refresh()
	w.ResponseWriter.WriteHeader(status)
}

func (w *idleDeadlineWriter) Write(data []byte) (int, error) {
	w.refresh()
	return w.ResponseWriter.Write(data)
}

func (w *idleDeadlineWriter) refresh() {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.timeout))
}
