package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

// fixture is a small published site: a page tree and a volume holding two
// pinned media files in the immutable/<sha256>/<name> layout.
type fixture struct {
	root    string
	objects []site.Object
	pages   fstest.MapFS
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{root: root, pages: fstest.MapFS{
		"index.html":       {Data: []byte("<!doctype html><title>t</title>")},
		"style.css":        {Data: []byte("body{}")},
		"app.js":           {Data: []byte("void 0")},
		"assets/font.ttf":  {Data: []byte("font-bytes")},
		"embed.go":         {Data: []byte("package site")},
		"assets/notes.txt": nil,
	}}
	delete(f.pages, "assets/notes.txt")
	f.objects = []site.Object{
		f.write(t, "photo.webp", "image/webp", []byte("webp-bytes-0123456789")),
		f.write(t, "film.mp4", "video/mp4", []byte(strings.Repeat("0123456789", 1000))),
	}
	return f
}

func (f *fixture) write(t *testing.T, name, contentType string, data []byte) site.Object {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(f.root, "immutable", digest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return site.Object{Name: name, SHA256: digest, Size: int64(len(data)), ContentType: contentType}
}

func (f *fixture) path(object site.Object) string {
	return filepath.Join(f.root, "immutable", object.SHA256, object.Name)
}

func (f *fixture) config() Config {
	return Config{Pages: f.pages, Media: f.objects, MediaRoot: f.root, MediaMaxConcurrent: 4}
}

func (f *fixture) site(t *testing.T) *Site {
	t.Helper()
	s, err := New(f.config())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func do(t *testing.T, h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
