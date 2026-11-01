package server

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

func TestMediaIsServedFromItsPinnedPath(t *testing.T) {
	f := newFixture(t)
	h := f.site(t).Handler()
	w := do(t, h, http.MethodGet, "/assets/photo.webp", nil)
	if w.Code != http.StatusOK || w.Body.String() != "webp-bytes-0123456789" {
		t.Fatalf("media: %d %q", w.Code, w.Body.String())
	}
	header := w.Header()
	if header.Get("Content-Type") != "image/webp" || header.Get("Cache-Control") != "public, max-age=86400" ||
		header.Get("ETag") != `"`+f.objects[0].SHA256+`"` || header.Get("Last-Modified") != "" {
		t.Fatalf("media headers: %v", header)
	}
	if w := do(t, h, http.MethodGet, "/assets/photo.webp", map[string]string{"If-None-Match": header.Get("ETag")}); w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", w.Code)
	}
}

func TestFilmSupportsRangeRequests(t *testing.T) {
	h := newFixture(t).site(t).Handler()
	w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": "bytes=10-19"})
	if w.Code != http.StatusPartialContent || w.Body.String() != "0123456789" ||
		w.Header().Get("Content-Range") != "bytes 10-19/10000" || w.Header().Get("Content-Type") != "video/mp4" {
		t.Fatalf("range: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Range"))
	}
}

func TestAbusiveRangesAreRefusedButPreconditionsStillWin(t *testing.T) {
	f := newFixture(t)
	h := f.site(t).Handler()
	abusive := "bytes=" + strings.Repeat("0-0,", maxRangeParts)
	w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": abusive})
	if w.Code != http.StatusRequestedRangeNotSatisfiable || w.Header().Get("Content-Range") != "bytes */10000" {
		t.Fatalf("abusive range: %d %q", w.Code, w.Header().Get("Content-Range"))
	}
	etag := `"` + f.objects[1].SHA256 + `"`
	if w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": abusive, "If-None-Match": etag}); w.Code != http.StatusNotModified {
		t.Fatalf("a matching If-None-Match must still answer 304: %d", w.Code)
	}
	if w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": abusive, "If-Range": `"stale"`}); w.Code != http.StatusOK {
		t.Fatalf("a stale If-Range makes Range moot and must answer 200: %d", w.Code)
	}
	if w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": abusive, "If-Match": `"other"`}); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("a failed If-Match must answer 412: %d", w.Code)
	}
	long := "bytes=0-" + strings.Repeat("0", maxRangeHeaderBytes)
	if w := do(t, h, http.MethodGet, "/assets/film.mp4", map[string]string{"Range": long}); w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("oversized range header: %d", w.Code)
	}
}

func TestCapacityExhaustionAnswers503(t *testing.T) {
	s := newFixture(t).site(t)
	for i := 0; i < cap(s.media.slots); i++ {
		s.media.slots <- struct{}{}
	}
	w := do(t, s.Handler(), http.MethodGet, "/assets/photo.webp", nil)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("capacity: %d %v", w.Code, w.Header())
	}
}

// After construction the volume is out of the request path. Whatever changes
// on the host afterwards -- a same-size overwrite in place, an atomic same-size
// replacement, a resize or a removal -- visitors still receive exactly the
// verified bytes under the pinned ETag, whole or by range, and readiness stays
// true because the site can still serve all of it.
func TestVolumeChangesAfterVerificationNeverReachVisitors(t *testing.T) {
	const original = "webp-bytes-0123456789"
	const forged = "WEBP-BYTES-9876543210" // same length as original
	changes := map[string]func(*testing.T, string){
		"same-size overwrite in place": func(t *testing.T, name string) {
			file, err := os.OpenFile(name, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := file.WriteAt([]byte(forged), 0); err != nil {
				t.Fatal(err)
			}
		},
		"same-size atomic replacement": func(t *testing.T, name string) {
			if err := os.WriteFile(name+".new", []byte(forged), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(name+".new", name); err != nil {
				t.Fatal(err)
			}
		},
		"resize": func(t *testing.T, name string) {
			if err := os.WriteFile(name, []byte("swapped"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"removal": func(t *testing.T, name string) {
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
		},
	}
	for label, change := range changes {
		t.Run(label, func(t *testing.T) {
			f := newFixture(t)
			if len(forged) != len(original) || f.objects[0].Size != int64(len(original)) {
				t.Fatal("fixture no longer matches this test's same-size premise")
			}
			h := f.site(t).Handler()
			change(t, f.path(f.objects[0]))
			etag := `"` + f.objects[0].SHA256 + `"`
			w := do(t, h, http.MethodGet, "/assets/photo.webp", nil)
			if w.Code != http.StatusOK || w.Body.String() != original || w.Header().Get("ETag") != etag {
				t.Fatalf("served %d %q etag %q", w.Code, w.Body.String(), w.Header().Get("ETag"))
			}
			w = do(t, h, http.MethodGet, "/assets/photo.webp", map[string]string{"Range": "bytes=11-20"})
			if w.Code != http.StatusPartialContent || w.Body.String() != original[11:] {
				t.Fatalf("range served %d %q", w.Code, w.Body.String())
			}
			if w := do(t, h, http.MethodGet, "/readyz", nil); w.Code != http.StatusOK {
				t.Fatalf("readiness: %d", w.Code)
			}
		})
	}
}

func TestConstructionVerifiesEveryPinnedByte(t *testing.T) {
	cases := map[string]func(*testing.T, *fixture) Config{
		"relative root": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.MediaRoot = "media"
			return c
		},
		"zero concurrency": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.MediaMaxConcurrent = 0
			return c
		},
		"excess concurrency": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.MediaMaxConcurrent = MaxMediaConcurrency + 1
			return c
		},
		"no media": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = nil
			return c
		},
		"missing root": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.MediaRoot = filepath.Join(f.root, "absent")
			return c
		},
		"root is a symlink": func(t *testing.T, f *fixture) Config {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(f.root, link); err != nil {
				t.Fatal(err)
			}
			c := f.config()
			c.MediaRoot = link
			return c
		},
		"missing file": func(t *testing.T, f *fixture) Config {
			if err := os.Remove(f.path(f.objects[0])); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"wrong size": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = append([]site.Object(nil), f.objects...)
			c.Media[0].Size++
			return c
		},
		"altered bytes": func(t *testing.T, f *fixture) Config {
			if err := os.WriteFile(f.path(f.objects[0]), []byte("webp-bytes-ALTERED-89"), 0o644); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"symlinked file": func(t *testing.T, f *fixture) Config {
			target := filepath.Join(t.TempDir(), "elsewhere")
			data, _ := os.ReadFile(f.path(f.objects[0]))
			if err := os.WriteFile(target, data, 0o644); err != nil {
				t.Fatal(err)
			}
			os.Remove(f.path(f.objects[0]))
			if err := os.Symlink(target, f.path(f.objects[0])); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"symlinked directory": func(t *testing.T, f *fixture) Config {
			dir := filepath.Dir(f.path(f.objects[0]))
			moved := filepath.Join(t.TempDir(), "moved")
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, dir); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"directory in place of file": func(t *testing.T, f *fixture) Config {
			os.Remove(f.path(f.objects[0]))
			if err := os.Mkdir(f.path(f.objects[0]), 0o755); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"hard-linked file": func(t *testing.T, f *fixture) Config {
			if err := os.Link(f.path(f.objects[0]), filepath.Join(f.root, "extra-link")); err != nil {
				t.Fatal(err)
			}
			return f.config()
		},
		"bad name": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = append([]site.Object(nil), f.objects...)
			c.Media[0].Name = "../photo.webp"
			return c
		},
		"bad digest": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = append([]site.Object(nil), f.objects...)
			c.Media[0].SHA256 = strings.ToUpper(c.Media[0].SHA256)
			return c
		},
		"type mismatch": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = append([]site.Object(nil), f.objects...)
			c.Media[0].ContentType = "image/png"
			return c
		},
		"duplicate pin": func(_ *testing.T, f *fixture) Config {
			c := f.config()
			c.Media = append(append([]site.Object(nil), f.objects...), f.objects[0])
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "hard-linked file" && runtime.GOOS == "windows" {
				t.Skip("no link counts")
			}
			f := newFixture(t)
			cfg := mutate(t, f)
			s, err := New(cfg)
			if err == nil {
				s.Close()
				t.Fatal("construction accepted an unsafe or unverified volume")
			}
			if strings.Contains(err.Error(), f.root) {
				t.Fatalf("error leaks the mount path: %v", err)
			}
		})
	}
}

func TestEtagListMatching(t *testing.T) {
	if !etagListMatches(`W/"a", "b"`, `"a"`, true) || etagListMatches(`W/"a"`, `"a"`, false) ||
		!etagListMatches(`*`, `"a"`, false) || !etagListMatches(` "x" , "a"`, `"a"`, false) {
		t.Fatal("etag list semantics")
	}
}
