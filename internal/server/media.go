package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

var errUnsafeMediaPath = errors.New("unsafe media path")

// mediaStore serves the pinned photographs and film. They are read once from
// the read-only volume, at <root>/immutable/<sha256>/<name> (the
// content-addressed layout naranjo.online's gallery uses), and every response
// is served from the bytes that were hashed. The volume is closed after
// startup, so nothing later written, replaced or removed there can change or
// withdraw what a visitor receives. Fifteen files of about 26 MiB in all fit
// the Pod's memory limit with room to spare.
type mediaStore struct {
	objects map[string]verifiedObject
	slots   chan struct{}
}

// verifiedObject is one pin together with the exact bytes that matched it.
type verifiedObject struct {
	site.Object
	data []byte
}

// openMediaStore validates the configuration, then reads and hashes every
// pinned file. Errors never name a filesystem path: the mount point is an
// operator fact, not something a log reader needs.
func openMediaStore(root string, maxConcurrent int, objects []site.Object) (*mediaStore, error) {
	if !filepath.IsAbs(root) || maxConcurrent < 1 || maxConcurrent > MaxMediaConcurrency || len(objects) == 0 {
		return nil, errors.New("media configuration is incomplete")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("media root is unavailable")
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("media root is unavailable")
	}
	defer opened.Close()
	store := &mediaStore{objects: make(map[string]verifiedObject, len(objects)), slots: make(chan struct{}, maxConcurrent)}
	for _, object := range objects {
		if err := store.admit(opened, object); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// admit checks one pinned object's declaration, then reads exactly its pinned
// size and keeps those bytes only if they hash to its pin.
func (s *mediaStore) admit(root *os.Root, object site.Object) error {
	if !mediaName.MatchString(object.Name) || !sha256Hex.MatchString(object.SHA256) || object.Size <= 0 {
		return fmt.Errorf("media %q is not a valid pin", object.Name)
	}
	if want, known := mediaTypes[path.Ext(object.Name)]; !known || want != object.ContentType {
		return fmt.Errorf("media %s has an unreviewed content type", object.Name)
	}
	if _, duplicate := s.objects[object.Name]; duplicate {
		return fmt.Errorf("media %s is pinned twice", object.Name)
	}
	file, info, err := openRegular(root, objectPath(object))
	if err != nil {
		return fmt.Errorf("media %s is missing or unsafe on the volume", object.Name)
	}
	defer file.Close()
	if info.Size() != object.Size {
		return fmt.Errorf("media %s has the wrong size", object.Name)
	}
	// Read exactly the pinned size, then require end of file: a file that grew
	// after the size check is refused rather than truncated into a match.
	data := make([]byte, object.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		return fmt.Errorf("media %s is unreadable", object.Name)
	}
	if n, err := file.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		return fmt.Errorf("media %s has the wrong size", object.Name)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != object.SHA256 {
		return fmt.Errorf("media %s does not match its pinned digest", object.Name)
	}
	s.objects[object.Name] = verifiedObject{Object: object, data: data}
	return nil
}

// Close is kept for the Site's lifecycle; the volume was released at startup.
func (s *mediaStore) Close() error { return nil }

// lookup maps a request name such as "assets/hero.webp" to its verified object.
func (s *mediaStore) lookup(name string) (verifiedObject, bool) {
	if !strings.HasPrefix(name, assetsPrefix) {
		return verifiedObject{}, false
	}
	object, ok := s.objects[strings.TrimPrefix(name, assetsPrefix)]
	return object, ok
}

func objectPath(object site.Object) string {
	return path.Join("immutable", object.SHA256, object.Name)
}

// serve streams one verified object with Range support. A bounded number of
// transfers run at once; beyond that the Pod answers 503 rather than queue
// visitors behind a slow download.
func (s *mediaStore) serve(w http.ResponseWriter, r *http.Request, object verifiedObject, cacheControl string) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "media capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := `"` + object.SHA256 + `"`
	header := w.Header()
	header.Set("Cache-Control", cacheControl)
	header.Set("Content-Security-Policy", mediaContentSecurityPolicy)
	header.Set("Content-Type", object.ContentType)
	header.Set("ETag", etag)
	if rangeHeaderIsAbusive(r.Header.Get("Range")) && !preconditionsDisableRange(r, etag) {
		header.Set("Content-Range", fmt.Sprintf("bytes */%d", len(object.data)))
		http.Error(w, "requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	http.ServeContent(w, r, object.Name, time.Time{}, bytes.NewReader(object.data))
}

// openRegular opens a file beneath the root only if no component is a
// symlink, every intermediate component is a directory, the final one is a
// regular file with exactly one link, and the opened handle is the same file
// that was inspected. A swapped, linked or special file is errUnsafeMediaPath.
func openRegular(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	segments := strings.Split(name, "/")
	current := ""
	var inspected fs.FileInfo
	for index, segment := range segments {
		current = path.Join(current, segment)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (index < len(segments)-1 && !info.IsDir()) {
			return nil, nil, errUnsafeMediaPath
		}
		inspected = info
	}
	if inspected == nil || !inspected.Mode().IsRegular() {
		return nil, nil, errUnsafeMediaPath
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(inspected, opened) || mediaFileHasMultipleLinks(opened) {
		file.Close()
		if err == nil {
			err = errUnsafeMediaPath
		}
		return nil, nil, err
	}
	return file, opened, nil
}

// rangeHeaderIsAbusive refuses Range headers big enough to make a tiny request
// cost many seeks and multipart boundaries.
func rangeHeaderIsAbusive(value string) bool {
	return len(value) > maxRangeHeaderBytes || strings.Count(value, ",") >= maxRangeParts
}

// preconditionsDisableRange mirrors net/http's evaluation order so that the
// abuse refusal above never replaces a standard 304, 412 or full 200: when a
// precondition already decides the response, the Range header is moot.
func preconditionsDisableRange(r *http.Request, etag string) bool {
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" && !etagListMatches(ifMatch, etag, false) {
		return true
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" && etagListMatches(ifNoneMatch, etag, true) {
		return true
	}
	ifRange := strings.TrimSpace(r.Header.Get("If-Range"))
	if ifRange == "" {
		return false
	}
	// Without a modification time only a strong, exact ETag keeps the range.
	return strings.HasPrefix(ifRange, "W/") || ifRange != etag
}

func etagListMatches(value, current string, weak bool) bool {
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if weak {
			if strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(current, "W/") {
				return true
			}
			continue
		}
		if !strings.HasPrefix(candidate, "W/") && candidate == current {
			return true
		}
	}
	return false
}
