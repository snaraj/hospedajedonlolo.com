package site

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"sort"
	"testing"
)

// exported pins every embedded file to the bytes the owner delivered on
// 2026-10-31 (CHECKSUMS.sha256 of the export, source commit c39ac49d). This is
// the "content does not change" invariant made executable: an edit to the
// page, its styles, its script or a font fails here and must be a reviewed,
// deliberate change to this table.
var exported = map[string]string{
	"index.html":                    "0a264cdd996cb02cf4d47a22d0533f9b604ba22717ee35b73b6fd8b16d09682a",
	"style.css":                     "cd7561d9751f150e7cdc1f04450fc15c0dd1978803706f62798a4b1eff557446",
	"app.js":                        "816c39710259d64e97b45795824353fb9944de1775a258c93295d331c1c85adf",
	"assets/font-0.ttf":             "b0ae3e89a7d3ef2b1838bb4b1ceb0b17cc3435af061eee809d76aa623ff116e9",
	"assets/font-1.ttf":             "376427b5322148d8de1e03f263bcca4935a2d60ba71d9f94f4947ab664c711ae",
	"assets/font-2.ttf":             "b79a2ea7a38f33fd96a282fadb9ce97626bb0724a44d21075859f0e50239993a",
	"assets/font-3.ttf":             "f5bc4341f15de5e877d8d95b6b14b33e9a3da1f8fef4ed0700ed407f096cffb6",
	"assets/font-4.ttf":             "8b008ffdae31b314657cb8e28d822da09893035d06bad9b1ab53ea762549cbd1",
	"assets/cormorant-italic-0.ttf": "14efb9443652199ade5bc6ba8637b4084acce40a58368a3808f84f55667e3e90",
}

func TestEmbeddedFilesAreTheDeliveredBytes(t *testing.T) {
	seen := map[string]bool{}
	err := fs.WalkDir(Pages, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		seen[name] = true
		want, pinned := exported[name]
		if !pinned {
			t.Errorf("embedded file %s is not in the delivered set", name)
			return nil
		}
		data, err := fs.ReadFile(Pages, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s hashes to %s, delivered bytes hash to %s", name, got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range exported {
		if !seen[name] {
			t.Errorf("delivered file %s is not embedded", name)
		}
	}
}

var (
	assetReference = regexp.MustCompile(`assets/([A-Za-z0-9._-]+)`)
	photoKey       = regexp.MustCompile(`data-photo="([a-z0-9-]+)"`)
)

// TestEveryReferenceResolvesAndNothingIsOrphaned proves the published set is
// exactly what the page uses: every `assets/...` reference in the HTML, CSS
// and script — including the lightbox's `assets/<data-photo>.webp` built at
// run time — names an embedded font or a pinned media object, and every
// font and media object is referenced by something.
func TestEveryReferenceResolvesAndNothingIsOrphaned(t *testing.T) {
	available := map[string]string{}
	for _, object := range Media {
		available[object.Name] = "media"
	}
	for name := range exported {
		if len(name) > len("assets/") && name[:len("assets/")] == "assets/" {
			available[name[len("assets/"):]] = "font"
		}
	}
	referenced := map[string]bool{}
	for _, file := range []string{"index.html", "style.css", "app.js"} {
		data, err := fs.ReadFile(Pages, file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range assetReference.FindAllSubmatch(data, -1) {
			name := string(match[1])
			if name == "" || name[len(name)-1] == '.' {
				continue // the script's dynamic prefix "assets/" + key + ".webp"
			}
			referenced[name] = true
		}
		for _, match := range photoKey.FindAllSubmatch(data, -1) {
			referenced[string(match[1])+".webp"] = true
		}
	}
	var missing, orphaned []string
	for name := range referenced {
		if _, ok := available[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range available {
		if !referenced[name] {
			orphaned = append(orphaned, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphaned)
	if len(missing) > 0 {
		t.Errorf("referenced but not published: %v", missing)
	}
	if len(orphaned) > 0 {
		t.Errorf("published but never referenced: %v", orphaned)
	}
}

func TestMediaPinsAreWellFormed(t *testing.T) {
	digest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	names := map[string]bool{}
	for _, object := range Media {
		if names[object.Name] {
			t.Errorf("%s is pinned twice", object.Name)
		}
		names[object.Name] = true
		if !digest.MatchString(object.SHA256) || object.Size <= 0 {
			t.Errorf("%s has a malformed pin", object.Name)
		}
	}
	if len(Media) != 15 {
		t.Errorf("the delivered page uses 15 media files, the table pins %d", len(Media))
	}
	for _, name := range Withheld {
		if !names[name] {
			t.Errorf("withheld %s is not a pinned media file", name)
		}
	}
}
