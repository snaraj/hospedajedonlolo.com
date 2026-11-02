package site

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// deliveredScript is app.js exactly as the owner delivered it on 2026-10-31.
const deliveredScript = "816c39710259d64e97b45795824353fb9944de1775a258c93295d331c1c85adf"

// languageDefault is the whole owner-requested addition to app.js, spelled
// out so that changing what it does is an edit to this test, not only to a
// regenerated pin. It takes the first Spanish or English entry of the
// browser's preferences; anything else opens in English. It switches by
// clicking the delivered toggle, so the toggle's own code is untouched.
const languageDefault = "// Open in the visitor's browser language: the first Spanish or English preference wins, and any other browser gets English. The toggle still switches freely.\n" +
	"if([...(navigator.languages||[]),navigator.language].map(tag=>String(tag||'').slice(0,2).toLowerCase()).find(tag=>tag==='es'||tag==='en')!=='es')toggle.click();\n"

// mapOnRequest is the whole owner-requested addition that keeps Google from
// being contacted until the visitor asks for the map (issue #2, option 2).
// The frame carries its address in data-src; "Show the map" moves it to src,
// and a place button, which already sets src itself, also removes the button.
const mapOnRequest = "// Load the area map only when the visitor asks for it (issue #2): Google is contacted after a click on \"Show the map\" or on a place, never on its own.\n" +
	"const areaMap=document.getElementById('area-map'),showMap=document.getElementById('show-map');showMap.addEventListener('click',()=>{areaMap.src=areaMap.dataset.src;showMap.remove()});document.querySelectorAll('.map-select').forEach(button=>button.addEventListener('click',()=>showMap.remove()));\n"

// TestScriptKeepsTheDeliveredLines proves the only changes to the delivered
// script are the two owner-requested additions: the language default's two
// lines directly after the toggle's handler, and the map's two lines at the
// end. Dropping both gives back the delivered bytes exactly.
func TestScriptKeepsTheDeliveredLines(t *testing.T) {
	data, err := fs.ReadFile(Pages, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	last := len(lines) - 1 // SplitAfter leaves an empty final element after the closing newline
	if len(lines) < 10 || lines[last] != "" || !strings.HasPrefix(lines[4], "toggle.addEventListener('click'") ||
		lines[5]+lines[6] != languageDefault {
		t.Fatal("the language default is not exactly the two lines after the toggle's handler")
	}
	if lines[last-2]+lines[last-1] != mapOnRequest {
		t.Fatal("the map-on-request block is not exactly the script's last two lines")
	}
	delivered := strings.Join(lines[:5], "") + strings.Join(lines[7:last-2], "")
	if sum := sha256.Sum256([]byte(delivered)); hex.EncodeToString(sum[:]) != deliveredScript {
		t.Fatal("app.js changed beyond the language default")
	}
}

const htmlSpace = " \t\n\f\r"

// startTags returns the attributes of every start tag called name, read the
// way an HTML tokenizer reads them: names in any case, attributes separated
// by whitespace or '/' (or by nothing after a quoted value), optional
// whitespace around '=', quoted or unquoted values, and the first of a
// repeated attribute winning. A '>' inside a quoted value does not end the tag.
func startTags(page, name string) []map[string]string {
	var tags []map[string]string
	lower := strings.ToLower(page)
	for i := 0; ; {
		at := strings.Index(lower[i:], "<"+name)
		if at < 0 {
			return tags
		}
		j := i + at + 1 + len(name)
		if j < len(page) && !strings.ContainsRune(htmlSpace+"/>", rune(page[j])) {
			i = j // a longer tag name, such as <iframes
			continue
		}
		attrs := map[string]string{}
		for j < len(page) && page[j] != '>' {
			if strings.ContainsRune(htmlSpace+"/", rune(page[j])) {
				j++
				continue
			}
			k := j + 1 // an attribute name is at least one character, even '='
			for k < len(page) && !strings.ContainsRune(htmlSpace+"/>=", rune(page[k])) {
				k++
			}
			key, value := strings.ToLower(page[j:k]), ""
			for k < len(page) && strings.ContainsRune(htmlSpace, rune(page[k])) {
				k++
			}
			if k < len(page) && page[k] == '=' {
				for k++; k < len(page) && strings.ContainsRune(htmlSpace, rune(page[k])); k++ {
				}
				if k < len(page) && (page[k] == '"' || page[k] == '\'') {
					end := strings.IndexByte(page[k+1:], page[k])
					if end < 0 {
						end = len(page) - k - 1
					}
					value, k = page[k+1:k+1+end], k+end+2
				} else {
					v := k
					for k < len(page) && !strings.ContainsRune(htmlSpace+">", rune(page[k])) {
						k++
					}
					value = page[v:k]
				}
			}
			if _, seen := attrs[key]; !seen {
				attrs[key] = value
			}
			j = k
		}
		tags = append(tags, attrs)
		i = j
	}
}

// TestTheMapWaitsForTheVisitor pins issue #2's behaviour, not its bytes: no
// frame on the page has a src, so nothing loads Google on its own; the area
// map's address waits in data-src behind the "Show the map" button; and the
// privacy notice that compliance.json publishes at /#privacidad is on the page.
func TestTheMapWaitsForTheVisitor(t *testing.T) {
	data, err := fs.ReadFile(Pages, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	frames := startTags(page, "iframe")
	if len(frames) != 1 || frames[0]["id"] != "area-map" ||
		!strings.HasPrefix(frames[0]["data-src"], "https://maps.google.com/") {
		t.Fatalf("want exactly the area map frame with its address in data-src, got %v", frames)
	}
	if _, loads := frames[0]["src"]; loads {
		t.Fatal("the area map frame has a src, so Google loads before the visitor asks")
	}
	for _, want := range []string{`<button id="show-map" class="button" type="button"`, `<section class="section privacy" id="privacidad">`} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page lacks %s", want)
		}
	}
}

// exported pins every embedded file to the bytes the owner delivered on
// 2026-10-31 (CHECKSUMS.sha256 of the export, source commit c39ac49d). This is
// the "content does not change" invariant made executable: an edit to the
// page, its styles, its script or a font fails here and must be a reviewed,
// deliberate change to this table.
//
// Two deliberate changes so far, both owner decisions of 2026-11-02:
//   - the page opens in the visitor's browser language (issue #5): app.js
//     gains one comment line and one statement after the toggle's handler;
//   - privacy (issue #2, option 2): the area map loads only when the visitor
//     asks for it (index.html moves the frame's address to data-src behind a
//     "Show the map" button, app.js gains two lines at the end, style.css six
//     rules at the end), and a short bilingual privacy notice sits above the
//     footer. TestScriptKeepsTheDeliveredLines proves app.js is otherwise the
//     delivered script, and TestTheMapWaitsForTheVisitor pins the behaviour.
var exported = map[string]string{
	"index.html":                    "c7fb6536261466cafa7f91d9608b66e92bbf830501a22d6cba6c917964dfbf72",
	"style.css":                     "39327b42d74deff549819cbb1b7b1a16127af337b156452b9f1026b1db034df7",
	"app.js":                        "967388cb5a6afb2ed568db7cad15f6dbbe44437c923b3db30d1ad5e1aef0b41f",
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
	if !names["don-lolo.mp4"] {
		t.Error("the delivered film is not a pinned media file")
	}
}
