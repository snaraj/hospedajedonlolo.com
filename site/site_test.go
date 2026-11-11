package site

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
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

// scriptEdits are the reviewed changes made INSIDE delivered lines, each the
// delivered text and the text that replaced it. Every one changes how the
// script loads or degrades, never what the page shows or says.
var scriptEdits = []struct{ delivered, shipped string }{
	// Release 0.1.7 (issue #16): the lightbox opens the photograph's own
	// content-addressed URL, which its button carries in data-photo, instead
	// of building an unversioned one from a key.
	{"dialog.querySelector('img').src='assets/'+button.dataset.photo+'.webp';", "dialog.querySelector('img').src=button.dataset.photo;"},
}

// TestScriptKeepsTheDeliveredLines proves the only changes to the delivered
// script are the two owner-requested additions (the language default's two
// lines directly after the toggle's handler, and the map's two lines at the
// end) and the named scriptEdits. Dropping both additions and undoing every
// edit gives back the delivered bytes exactly.
func TestScriptKeepsTheDeliveredLines(t *testing.T) {
	data, err := fs.ReadFile(Pages, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := undoScriptChanges(string(data)); err != nil {
		t.Fatal(err)
	}
}

// undoScriptChanges is TestScriptKeepsTheDeliveredLines's check, separate so
// its own test can feed it altered scripts.
func undoScriptChanges(script string) error {
	lines := strings.SplitAfter(script, "\n")
	last := len(lines) - 1 // SplitAfter leaves an empty final element after the closing newline
	if len(lines) < 10 || lines[last] != "" || !strings.HasPrefix(lines[4], "toggle.addEventListener('click'") ||
		lines[5]+lines[6] != languageDefault {
		return errors.New("the language default is not exactly the two lines after the toggle's handler")
	}
	if lines[last-2]+lines[last-1] != mapOnRequest {
		return errors.New("the map-on-request block is not exactly the script's last two lines")
	}
	delivered := strings.Join(lines[:5], "") + strings.Join(lines[7:last-2], "")
	for _, edit := range scriptEdits {
		if strings.Count(delivered, edit.shipped) != 1 {
			return fmt.Errorf("the reviewed edit %q is not in the script exactly once", edit.shipped)
		}
		delivered = strings.Replace(delivered, edit.shipped, edit.delivered, 1)
	}
	if sum := sha256.Sum256([]byte(delivered)); hex.EncodeToString(sum[:]) != deliveredScript {
		return errors.New("app.js changed beyond the language default, the map block and the reviewed edits")
	}
	return nil
}

func TestTheScriptCheckSeesEveryChange(t *testing.T) {
	data, err := fs.ReadFile(Pages, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for name, altered := range map[string]string{
		"an edit undone":       strings.Replace(script, scriptEdits[0].shipped, scriptEdits[0].delivered, 1),
		"an edit made twice":   strings.Replace(script, scriptEdits[0].shipped, scriptEdits[0].shipped+scriptEdits[0].shipped, 1),
		"an unreviewed change": strings.Replace(script, "dialog.showModal();", "dialog.show();", 1),
		"a line appended":      script + "void 0;\n",
	} {
		if altered == script {
			t.Fatalf("%s: the alteration did not apply", name)
		}
		if undoScriptChanges(altered) == nil {
			t.Errorf("%s passed the delivered-script check", name)
		}
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

// everyStartTag returns every start tag on the page as its lowercase name and
// attributes, read by startTags. It over-reads rather than under-reads: a
// "<name" inside an attribute value counts too, so nothing a parser could
// see as an element is missed.
func everyStartTag(page string) map[string][]map[string]string {
	tags := map[string][]map[string]string{}
	for _, match := range regexp.MustCompile(`<([A-Za-z][A-Za-z0-9-]*)`).FindAllStringSubmatch(page, -1) {
		name := strings.ToLower(match[1])
		if _, done := tags[name]; !done {
			tags[name] = startTags(page, name)
		}
	}
	return tags
}

// TestNothingOnThePageWeakensItsReferrerPolicy holds the page to the promise
// its Referrer-Policy header makes: no request it starts names the page. An
// element's referrerpolicy attribute replaces the document's policy for the
// request that element makes (the map frame's no-referrer-when-downgrade sent
// Google the page address), a <meta name="referrer"> replaces it for the whole
// page, and a script can set either; so the only value admitted is the
// header's own, no such meta exists, and the script never touches a referrer.
func TestNothingOnThePageWeakensItsReferrerPolicy(t *testing.T) {
	data, err := fs.ReadFile(Pages, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	tags := everyStartTag(string(data))
	if len(tags["iframe"]) != 1 || len(tags["img"]) == 0 || len(tags["a"]) == 0 {
		t.Fatalf("the page was not read: %d frames, %d images, %d links", len(tags["iframe"]), len(tags["img"]), len(tags["a"]))
	}
	for name, elements := range tags {
		for _, attrs := range elements {
			if value, set := attrs["referrerpolicy"]; set && strings.ToLower(strings.TrimSpace(value)) != "no-referrer" {
				t.Errorf("a <%s> asks for referrer policy %q, weaker than the page's no-referrer", name, value)
			}
			if name == "meta" && (strings.EqualFold(strings.TrimSpace(attrs["name"]), "referrer") || strings.EqualFold(strings.TrimSpace(attrs["http-equiv"]), "referrer-policy")) {
				t.Errorf("a <meta> sets the referrer policy to %q", attrs["content"])
			}
		}
	}
	script, err := fs.ReadFile(Pages, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(script)), "referrer") {
		t.Error("the script touches a referrer policy")
	}
}

// exported pins every embedded file to the bytes the owner delivered on
// 2026-10-31 (CHECKSUMS.sha256 of the export, source commit c39ac49d). This is
// the "content does not change" invariant made executable: an edit to the
// page, its styles, its script or a font fails here and must be a reviewed,
// deliberate change to this table.
//
// Three deliberate changes so far, all owner decisions of 2026-11-02:
//   - the page opens in the visitor's browser language (issue #5): app.js
//     gains one comment line and one statement after the toggle's handler;
//   - privacy (issue #2, option 2): the area map loads only when the visitor
//     asks for it (index.html moves the frame's address to data-src behind a
//     "Show the map" button, app.js gains two lines at the end, style.css six
//     rules at the end), and a short bilingual privacy notice sits above the
//     footer. TestScriptKeepsTheDeliveredLines proves app.js is otherwise the
//     delivered script, and TestTheMapWaitsForTheVisitor pins the behaviour.
//   - network-error reports (issue #10): the edge stopped requesting them,
//     so the privacy notice drops that clause in Spanish and in English.
//
// Release 0.1.7 (issue #16) changes delivery, never what the page shows or
// says:
//   - the map frame's referrerpolicy is no-referrer, the page's own policy,
//     pinned by TestNothingOnThePageWeakensItsReferrerPolicy;
//   - every file the page loads is named by its content address,
//     <stem>.<sha256>.<ext>: the page's stylesheet, script, photographs and
//     film, the stylesheet's fonts, and the lightbox's photographs, which
//     app.js now reads whole from data-photo (scriptEdits).
//     TestEveryReferenceIsTheContentAddressOfAPublishedFile holds every
//     address to the bytes it names.
var exported = map[string]string{
	"index.html":                    "8287861c68f3a0f69f28c5f7d4d0ca705abdebeb1a0eceef073aa6f79f74d4f1",
	"style.css":                     "8fb8e798a2d37acc4a2fc21613ecb0b9daefabaaf442d0e8914fc0b71309f67b",
	"app.js":                        "0ce5218a46024d67ee41872c9c817ffb2df5dcbf504409829890a79e57016216",
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
	// contentAddress is how the page names every file it loads: the
	// published name with the SHA-256 of its bytes before the extension. The
	// origin answers it only while the digest is the file's own
	// (internal/server), so the stylesheet, script, fonts and media may be
	// cached for a year and a release still reaches every visitor through the
	// page's own revalidation.
	contentAddress = regexp.MustCompile(`^((?:assets/)?[a-z0-9][a-z0-9-]*)\.([0-9a-f]{64})(\.[a-z0-9]+)$`)
	// strayAsset finds every "assets/..." in the three files, wherever it is,
	// so a reference outside the attributes pageReferences reads cannot hide.
	strayAsset = regexp.MustCompile(`assets/[^"'\s(),]*`)
	cssURL     = regexp.MustCompile(`url\(\s*['"]?([^'")\s]+)`)
)

// pageReferences returns every same-origin URL the page and its stylesheet
// load: src, href, poster, data-photo (the lightbox's full photograph) and
// each srcset candidate on every element, and every url() in the stylesheet.
// Off-site addresses, in-page anchors and inline data are not loads from this
// origin and are left out.
func pageReferences(pages fs.FS) ([]string, error) {
	page, err := fs.ReadFile(pages, "index.html")
	if err != nil {
		return nil, err
	}
	css, err := fs.ReadFile(pages, "style.css")
	if err != nil {
		return nil, err
	}
	var all []string
	for _, elements := range everyStartTag(string(page)) {
		for _, attrs := range elements {
			for _, key := range []string{"src", "href", "poster", "data-photo"} {
				if value, ok := attrs[key]; ok {
					all = append(all, value)
				}
			}
			for _, candidate := range strings.Split(attrs["srcset"], ",") {
				if fields := strings.Fields(candidate); len(fields) > 0 {
					all = append(all, fields[0])
				}
			}
		}
	}
	for _, match := range cssURL.FindAllStringSubmatch(string(css), -1) {
		all = append(all, match[1])
	}
	var local []string
	for _, ref := range all {
		if !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "#") && !strings.HasPrefix(ref, "data:") &&
			!strings.HasPrefix(ref, "mailto:") && !strings.HasPrefix(ref, "tel:") {
			local = append(local, ref)
		}
	}
	return local, nil
}

// referenceProblems lists every way the page's references and the published
// set disagree: a reference that is not a content address, one naming nothing
// published, one whose digest is not its file's own, a stray "assets/" that is
// not a content address, and a stylesheet, script, font or media file that
// nothing references.
func referenceProblems(pages fs.FS, media []Object) []string {
	digests := map[string]string{}
	for _, object := range media {
		digests["assets/"+object.Name] = object.SHA256
	}
	var problems []string
	err := fs.WalkDir(pages, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || name == "index.html" {
			return err
		}
		data, err := fs.ReadFile(pages, name)
		sum := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(sum[:])
		return err
	})
	refs, refErr := pageReferences(pages)
	if err = errors.Join(err, refErr); err != nil {
		return []string{err.Error()}
	}
	used := map[string]bool{}
	for _, ref := range refs {
		match := contentAddress.FindStringSubmatch(ref)
		if match == nil {
			problems = append(problems, ref+" is not a content address")
			continue
		}
		name := match[1] + match[3]
		used[name] = true
		if want, published := digests[name]; !published {
			problems = append(problems, ref+" names nothing published")
		} else if want != match[2] {
			problems = append(problems, ref+" carries a digest other than its file's")
		}
	}
	for _, file := range []string{"index.html", "style.css", "app.js"} {
		data, _ := fs.ReadFile(pages, file)
		for _, stray := range strayAsset.FindAllString(string(data), -1) {
			if !contentAddress.MatchString(stray) {
				problems = append(problems, file+" names "+stray+", which is not a content address")
			}
		}
	}
	for name := range digests {
		if !used[name] {
			problems = append(problems, name+" is published but never referenced")
		}
	}
	sort.Strings(problems)
	return problems
}

// TestEveryReferenceIsTheContentAddressOfAPublishedFile proves the published
// set is exactly what the page uses, each file named by its own digest.
func TestEveryReferenceIsTheContentAddressOfAPublishedFile(t *testing.T) {
	refs, err := pageReferences(Pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) < len(Media)+len(exported)-1 {
		t.Fatalf("read only %d references", len(refs))
	}
	for _, problem := range referenceProblems(Pages, Media) {
		t.Error(problem)
	}
}

// TestAReferenceFollowsTheBytesItNames proves the check is not decorative:
// one changed byte in a file, a different pin, an unreferenced file or a
// reference without its digest each leaves the page naming bytes nobody
// publishes.
func TestAReferenceFollowsTheBytesItNames(t *testing.T) {
	copied := func() fstest.MapFS {
		pages := fstest.MapFS{}
		if err := fs.WalkDir(Pages, ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := fs.ReadFile(Pages, name)
			pages[name] = &fstest.MapFile{Data: data}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	if problems := referenceProblems(copied(), Media); len(problems) != 0 {
		t.Fatalf("the copy already disagrees: %v", problems)
	}
	edited := func(name, old, new string) fstest.MapFS {
		pages := copied()
		data := string(pages[name].Data)
		if strings.Count(data, old) != 1 {
			t.Fatalf("%s holds %q %d times", name, old, strings.Count(data, old))
		}
		pages[name] = &fstest.MapFile{Data: []byte(strings.Replace(data, old, new, 1))}
		return pages
	}
	page := string(copied()["index.html"].Data)
	stylesheet := regexp.MustCompile(`style\.[0-9a-f]{64}\.css`).FindString(page)
	repinned := append([]Object(nil), Media...)
	repinned[0].SHA256 = strings.Repeat("0", 64)
	extra := append(append([]Object(nil), Media...), Object{Name: "unused.webp", SHA256: strings.Repeat("1", 64), Size: 1, ContentType: "image/webp"})
	for name, c := range map[string]struct {
		pages fstest.MapFS
		media []Object
	}{
		"a stylesheet byte changed": {edited("style.css", "--green:#263f35", "--green:#263f36"), Media},
		"a font byte changed": {func() fstest.MapFS {
			p := copied()
			p["assets/font-0.ttf"].Data = append(p["assets/font-0.ttf"].Data, 0)
			return p
		}(), Media},
		"a media pin changed":        {copied(), repinned},
		"a file nobody references":   {copied(), extra},
		"a reference without digest": {edited("index.html", `href="`+stylesheet+`"`, `href="style.css"`), Media},
		"a stray unversioned asset":  {edited("app.js", "dialog.showModal();", "dialog.showModal();void'assets/hero.webp';"), Media},
	} {
		if problems := referenceProblems(c.pages, c.media); len(problems) == 0 {
			t.Errorf("%s: the reference check found nothing", name)
		}
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
