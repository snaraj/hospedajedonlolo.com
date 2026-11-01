package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/snaraj/hospedajedonlolo.com/site"
)

func TestListenPort(t *testing.T) {
	if port, err := listenPort(""); err != nil || port != 8080 {
		t.Fatalf("default: %d %v", port, err)
	}
	if port, err := listenPort("9090"); err != nil || port != 9090 {
		t.Fatalf("explicit: %d %v", port, err)
	}
	for _, bad := range []string{"0", "65536", "-1", "80a", " 80"} {
		if _, err := listenPort(bad); err == nil {
			t.Fatalf("PORT %q accepted", bad)
		}
	}
}

func TestMediaConcurrencyIsRequiredAndBounded(t *testing.T) {
	if n, err := mediaConcurrency("32"); err != nil || n != 32 {
		t.Fatalf("32: %d %v", n, err)
	}
	for _, bad := range []string{"", "0", "257", "x"} {
		if _, err := mediaConcurrency(bad); err == nil {
			t.Fatalf("MEDIA_MAX_CONCURRENT %q accepted", bad)
		}
	}
}

func TestLoggerFormatsLevelsAndWarnings(t *testing.T) {
	cases := []struct {
		env      map[string]string
		terminal bool
		want     []string
	}{
		{map[string]string{}, false, []string{`"service.name":"hospedajedonlolo.com"`}},
		{map[string]string{}, true, []string{"service.name=hospedajedonlolo.com"}},
		{map[string]string{"LOG_FORMAT": "text"}, false, []string{"service.name=hospedajedonlolo.com"}},
		{map[string]string{"LOG_FORMAT": "xml"}, false, []string{"unrecognized LOG_FORMAT"}},
		{map[string]string{"LOG_LEVEL": "loud"}, false, []string{"unrecognized LOG_LEVEL"}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		logger := newLogger(&buf, c.terminal, func(k string) string { return c.env[k] })
		logger.Info("probe")
		for _, want := range c.want {
			if !strings.Contains(buf.String(), want) {
				t.Fatalf("env %v: log lacks %q:\n%s", c.env, want, buf.String())
			}
		}
	}
	for level, wantDebug := range map[string]bool{"debug": true, "info": false, "warn": false, "error": false} {
		var buf bytes.Buffer
		logger := newLogger(&buf, false, func(k string) string { return map[string]string{"LOG_LEVEL": level}[k] })
		if logger.Enabled(context.Background(), slog.LevelDebug) != wantDebug {
			t.Fatalf("LOG_LEVEL=%s debug enabled mismatch", level)
		}
	}
}

func TestIdentityArgs(t *testing.T) {
	if args := identityArgs(nil, false); len(args) != 1 {
		t.Fatalf("no build info: %v", args)
	}
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.1.1"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.time", Value: ""}}}
	if args := identityArgs(info, true); len(args) != 3 {
		t.Fatalf("build info: %v", args)
	}
	if args := identityArgs(&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true); len(args) != 1 {
		t.Fatalf("devel build: %v", args)
	}
}

func fixtureVolume(t *testing.T) (string, []site.Object) {
	t.Helper()
	root := t.TempDir()
	data := []byte("webp-fixture")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, "immutable", digest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hero.webp"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, []site.Object{{Name: "hero.webp", SHA256: digest, Size: int64(len(data)), ContentType: "image/webp"}}
}

func TestRunServesThenDrainsOnSignal(t *testing.T) {
	root, media := fixtureVolume(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MEDIA_ROOT": root, "MEDIA_MAX_CONCURRENT": "2"}
	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func(k string) string { return env[k] }, listener, site.Pages, media, nil)
	}()
	base := "http://" + listener.Addr().String()
	var response *http.Response
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if response, err = http.Get(base + "/assets/hero.webp"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "webp-fixture" {
		t.Fatalf("media through the real server: %d %q", response.StatusCode, body)
	}
	page, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	if page.StatusCode != http.StatusOK || page.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("page through the real server: %d", page.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("drain: %v", err)
	}
	for _, want := range []string{"listening", "shutdown signal received", "server drained"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("lifecycle log lacks %q", want)
		}
	}
}

func TestRunRefusesBadConfigurationBeforeListening(t *testing.T) {
	root, media := fixtureVolume(t)
	cases := map[string]map[string]string{
		"bad port":          {"PORT": "x", "MEDIA_ROOT": root, "MEDIA_MAX_CONCURRENT": "2"},
		"no concurrency":    {"MEDIA_ROOT": root},
		"no media root":     {"MEDIA_MAX_CONCURRENT": "2"},
		"relative root":     {"MEDIA_ROOT": "media", "MEDIA_MAX_CONCURRENT": "2"},
		"wrong media bytes": {"MEDIA_ROOT": t.TempDir(), "MEDIA_MAX_CONCURRENT": "2"},
	}
	for name, env := range cases {
		err := run(context.Background(), slog.New(slog.DiscardHandler), func(k string) string { return env[k] }, nil, site.Pages, media, nil)
		if err == nil {
			t.Fatalf("%s: started", name)
		}
	}
	err := run(context.Background(), slog.New(slog.DiscardHandler), func(string) string { return "" }, nil, fstest.MapFS{}, media, nil)
	if err == nil {
		t.Fatal("empty pages started")
	}
}

func TestRunReportsListenAndServeFailures(t *testing.T) {
	root, media := fixtureVolume(t)
	// Occupy the port on every interface, exactly as run would bind it; an
	// occupation on loopback alone does not stop a wildcard bind everywhere.
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	env := map[string]string{"PORT": itoa(port), "MEDIA_ROOT": root, "MEDIA_MAX_CONCURRENT": "1"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, slog.New(slog.DiscardHandler), func(k string) string { return env[k] }, nil, site.Pages, media, nil); err == nil {
		t.Fatal("listening on an occupied port succeeded")
	}
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closed.Close()
	if err := run(context.Background(), slog.New(slog.DiscardHandler), func(k string) string { return env[k] }, closed, site.Pages, media, nil); err == nil {
		t.Fatal("serving on a closed listener succeeded")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

func TestProductionInputsAreThePublishedSite(t *testing.T) {
	pages, media, withheld := productionInputs()
	if pages != site.Pages || len(media) != len(site.Media) || !slices.Equal(withheld, site.Withheld) || len(withheld) == 0 {
		t.Fatalf("production inputs drifted from the site package: %d media, withheld %v", len(media), withheld)
	}
}

func TestIsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "plain")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("a regular file is not a terminal")
	}
}
