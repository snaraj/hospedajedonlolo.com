package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIdentityKeepsOnlySafeInboundIDs(t *testing.T) {
	if got := requestIdentity("abc_DEF-123"); got != "abc_DEF-123" {
		t.Fatalf("safe id replaced: %q", got)
	}
	for _, hostile := range []string{"", "a b", "x\ny", strings.Repeat("a", 65), `"}`} {
		if got := requestIdentity(hostile); got == hostile || len(got) != 32 {
			t.Fatalf("hostile id %q kept or malformed replacement %q", hostile, got)
		}
	}
}

func TestTraceContextAcceptsOnlyValidTraceparent(t *testing.T) {
	trace, parent := traceContext("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if trace != "4bf92f3577b34da6a3ce929d0e0e4736" || parent != "00f067aa0ba902b7" {
		t.Fatalf("valid traceparent: %q %q", trace, parent)
	}
	for _, bad := range []string{
		"", "garbage",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
	} {
		if trace, _ := traceContext(bad); trace != "" {
			t.Fatalf("invalid traceparent %q accepted", bad)
		}
	}
}

func TestLogLevelsFollowStatusAndPanicsAreRecorded(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	serve := func(h http.HandlerFunc, headers map[string]string) {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		requestLog(logger, h).ServeHTTP(httptest.NewRecorder(), r)
	}
	serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, nil)
	serve(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, nil)
	serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) },
		map[string]string{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	out := buf.String()
	for _, want := range []string{`"level":"WARN"`, `"level":"ERROR"`, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`, `"http.response.body.size":2`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %s:\n%s", want, out)
		}
	}
	buf.Reset()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was swallowed")
			}
		}()
		serve(func(http.ResponseWriter, *http.Request) { panic("boom") }, nil)
	}()
	if !strings.Contains(buf.String(), `"msg":"request failed"`) || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("panic not recorded: %s", buf.String())
	}
}
