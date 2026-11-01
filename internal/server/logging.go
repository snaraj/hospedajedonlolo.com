package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// requestLog writes one record per request. It deliberately records neither
// the client address nor the query string: the site needs neither to operate,
// and compliance.json states exactly what is kept.
func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		identity := requestIdentity(r.Header.Get(requestIDHeader))
		w.Header().Set(requestIDHeader, identity)
		recorder := &responseRecorder{ResponseWriter: w}
		defer func() {
			failure := recover()
			status := recorder.status
			if failure == nil && status == 0 {
				status = http.StatusOK
			}
			attrs := []slog.Attr{
				slog.String("request_id", identity),
				slog.String("http.request.method", r.Method),
				slog.String("url.path", r.URL.Path),
				slog.Int("http.response.status_code", status),
				slog.Float64("duration_ms", float64(time.Since(start))/float64(time.Millisecond)),
				slog.Int64("http.response.body.size", recorder.bytes),
				slog.String("network.protocol.version", strings.TrimPrefix(r.Proto, "HTTP/")),
			}
			if traceID, parentSpanID := traceContext(r.Header.Get(traceparentHeader)); traceID != "" {
				attrs = append(attrs, slog.String("trace_id", traceID), slog.String("parent_span_id", parentSpanID))
			}
			if failure != nil {
				attrs = append(attrs, slog.Any("error", fmt.Errorf("handler panic: %v", failure)))
				logger.LogAttrs(r.Context(), slog.LevelError, "request failed", attrs...)
				panic(failure)
			}
			level := slog.LevelInfo
			switch {
			case status >= http.StatusInternalServerError:
				level = slog.LevelError
			case status >= http.StatusBadRequest:
				level = slog.LevelWarn
			}
			logger.LogAttrs(r.Context(), level, "request served", attrs...)
		}()
		next.ServeHTTP(recorder, r)
	})
}

// requestIdentity keeps an inbound request id only when it has a safe shape,
// so a header can never inject structure into the logs.
func requestIdentity(inbound string) string {
	if inboundRequestIDShape.MatchString(inbound) {
		return inbound
	}
	identity := make([]byte, generatedRequestIDBytes)
	_, _ = rand.Read(identity)
	return hex.EncodeToString(identity)
}

// traceContext extracts a W3C trace id only from a well-formed traceparent.
func traceContext(value string) (string, string) {
	if !traceparentShape.MatchString(value) {
		return "", ""
	}
	version, traceID, parentID := value[:2], value[3:35], value[36:52]
	if version == "ff" || traceID == zeroTraceID || parentID == zeroParentID {
		return "", ""
	}
	return traceID, parentID
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// Unwrap lets http.ResponseController reach the connection beneath.
func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytes += int64(written)
	return written, err
}
