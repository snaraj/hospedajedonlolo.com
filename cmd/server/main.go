// Command server runs the hospedajedonlolo.com origin.
//
// Configuration comes only from the environment the Helm chart sets: PORT,
// MEDIA_ROOT, MEDIA_MAX_CONCURRENT, and optionally LOG_FORMAT and LOG_LEVEL.
// Every value is validated before a socket opens; a bad value stops the
// process instead of starting a site that is half configured.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/snaraj/hospedajedonlolo.com/internal/server"
	"github.com/snaraj/hospedajedonlolo.com/site"
)

const (
	serviceName           = "hospedajedonlolo.com"
	defaultPort           = 8080
	maxRequestHeaderBytes = 32 * 1024
	shutdownTimeout       = 10 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := newLogger(os.Stdout, isTerminal(os.Stdout), os.Getenv)
	pages, media := productionInputs()
	if err := run(ctx, logger, os.Getenv, nil, pages, media); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("server exited")
}

// productionInputs is the published site: the embedded page and the pinned
// media, the film included.
func productionInputs() (fs.FS, []site.Object) {
	return site.Pages, site.Media
}

// buildSite validates the environment and builds the verified site exactly as
// run serves it. It opens no socket, so the whole configuration path is
// testable on its own.
func buildSite(logger *slog.Logger, getenv func(string) string, pages fs.FS, media []site.Object) (*server.Site, int, int, error) {
	port, err := listenPort(getenv("PORT"))
	if err != nil {
		return nil, 0, 0, err
	}
	maxConcurrent, err := mediaConcurrency(getenv("MEDIA_MAX_CONCURRENT"))
	if err != nil {
		return nil, 0, 0, err
	}
	origin, err := server.New(server.Config{
		Pages:              pages,
		Media:              media,
		MediaRoot:          getenv("MEDIA_ROOT"),
		MediaMaxConcurrent: maxConcurrent,
		Logger:             logger,
	})
	if err != nil {
		return nil, 0, 0, err
	}
	return origin, port, maxConcurrent, nil
}

// run builds the site from the environment and serves until ctx ends. A nil
// listener means "listen on PORT"; tests pass their own listener, pages and
// media so the whole start-serve-drain path runs against a fixture volume.
func run(ctx context.Context, logger *slog.Logger, getenv func(string) string, listener net.Listener, pages fs.FS, media []site.Object) error {
	origin, port, maxConcurrent, err := buildSite(logger, getenv, pages, media)
	if err != nil {
		return err
	}
	defer origin.Close()

	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           origin.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// No WriteTimeout: a whole-response deadline would cut a slow visitor
		// off mid-film. The handler enforces a per-write idle deadline instead.
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: maxRequestHeaderBytes,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if listener == nil {
		listener, err = net.Listen("tcp", httpServer.Addr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()
	logger.Info("listening", "port", port, "media_objects", len(media), "media_max_concurrent", maxConcurrent)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received", "drain_timeout", shutdownTimeout.String())
		drainCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(drainCtx); err != nil {
			return fmt.Errorf("drain: %w", err)
		}
		logger.Info("server drained")
		return nil
	}
}

// listenPort accepts an unset value (8080) or an integer in 1..65535.
func listenPort(value string) (int, error) {
	if value == "" {
		return defaultPort, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("PORT must be an integer from 1 to 65535")
	}
	return port, nil
}

// mediaConcurrency requires an explicit bound; the chart always sets one.
func mediaConcurrency(value string) (int, error) {
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > server.MaxMediaConcurrency {
		return 0, fmt.Errorf("MEDIA_MAX_CONCURRENT must be an integer from 1 to %d", server.MaxMediaConcurrency)
	}
	return limit, nil
}

// newLogger honours LOG_FORMAT (json|text; JSON when stdout is not a terminal)
// and LOG_LEVEL (debug|info|warn|error). An unknown value falls back to the
// default and says so once, so a typo never silences the log.
func newLogger(out io.Writer, terminal bool, getenv func(string) string) *slog.Logger {
	format := getenv("LOG_FORMAT")
	level := slog.LevelInfo
	var warnings []string
	switch format {
	case "", "json", "text":
	default:
		warnings = append(warnings, "unrecognized LOG_FORMAT value; using the default")
		format = ""
	}
	if format == "" {
		format = "json"
		if terminal {
			format = "text"
		}
	}
	switch raw := getenv("LOG_LEVEL"); raw {
	case "", "info":
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		warnings = append(warnings, "unrecognized LOG_LEVEL value; using the default")
	}
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewJSONHandler(out, options)
	if format == "text" {
		handler = slog.NewTextHandler(out, options)
	}
	logger := slog.New(handler).With(identityArgs(debug.ReadBuildInfo())...)
	for _, warning := range warnings {
		logger.Warn(warning)
	}
	return logger
}

// identityArgs stamps every record with the service name and, when the build
// carries them, its version and source revision.
func identityArgs(info *debug.BuildInfo, ok bool) []any {
	args := []any{slog.String("service.name", serviceName)}
	if !ok || info == nil {
		return args
	}
	if version := info.Main.Version; version != "" && version != "(devel)" {
		args = append(args, slog.String("service.version", version))
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && setting.Value != "" {
			args = append(args, slog.String("vcs.ref.head.revision", setting.Value))
		}
	}
	return args
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
