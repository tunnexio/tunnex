// Package log provides structured logging (slog) and HTTP middleware that
// stamps every request with a correlation ID and emits a structured access log.
//
// This is a cross-cutting concern established in S0.1 so that every later story
// gets request-scoped, correlated logs for free — never retrofitted.
package log

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// New builds a JSON slog.Logger at the given level ("debug"|"info"|"warn"|"error").
func New(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}

// Requests returns middleware that logs one structured line per request,
// including the chi request ID, method, path, status, and duration.
//
// It relies on chi's middleware.RequestID running earlier in the chain so that
// middleware.GetReqID(ctx) is populated.
func Requests(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			reqID := middleware.GetReqID(r.Context())
			// Surface the correlation ID to clients for support/debugging.
			if reqID != "" {
				ww.Header().Set("X-Request-ID", reqID)
			}

			next.ServeHTTP(ww, r)

			logger.LogAttrs(r.Context(), slog.LevelInfo, "http_request",
				slog.String("request_id", reqID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote", r.RemoteAddr),
			)
		})
	}
}

// FromContext is a placeholder for request-scoped logger retrieval used by later
// stories; for now it returns the default logger.
func FromContext(_ context.Context) *slog.Logger { return slog.Default() }
