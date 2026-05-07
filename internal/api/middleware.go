package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const maxRequestBody = 256 << 10 // 256 KB; matches contract cap on POST /v1/certifications

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(s int) {
	sr.status = s
	sr.ResponseWriter.WriteHeader(s)
}

func slogRequest(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sr := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(sr, r)
			logger.LogAttrs(r.Context(), slog.LevelInfo, "http",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sr.status),
				slog.Duration("dur", time.Since(start)),
				slog.String("device_id", r.Header.Get("X-Device-Id")),
				slog.String("app_version", r.Header.Get("X-App-Version")),
				slog.String("request_id", w.Header().Get("X-Request-Id")),
			)
		})
	}
}

func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic", slog.Any("err", rec), slog.String("path", r.URL.Path))
					writeError(w, http.StatusInternalServerError, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func maxBodyBytes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// permissiveBearer honors the contract's bearerAuth declaration without
// enforcing it. Phase 1 ships without /v1/devices/register; the Android
// client today uses NoAuthProvider and sends no Authorization header.
// We accept both: any non-empty Bearer token, or no header at all. The
// middleware only rejects malformed Authorization headers (e.g. "Basic ...")
// so plumbing bugs are visible.
func permissiveBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" && !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "unsupported authorization scheme")
			return
		}
		next.ServeHTTP(w, r)
	})
}
