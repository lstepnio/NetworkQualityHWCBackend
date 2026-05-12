package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/auth"
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
				slog.String("client_ip", clientIP(r)),
				slog.String("device_id", r.Header.Get("X-Device-Id")),
				slog.String("app_version", r.Header.Get("X-App-Version")),
				slog.String("request_id", w.Header().Get("X-Request-Id")),
			)
		})
	}
}

// clientIP returns the network-layer source address of the request,
// stripped of its port. We deliberately ignore X-Forwarded-For today:
// the lab-LAN deployment has no reverse proxy in front, so trusting
// XFF would just hand any caller a way to spoof the access log. When
// prod ships behind a load balancer, gate XFF parsing behind a
// trusted-proxy allowlist before flipping that on.
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
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

// v1Auth gates the device-facing /v1/* surface. It supports the
// HMAC-SHA256 scheme (see internal/auth) and a legacy passthrough so a
// fleet running pre-HMAC client builds keeps working through the rollout
// window.
//
// Modes:
//   - verifier == nil:    legacy passthrough only. Behaves like the old
//     permissiveBearer middleware: empty header OK, any non-empty
//     "Bearer ..." header OK, "Basic ..." or other schemes → 401.
//   - verifier != nil, requireStrict == false: empty header OK, "Bearer ..."
//     OK, "HMAC-SHA256 ..." is verified and must pass. This is the
//     "observe + opt-in" mode used while the field fleet upgrades.
//   - verifier != nil, requireStrict == true:  every request MUST present a
//     valid "HMAC-SHA256 ..." header. Empty or "Bearer ..." → 401.
//
// The middleware buffers the body (already bounded by maxBodyBytes upstream)
// so the canonical-request hash can be computed once and the body re-read
// downstream.
func v1Auth(verifier *auth.Verifier, requireStrict bool, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			scheme := schemeOf(header)

			switch {
			case scheme == schemeHMAC:
				if verifier == nil {
					// Header claims HMAC but the server isn't configured to
					// verify. Better to fail loudly than to silently accept.
					writeError(w, http.StatusUnauthorized, "HMAC auth not enabled on this server")
					return
				}
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					writeError(w, http.StatusBadRequest, "could not read request body")
					return
				}
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				bodyHash := auth.HashBody(bodyBytes)
				if err := verifier.Verify(header, r.Method, r.URL.Path, r.Header.Get("X-Device-Id"), bodyHash); err != nil {
					if logger != nil {
						logger.Warn("v1 auth: HMAC verification failed",
							slog.String("path", r.URL.Path),
							slog.String("device_id", r.Header.Get("X-Device-Id")),
							slog.String("err", err.Error()),
						)
					}
					writeError(w, http.StatusUnauthorized, "invalid HMAC signature")
					return
				}
			case scheme == schemeBearer:
				if requireStrict {
					writeError(w, http.StatusUnauthorized, "HMAC-SHA256 required")
					return
				}
				// Legacy passthrough; accept any non-empty token.
			case scheme == schemeNone:
				if requireStrict {
					writeError(w, http.StatusUnauthorized, "Authorization header required")
					return
				}
			default:
				writeError(w, http.StatusUnauthorized, "unsupported authorization scheme")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type authScheme int

const (
	schemeNone authScheme = iota
	schemeBearer
	schemeHMAC
	schemeUnknown
)

func schemeOf(header string) authScheme {
	if header == "" {
		return schemeNone
	}
	if auth.HasScheme(header) {
		return schemeHMAC
	}
	if strings.HasPrefix(header, "Bearer ") {
		return schemeBearer
	}
	return schemeUnknown
}
