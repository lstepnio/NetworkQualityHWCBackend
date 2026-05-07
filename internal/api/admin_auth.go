package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// adminBearer enforces a fixed shared secret on /admin/* routes. The token
// comes from the ADMIN_TOKEN env var; an empty token disables the admin API
// entirely (every request returns 503). A constant-time compare prevents
// timing oracles when the token is shorter than the supplied bearer.
//
// This is intentionally a different surface from the device-facing
// permissiveBearer middleware. Admin tooling is staff-only and cannot share
// the device path's "any non-empty token works" posture.
func adminBearer(token string) func(http.Handler) http.Handler {
	tokenBytes := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token == "" {
				writeError(w, http.StatusServiceUnavailable, "admin api disabled (set ADMIN_TOKEN)")
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "admin authentication required")
				return
			}
			supplied := []byte(strings.TrimPrefix(auth, "Bearer "))
			if subtle.ConstantTimeCompare(supplied, tokenBytes) != 1 {
				writeError(w, http.StatusUnauthorized, "invalid admin token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
