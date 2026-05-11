package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz_OK(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != "ok" {
		t.Errorf("body: got %q, want %q", got, "ok")
	}
}

func TestHealthz_DBDown(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	// Stop the pool out from under the router. Ping should fail; /healthz
	// should report 503. Cleanup is still safe — pool.Close() is idempotent.
	env.pool.Close()

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz after pool close: got %d, want 503", w.Code)
	}
}
