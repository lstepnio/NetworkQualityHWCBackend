package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/auth"
)

// echoBodyHandler reads the request body and writes it back as the response.
// Used to assert that v1Auth doesn't break downstream body access.
var echoBodyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
})

func TestV1AuthLegacyPassthrough(t *testing.T) {
	// verifier == nil → behaves like the old permissiveBearer.
	h := v1Auth(nil, false, nil)(echoBodyHandler)

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"empty header allowed", "", http.StatusOK},
		{"any Bearer allowed", "Bearer whatever", http.StatusOK},
		{"unknown scheme rejected", "Basic abc", http.StatusUnauthorized},
		{"hmac-when-disabled rejected", "HMAC-SHA256 t=1,sig=ab", http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
			if c.authHeader != "" {
				req.Header.Set("Authorization", c.authHeader)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != c.wantStatus {
				t.Fatalf("status: got %d, want %d (body: %s)", rr.Code, c.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestV1AuthHMACValidAndBodyReadable(t *testing.T) {
	const secret = "lab-secret"
	verifier := auth.NewVerifier(secret)
	h := v1Auth(verifier, false, nil)(echoBodyHandler)

	body := []byte(`{"hello":"world"}`)
	bodyHash := auth.HashBody(body)
	now := time.Now().Unix()
	sig := auth.Sign(secret, http.MethodPost, "/v1/certifications", "dev-1", now, bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now, sig)

	req := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
	req.Header.Set("Authorization", header)
	req.Header.Set("X-Device-Id", "dev-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	// Downstream handler must have seen the original body — the auth
	// middleware drains it for hashing and is responsible for restoring it.
	if !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatalf("downstream body mismatch: got %q, want %q", rr.Body.String(), body)
	}
}

func TestV1AuthHMACInvalidSignature(t *testing.T) {
	verifier := auth.NewVerifier("lab-secret")
	h := v1Auth(verifier, false, nil)(echoBodyHandler)

	now := time.Now().Unix()
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now, strings.Repeat("aa", 32))
	req := httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
	req.Header.Set("Authorization", header)
	req.Header.Set("X-Device-Id", "dev-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestV1AuthStrictMode(t *testing.T) {
	const secret = "lab-secret"
	verifier := auth.NewVerifier(secret)
	h := v1Auth(verifier, true /* require */, nil)(echoBodyHandler)

	// 1. Empty header → 401
	req := httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty header in strict mode: got %d, want 401", rr.Code)
	}

	// 2. Bearer (legacy) → 401
	req = httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
	req.Header.Set("Authorization", "Bearer abc")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("legacy bearer in strict mode: got %d, want 401", rr.Code)
	}

	// 3. Valid HMAC → 200
	now := time.Now().Unix()
	sig := auth.Sign(secret, http.MethodGet, "/v1/cert-config", "dev-1", now, auth.HashBody(nil))
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now, sig)
	req = httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
	req.Header.Set("Authorization", header)
	req.Header.Set("X-Device-Id", "dev-1")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid HMAC in strict mode: got %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
}
