package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestVerifyHappyPath(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)

	bodyHash := HashBody([]byte(`{"hello":"world"}`))
	sig := Sign("topsecret", "POST", "/v1/certifications", "dev-123", now.Unix(), bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now.Unix(), sig)

	if err := v.Verify(header, "POST", "/v1/certifications", "dev-123", bodyHash); err != nil {
		t.Fatalf("expected verify to succeed, got %v", err)
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)

	originalHash := HashBody([]byte(`{"x":1}`))
	tamperedHash := HashBody([]byte(`{"x":2}`))
	sig := Sign("topsecret", "POST", "/v1/certifications", "dev-123", now.Unix(), originalHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now.Unix(), sig)

	err := v.Verify(header, "POST", "/v1/certifications", "dev-123", tamperedHash)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyTamperedDeviceID(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)

	bodyHash := HashBody(nil)
	sig := Sign("topsecret", "GET", "/v1/cert-config", "dev-A", now.Unix(), bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now.Unix(), sig)

	err := v.Verify(header, "GET", "/v1/cert-config", "dev-B", bodyHash)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected device-id swap to fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifyTamperedMethodPath(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)

	bodyHash := HashBody(nil)
	sig := Sign("topsecret", "GET", "/v1/cert-config", "dev-1", now.Unix(), bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", now.Unix(), sig)

	// Same signature replayed against a different endpoint must fail.
	err := v.Verify(header, "GET", "/v1/app/version", "dev-1", bodyHash)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected path swap to fail with ErrBadSignature, got %v", err)
	}
}

func TestVerifySkewOutsideWindow(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)

	// Client clock is 10 minutes behind — outside the ±5 min window.
	clientT := now.Add(-10 * time.Minute).Unix()
	bodyHash := HashBody(nil)
	sig := Sign("topsecret", "GET", "/v1/cert-config", "dev-1", clientT, bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", clientT, sig)

	err := v.Verify(header, "GET", "/v1/cert-config", "dev-1", bodyHash)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("expected ErrSkewExceeded, got %v", err)
	}
}

func TestVerifySkewInsideWindowBothDirections(t *testing.T) {
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)
	bodyHash := HashBody(nil)

	// Client a bit ahead and a bit behind — both should pass.
	for _, delta := range []time.Duration{-4 * time.Minute, +4 * time.Minute} {
		clientT := now.Add(delta).Unix()
		sig := Sign("topsecret", "GET", "/v1/cert-config", "dev-1", clientT, bodyHash)
		header := fmt.Sprintf("HMAC-SHA256 t=%d,sig=%s", clientT, sig)
		if err := v.Verify(header, "GET", "/v1/cert-config", "dev-1", bodyHash); err != nil {
			t.Fatalf("delta %v: expected verify to succeed, got %v", delta, err)
		}
	}
}

func TestVerifyMalformedHeaders(t *testing.T) {
	v := NewVerifier("topsecret")
	v.now = fixedClock(time.Unix(1_715_000_000, 0))

	bad := []string{
		"",
		"Bearer abc",
		"HMAC-SHA256 ",
		"HMAC-SHA256 t=,sig=abc",
		"HMAC-SHA256 sig=abc",
		"HMAC-SHA256 t=1715",
		"HMAC-SHA256 t=notanumber,sig=abc",
		"HMAC-SHA256 t=1715000000,sig=zzz", // non-hex
	}
	for _, h := range bad {
		err := v.Verify(h, "GET", "/v1/cert-config", "dev-1", HashBody(nil))
		if err == nil {
			t.Fatalf("expected error for malformed header %q, got nil", h)
		}
		if !errors.Is(err, ErrMalformedHeader) {
			t.Fatalf("expected ErrMalformedHeader for %q, got %v", h, err)
		}
	}
}

func TestVerifyUnknownParameterIgnored(t *testing.T) {
	// Forward-compat: an unknown parameter (e.g. a future kid for key rotation)
	// must not break a valid signature.
	v := NewVerifier("topsecret")
	now := time.Unix(1_715_000_000, 0)
	v.now = fixedClock(now)
	bodyHash := HashBody(nil)
	sig := Sign("topsecret", "GET", "/v1/cert-config", "dev-1", now.Unix(), bodyHash)
	header := fmt.Sprintf("HMAC-SHA256 kid=v1,t=%d,sig=%s", now.Unix(), sig)
	if err := v.Verify(header, "GET", "/v1/cert-config", "dev-1", bodyHash); err != nil {
		t.Fatalf("unknown parameter should be ignored, got %v", err)
	}
}

func TestVerifyEmptySecret(t *testing.T) {
	v := NewVerifier("")
	err := v.Verify("HMAC-SHA256 t=1,sig=ab", "GET", "/v1/x", "d", HashBody(nil))
	if !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret, got %v", err)
	}
}

func TestHasScheme(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"Bearer abc", false},
		{"HMAC-SHA256 t=1,sig=ab", true},
		{"hmac-sha256 t=1,sig=ab", false}, // case-sensitive on purpose
	}
	for _, c := range cases {
		if got := HasScheme(c.in); got != c.want {
			t.Errorf("HasScheme(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSignDeterministic(t *testing.T) {
	a := Sign("k", "GET", "/p", "d", 1, "h")
	b := Sign("k", "GET", "/p", "d", 1, "h")
	if a != b {
		t.Fatalf("Sign should be deterministic, got %q vs %q", a, b)
	}
	if len(a) != 64 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("Sign output is not 64-hex: %q", a)
	}
}
