// Package auth implements the HMAC-SHA256 device-auth scheme used on the
// public /v1/* surface. The scheme is deliberately stateless: no
// /v1/devices/register endpoint, no DB-backed token store, no nonce cache.
// The Android client signs each request with a build-time shared secret,
// the server verifies, and a ±5-minute timestamp window bounds replay.
//
// Threat model: lab-LAN-deployed STBs, ~tens of devices, single-tap cert
// flow supervised by a field tech. The scheme stops external curl and
// passive replay; it does not defend against an attacker who has the APK
// + the tooling to extract BuildConfig strings. That trade is acceptable
// for the operational simplicity (no registration retries, no per-device
// state to back up).
//
// Canonical request format:
//
//	<METHOD>\n
//	<PATH>\n
//	<X-Device-Id>\n
//	<unix-seconds>\n
//	<sha256-hex(body)>
//
// Signature: HMAC-SHA256(secret, canonical), hex-encoded.
// Header: Authorization: HMAC-SHA256 t=<unix>,sig=<hex>
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MaxSkew is the absolute drift the verifier tolerates between the client's
// timestamp and the server's clock. STBs sync via NTP on boot; 5 minutes
// covers clock-skew on freshly-booted boxes without making replay windows
// uncomfortably wide.
const MaxSkew = 5 * time.Minute

// HeaderScheme is the literal scheme token at the start of the
// Authorization header value (after "Bearer "-style parsing).
const HeaderScheme = "HMAC-SHA256"

// Verifier validates HMAC-SHA256 signatures against a configured secret.
// A zero-value Verifier (empty secret) is unusable — Verify returns
// ErrMissingSecret. This is intentional: tests construct verifiers
// explicitly; the middleware decides what to do when the secret is unset
// at boot time.
type Verifier struct {
	secret []byte
	now    func() time.Time
}

// NewVerifier returns a Verifier bound to secret. secret must be non-empty;
// see package doc for why empty secrets are a configuration error rather
// than a permissive default.
func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: []byte(secret), now: time.Now}
}

// Verify checks that header is a well-formed HMAC-SHA256 Authorization
// header and that its signature matches the canonical request constructed
// from method, path, deviceID, and bodyHash.
//
// bodyHash MUST be the hex-encoded SHA-256 of the request body (or of the
// empty string for bodyless requests). Callers buffer the body once and
// pass the hash here so the middleware does not have to re-read the
// request stream.
//
// Errors returned are deliberately granular so the middleware can
// distinguish "absent / wrong scheme" (fall back to legacy passthrough)
// from "malformed / mismatched" (401).
func (v *Verifier) Verify(header, method, path, deviceID, bodyHash string) error {
	if len(v.secret) == 0 {
		return ErrMissingSecret
	}
	t, sig, err := parseHeader(header)
	if err != nil {
		return err
	}
	clientTime := time.Unix(t, 0)
	skew := v.now().Sub(clientTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxSkew {
		return fmt.Errorf("%w: %s skew (max %s)", ErrSkewExceeded, skew.Round(time.Second), MaxSkew)
	}
	expected := computeSignature(v.secret, method, path, deviceID, t, bodyHash)
	supplied, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrMalformedHeader)
	}
	if !hmac.Equal(expected, supplied) {
		return ErrBadSignature
	}
	return nil
}

// HasScheme reports whether header is an HMAC-SHA256 Authorization
// header (without validating it). Used by the middleware to choose
// between the HMAC path and legacy passthrough.
func HasScheme(header string) bool {
	const prefix = "HMAC-SHA256 "
	return strings.HasPrefix(header, prefix)
}

// HashBody returns the hex-encoded SHA-256 of body. Empty body hashes to
// the sha256 of the empty string (consistent with how GET requests sign
// "no body").
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

var (
	ErrMissingSecret   = errors.New("verifier has no configured secret")
	ErrMalformedHeader = errors.New("malformed HMAC-SHA256 Authorization header")
	ErrSkewExceeded    = errors.New("timestamp outside allowed skew window")
	ErrBadSignature    = errors.New("HMAC signature did not match")
)

// parseHeader extracts t and sig from an "HMAC-SHA256 t=<unix>,sig=<hex>"
// header value. Whitespace around the comma is tolerated; key order is
// not enforced.
func parseHeader(header string) (t int64, sig string, err error) {
	const prefix = "HMAC-SHA256 "
	if !strings.HasPrefix(header, prefix) {
		return 0, "", fmt.Errorf("%w: scheme is not HMAC-SHA256", ErrMalformedHeader)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if rest == "" {
		return 0, "", fmt.Errorf("%w: empty parameters", ErrMalformedHeader)
	}
	var tStr, sigStr string
	for _, kv := range strings.Split(rest, ",") {
		kv = strings.TrimSpace(kv)
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return 0, "", fmt.Errorf("%w: malformed parameter %q", ErrMalformedHeader, kv)
		}
		k, v := kv[:eq], kv[eq+1:]
		switch k {
		case "t":
			tStr = v
		case "sig":
			sigStr = v
		default:
			// Unknown parameter — ignore so future extensions (e.g. kid)
			// don't break older verifiers.
		}
	}
	if tStr == "" || sigStr == "" {
		return 0, "", fmt.Errorf("%w: missing t or sig", ErrMalformedHeader)
	}
	t, err = strconv.ParseInt(tStr, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("%w: t is not an integer", ErrMalformedHeader)
	}
	return t, sigStr, nil
}

func computeSignature(secret []byte, method, path, deviceID string, t int64, bodyHash string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(deviceID))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(strconv.FormatInt(t, 10)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(bodyHash))
	return mac.Sum(nil)
}

// Sign returns the hex-encoded HMAC for the canonical request. It is the
// inverse of Verify and exists so tests (and one day, a Go client) can
// produce headers without re-implementing the canonical-string layout.
func Sign(secret string, method, path, deviceID string, t int64, bodyHash string) string {
	return hex.EncodeToString(computeSignature([]byte(secret), method, path, deviceID, t, bodyHash))
}
