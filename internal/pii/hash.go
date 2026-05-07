// Package pii applies the server-side PII redaction policy to incoming
// CertificationResult payloads. The fields hashed here come from SPEC §2
// ("zero customer PII unless explicitly approved") and PRODUCTION_READINESS.md;
// the policy is provisional until legal sign-off, so the field set is
// concentrated in this one file for easy auditing.
package pii

import (
	"crypto/sha256"
	"encoding/hex"
)

type Hasher struct {
	pepper []byte
}

func NewHasher(pepper string) *Hasher {
	return &Hasher{pepper: []byte(pepper)}
}

// Hash returns the lower-case hex SHA-256 of pepper||value, or the empty
// string if value is empty. Deterministic for a fixed pepper, so two clients
// sending the same MAC/IP produce the same hash and remain joinable.
func (h *Hasher) Hash(value string) string {
	if value == "" {
		return ""
	}
	d := sha256.New()
	d.Write(h.pepper)
	d.Write([]byte(value))
	return hex.EncodeToString(d.Sum(nil))
}

// piiPaths enumerates the JSONPath-ish locations rewritten in every payload.
// Order matches SPEC §2 + the user's explicit list in the phase-1 plan.
var piiPaths = [][]string{
	{"identity", "hsn"},
	{"identity", "ethernetMac"},
	{"identity", "wifiMac"},
	{"network", "publicIp"},
	{"network", "gatewayIp"},
	{"wifi", "ssid"},
	{"wifi", "bssid"},
}

// Redact walks the parsed payload and replaces each PII field in-place with
// its hash. Null/missing values stay null. Nested non-object parents are
// left alone (defensive: if a future contract change re-shapes the tree,
// we don't crash, we just don't redact).
func (h *Hasher) Redact(payload map[string]any) {
	for _, path := range piiPaths {
		redactAt(payload, path, h)
	}
}

func redactAt(root map[string]any, path []string, h *Hasher) {
	cur := root
	for i, key := range path {
		if i == len(path)-1 {
			v, ok := cur[key]
			if !ok || v == nil {
				return
			}
			s, ok := v.(string)
			if !ok || s == "" {
				return
			}
			cur[key] = h.Hash(s)
			return
		}
		next, ok := cur[key].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}
