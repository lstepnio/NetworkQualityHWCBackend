// Package asn looks up an IP's autonomous-system number and registered name
// via Team Cymru's public DNS service. Used at /v1/certifications ingest to
// stamp each cert with the ISP behind the request source IP — the canonical
// "is this an HWC customer's connection?" signal.
//
// Lookups are cheap (two TXT queries; usually under 100ms total) and tolerant
// of failure: on any DNS error or NXDOMAIN we return (0, "", nil) and the
// caller stores null for both columns. Hard failures (context cancelled by
// the request timeout) bubble up so the caller can log them.
package asn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Lookup resolves an IP to (asn, name). Both zero values mean "no ASN known
// for this IP" — either the IP is private/reserved or Cymru has no record.
// Returns an error only for unrecoverable problems (timeout, network down).
type Lookup interface {
	Lookup(ctx context.Context, ip string) (asn int, name string, err error)
}

// Cymru queries Team Cymru's `origin.asn.cymru.com` (IP → ASN) and
// `asn.cymru.com` (ASN → name) DNS TXT records.
type Cymru struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewCymru returns a Lookup with the given per-query timeout. A timeout
// of 0 means "use the context's deadline" — that's fine in production
// where the request itself has a timeout.
func NewCymru(timeout time.Duration) *Cymru {
	return &Cymru{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

func (c *Cymru) Lookup(ctx context.Context, ip string) (int, string, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0, "", nil // not an IP — caller already validated, but be defensive
	}
	// Skip private / loopback / link-local / unspecified ranges — Cymru has
	// no records for them and we'd just be wasting two DNS queries.
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return 0, "", nil
	}
	// Cymru's IPv4 service only — IPv6 needs a different query
	// (`origin6.asn.cymru.com`). For now we skip IPv6; STBs report IPv4
	// publicIp in practice.
	v4 := addr.To4()
	if v4 == nil {
		return 0, "", nil
	}

	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Step 1: IP → ASN. Reverse the octets and append origin.asn.cymru.com.
	rev := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", v4[3], v4[2], v4[1], v4[0])
	asnRecords, err := c.resolver.LookupTXT(ctx, rev)
	if err != nil {
		// NXDOMAIN is a normal "no record" case — treat as no-ASN, not an error.
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("origin lookup: %w", err)
	}
	if len(asnRecords) == 0 {
		return 0, "", nil
	}
	// Record looks like: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
	// Multi-homed IPs return space-separated ASNs as the first field; take
	// the first ("15169 16509 | …" → 15169).
	asn, ok := parseFirstASN(asnRecords[0])
	if !ok {
		return 0, "", nil
	}

	// Step 2: ASN → name.
	asLookup := fmt.Sprintf("AS%d.asn.cymru.com.", asn)
	nameRecords, err := c.resolver.LookupTXT(ctx, asLookup)
	if err != nil {
		// The ASN is valid but the name lookup failed — return the ASN
		// alone rather than dropping the whole record.
		return asn, "", nil
	}
	if len(nameRecords) == 0 {
		return asn, "", nil
	}
	// Record looks like: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
	name := parseASName(nameRecords[0])
	return asn, name, nil
}

func parseFirstASN(record string) (int, bool) {
	parts := strings.SplitN(record, "|", 2)
	if len(parts) == 0 {
		return 0, false
	}
	fields := strings.Fields(parts[0])
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func parseASName(record string) string {
	// Take the 5th pipe-separated field; trim country-code suffix if present.
	parts := strings.Split(record, "|")
	if len(parts) < 5 {
		return ""
	}
	name := strings.TrimSpace(parts[4])
	// Many records end with ", US" or similar country suffix; keep it — it's
	// useful context and small. If we want to strip later, do it in the
	// dashboard layer rather than dropping information here.
	return name
}

// Noop returns (0, "", nil) for every lookup. Used in tests and when
// ASN_LOOKUP_ENABLED=false.
type Noop struct{}

func (Noop) Lookup(_ context.Context, _ string) (int, string, error) {
	return 0, "", nil
}
