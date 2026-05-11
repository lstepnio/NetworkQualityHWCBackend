package asn

import "testing"

func TestParseFirstASN(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01", 15169, true},
		// Multi-homed IPs return space-separated ASNs in the first field.
		{"15169 16509 | 8.8.8.0/24 | US | arin | 1992-12-01", 15169, true},
		{"  7029  | …", 7029, true},
		{"", 0, false},
		{"not-an-asn | …", 0, false},
		{"0 | …", 0, false},
		{"-1 | …", 0, false},
	}
	for _, c := range cases {
		got, ok := parseFirstASN(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseFirstASN(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseASName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"15169 | US | arin | 2000-03-30 | GOOGLE, US", "GOOGLE, US"},
		{"7029 | US | arin | 1995-12-04 | HOTWIRE-COMMUNICATIONS, US", "HOTWIRE-COMMUNICATIONS, US"},
		{"too | few | fields", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := parseASName(c.in)
		if got != c.want {
			t.Errorf("parseASName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNoopAlwaysZero(t *testing.T) {
	asn, name, err := Noop{}.Lookup(nil, "8.8.8.8")
	if asn != 0 || name != "" || err != nil {
		t.Errorf("Noop.Lookup = (%d, %q, %v), want (0, \"\", nil)", asn, name, err)
	}
}
