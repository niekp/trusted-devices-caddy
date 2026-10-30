package trusteddevices

import (
	"strings"
	"testing"
)

// mustParseIPList parses a list that may only produce warnings about host bits, as some tests want.
func mustParseIPList(data string) ipList {
	list, warnings := parseIPList(data)
	for _, w := range warnings {
		if !strings.Contains(w, "host bits") {
			panic("invalid test IP list: " + w)
		}
	}
	return list
}

func TestParseIPListSkipsCommentsAndWarnsAboutInvalidLines(t *testing.T) {
	list, warnings := parseIPList("# home\n192.168.1.100\n\n  10.0.0.0/24  \nnot-an-ip\n192.168.1.300\n")
	if len(list) != 2 {
		t.Fatalf("got %d entries, want 2", len(list))
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "not-an-ip") || !strings.Contains(warnings[1], "192.168.1.300") {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestParseIPListWarnsAboutRangesWiderThanWritten(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5/24":     "host bits",
		"10.0.0.1/0":      "every address",
		"0.0.0.0/0":       "every address",
		"::/0":            "every address",
		"192.168.1.0/24":  "",
		"2001:db8::/64":   "",
		"192.168.1.10/32": "",
	}
	for line, want := range cases {
		_, warnings := parseIPList(line)
		got := strings.Join(warnings, "; ")
		if want == "" && got != "" || want != "" && !strings.Contains(got, want) {
			t.Errorf("%s: warnings %q, want one about %q", line, got, want)
		}
	}
}

func TestMappedRangeMatchesIPv4Clients(t *testing.T) {
	list := mustParseIPList("::ffff:10.0.0.0/120")
	if !list.contains("10.0.0.7") || !list.contains("::ffff:10.0.0.7") || list.contains("10.0.1.7") {
		t.Fatal("IPv4-mapped range doesn't match like its IPv4 form")
	}
}

func TestIPListContains(t *testing.T) {
	list := mustParseIPList("192.168.1.100\n10.0.0.0/24\n2001:db8::/64\n")
	cases := map[string]bool{
		"192.168.1.100":     true,
		"192.168.1.101":     false,
		"10.0.0.1":          true,
		"10.0.0.255":        true,
		"10.0.1.1":          false,
		"::ffff:10.0.0.7":   true, // IPv4-mapped IPv6, as a dual-stack listener may report it
		"2001:db8::1234":    true,
		"2001:db8:0:1::1":   false,
		"":                  false,
		"192.168.1.100:443": false,
		"fe80::1%eth0":      false,
	}
	for ip, want := range cases {
		if got := list.contains(ip); got != want {
			t.Errorf("contains(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestHostBitsInRangeAreIgnored(t *testing.T) {
	list := mustParseIPList("10.0.0.5/24")
	if !list.contains("10.0.0.200") {
		t.Fatal("10.0.0.5/24 should cover the whole 10.0.0.0/24 range")
	}
}

func TestTrustedRangeGrantsAccess(t *testing.T) {
	m := newMiddleware(t)
	m.trustedIPs = mustParseIPList("192.168.1.0/24")
	_, called := serve(t, m, newReq("192.168.1.42", nil))
	if !called {
		t.Fatal("address inside a trusted range was denied")
	}
	_, called = serve(t, m, newReq("192.168.2.42", nil))
	if called {
		t.Fatal("address outside the trusted range was allowed")
	}
}

func TestLinkLocalWithZoneMatchesRange(t *testing.T) {
	list := mustParseIPList("fe80::/10")
	if !list.contains("fe80::1%en0") {
		t.Fatal("link-local address with a zone not matched")
	}
}
