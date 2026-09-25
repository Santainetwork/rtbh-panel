package feed

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	input := `
# Comment line
// Another comment
192.0.2.1
192.0.2.2/32
198.51.100.0/24 # inline comment

2001:db8::1
`
	prefixes, err := ParseList(strings.NewReader(input), false)
	if err != nil {
		t.Fatalf("ParseList failed: %v", err)
	}

	expected := []string{
		"192.0.2.1/32",
		"192.0.2.2/32",
		"198.51.100.0/24",
		"2001:db8::1/128",
	}

	if len(prefixes) != len(expected) {
		t.Fatalf("got %d prefixes, want %d", len(prefixes), len(expected))
	}

	for i, exp := range expected {
		if prefixes[i].String() != exp {
			t.Errorf("prefix[%d] = %s, want %s", i, prefixes[i], exp)
		}
	}
}

func TestExpandIPv4Slash24(t *testing.T) {
	prefix := netip.MustParsePrefix("1.1.1.0/24")
	expanded := ExpandIPv4Slash24(prefix)

	if len(expanded) != 256 {
		t.Fatalf("got %d prefixes, want 256", len(expanded))
	}

	if expanded[0].String() != "1.1.1.0/32" {
		t.Errorf("first prefix = %s, want 1.1.1.0/32", expanded[0])
	}
	if expanded[255].String() != "1.1.1.255/32" {
		t.Errorf("last prefix = %s, want 1.1.1.255/32", expanded[255])
	}

	// Test /23 expansion (512 host IPs)
	slash23 := netip.MustParsePrefix("1.1.0.0/23")
	exp23 := ExpandIPv4ToSlash32(slash23)
	if len(exp23) != 512 {
		t.Fatalf("slash23: got %d prefixes, want 512", len(exp23))
	}
	if exp23[0].String() != "1.1.0.0/32" || exp23[511].String() != "1.1.1.255/32" {
		t.Fatalf("slash23 bounds: first=%s, last=%s", exp23[0], exp23[511])
	}

	// Test /19 expansion (8192 host IPs)
	slash19 := netip.MustParsePrefix("10.0.0.0/19")
	exp19 := ExpandIPv4ToSlash32(slash19)
	if len(exp19) != 8192 {
		t.Fatalf("slash19: got %d prefixes, want 8192", len(exp19))
	}
	if exp19[0].String() != "10.0.0.0/32" || exp19[8191].String() != "10.0.31.255/32" {
		t.Fatalf("slash19 bounds: first=%s, last=%s", exp19[0], exp19[8191])
	}

	// Non-expandable prefix (< /16)
	slash15 := netip.MustParsePrefix("10.0.0.0/15")
	notExp := ExpandIPv4ToSlash32(slash15)
	if len(notExp) != 1 || notExp[0] != slash15 {
		t.Fatalf("slash15 unexpectedly expanded: %v", notExp)
	}
}
