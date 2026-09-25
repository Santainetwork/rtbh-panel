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

	// Non /24 prefix should not be expanded
	slash25 := netip.MustParsePrefix("1.1.1.0/25")
	notExp := ExpandIPv4Slash24(slash25)
	if len(notExp) != 1 || notExp[0] != slash25 {
		t.Fatalf("slash25 unexpectedly expanded: %v", notExp)
	}
}
