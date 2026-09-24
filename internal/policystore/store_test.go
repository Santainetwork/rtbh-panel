package policystore

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }

func TestZeroValueIsInMemoryStore(t *testing.T) {
	var s Store
	if changed, err := s.Add(Blocklist, mustPrefix("2001:db8::/32")); err != nil || !changed {
		t.Fatalf("add to zero value: changed=%v err=%v", changed, err)
	}
	if !s.Blocked(mustAddr("2001:db8::1")) {
		t.Fatal("zero-value store did not retain IPv6 policy")
	}
}

func TestWhitelistWinsByContainment(t *testing.T) {
	s := New()
	if changed, err := s.Add(Blocklist, mustPrefix("10.0.0.0/8")); err != nil || !changed {
		t.Fatalf("add blocklist: changed=%v err=%v", changed, err)
	}
	if changed, err := s.Add(Whitelist, mustPrefix("10.1.0.0/16")); err != nil || !changed {
		t.Fatalf("add whitelist: changed=%v err=%v", changed, err)
	}

	if s.Blocked(mustAddr("10.1.2.3")) {
		t.Fatal("whitelisted address reported blocked")
	}
	if !s.Blocked(mustAddr("10.2.2.3")) {
		t.Fatal("blocklisted address reported allowed")
	}

	s = New()
	_, _ = s.Add(Blocklist, mustPrefix("192.0.2.0/24"))
	_, _ = s.Add(Whitelist, mustPrefix("192.0.0.0/16"))
	if s.Blocked(mustAddr("192.0.2.1")) {
		t.Fatal("containing whitelist did not win")
	}
}

func TestMutationsAreValidatedIdempotentAndAudited(t *testing.T) {
	s := New()
	if changed, err := s.Add(List("invalid"), mustPrefix("192.0.2.0/24")); err == nil || changed {
		t.Fatalf("invalid list: changed=%v err=%v", changed, err)
	}
	if changed, err := s.Add(Blocklist, netip.Prefix{}); err == nil || changed {
		t.Fatalf("invalid prefix: changed=%v err=%v", changed, err)
	}

	// Host bits are normalized so equivalent CIDRs are one policy.
	p := netip.PrefixFrom(mustAddr("192.0.2.7"), 24)
	if changed, err := s.Add(Blocklist, p); err != nil || !changed {
		t.Fatalf("first add: changed=%v err=%v", changed, err)
	}
	if changed, err := s.Add(Blocklist, mustPrefix("192.0.2.0/24")); err != nil || changed {
		t.Fatalf("duplicate add: changed=%v err=%v", changed, err)
	}
	if got := len(s.Audit()); got != 1 {
		t.Fatalf("audit count after duplicate = %d, want 1", got)
	}

	if changed, err := s.Remove(Blocklist, mustPrefix("198.51.100.0/24")); err != nil || changed {
		t.Fatalf("missing remove: changed=%v err=%v", changed, err)
	}
	if changed, err := s.Remove(Blocklist, p); err != nil || !changed {
		t.Fatalf("existing remove: changed=%v err=%v", changed, err)
	}
	events := s.Audit()
	if len(events) != 2 || events[0].Operation != Add || events[1].Operation != Remove {
		t.Fatalf("audit events = %#v", events)
	}

	// Returned data must not expose mutable store state.
	events[0].List = Whitelist
	if s.Audit()[0].List != Blocklist {
		t.Fatal("Audit returned internal storage")
	}
}

func TestOpenPersistsPoliciesAndAuditAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Add(Blocklist, mustPrefix("203.0.113.0/24")); err != nil || !changed {
		t.Fatalf("add: changed=%v err=%v", changed, err)
	}
	if changed, err := s.Add(Whitelist, mustPrefix("203.0.113.8/32")); err != nil || !changed {
		t.Fatalf("whitelist: changed=%v err=%v", changed, err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Blocked(mustAddr("203.0.113.7")) || reopened.Blocked(mustAddr("203.0.113.8")) {
		t.Fatal("reopened policy decision differs")
	}
	if got := len(reopened.Audit()); got != 2 {
		t.Fatalf("reopened audit count = %d, want 2", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("policy file permissions = %o, want no group/other access", info.Mode().Perm())
	}
}

func TestFailedPersistenceDoesNotMutateMemory(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Add(Blocklist, mustPrefix("198.51.100.0/24")); err == nil || changed {
		t.Fatalf("failed persistence: changed=%v err=%v", changed, err)
	}
	if s.Blocked(mustAddr("198.51.100.1")) || len(s.Audit()) != 0 {
		t.Fatal("failed persistence changed in-memory state")
	}
}

func TestPrefixesReturnsCopy(t *testing.T) {
	s := New()
	_, _ = s.Add(Blocklist, mustPrefix("192.0.2.0/24"))
	prefixes, err := s.Prefixes(Blocklist)
	if err != nil {
		t.Fatal(err)
	}
	prefixes[0] = mustPrefix("198.51.100.0/24")
	if !s.Blocked(mustAddr("192.0.2.1")) || s.Blocked(mustAddr("198.51.100.1")) {
		t.Fatal("Prefixes returned internal storage")
	}
}

func TestOpenRejectsUnsafePersistedData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"blocklist":["not-a-prefix"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted an invalid persisted prefix")
	}
}
