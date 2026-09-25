package runtime

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/arcelo/rtbh-panel/internal/policystore"
)

func TestServerSyncFeedWhitelistExpansion(t *testing.T) {
	dir := t.TempDir()
	feedFile := filepath.Join(dir, "whitelist.txt")
	content := "# trusted networks\n1.1.1.0/24\n192.0.2.1/32\n"
	if err := os.WriteFile(feedFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	store := policystore.New()
	cfg := DefaultConfig()
	cfg.DryRun = false
	cfg.WhitelistExpandSlash24 = true

	server := &Server{
		config: cfg,
		store:  store,
		controller: newPolicyController(
			store,
			&stubEngine{},
			false,
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("::1"),
			nil,
		),
	}

	count, err := server.SyncFeed(context.Background(), "whitelist", feedFile, true)
	if err != nil {
		t.Fatalf("SyncFeed failed: %v", err)
	}

	// 256 for 1.1.1.0/24 plus 1 for 192.0.2.1/32 = 257 prefixes!
	if count != 257 {
		t.Fatalf("expected 257 prefixes, got %d", count)
	}

	// Check that 1.1.1.0/32 and 1.1.1.255/32 are in the store
	whitelisted, err := store.Prefixes(policystore.Whitelist)
	if err != nil {
		t.Fatal(err)
	}
	if len(whitelisted) != 257 {
		t.Fatalf("expected 257 prefixes in store, got %d", len(whitelisted))
	}

	p0 := netip.MustParsePrefix("1.1.1.0/32")
	p255 := netip.MustParsePrefix("1.1.1.255/32")
	found0 := false
	found255 := false
	for _, p := range whitelisted {
		if p == p0 {
			found0 = true
		}
		if p == p255 {
			found255 = true
		}
	}
	if !found0 || !found255 {
		t.Fatalf("expected 1.1.1.0/32 and 1.1.1.255/32 to be in whitelist, found0=%v found255=%v", found0, found255)
	}
}
