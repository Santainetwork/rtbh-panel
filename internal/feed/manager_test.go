package feed

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerCascadeDelete(t *testing.T) {
	var deletedPrefixes []string
	var addedPrefixes []string

	onSync := func(_ context.Context, _ FeedSource, toAdd, _ []string) error {
		addedPrefixes = append(addedPrefixes, toAdd...)
		return nil
	}
	onDelete := func(_ context.Context, _ FeedSource, prefixes []string) error {
		deletedPrefixes = append(deletedPrefixes, prefixes...)
		return nil
	}

	dir := t.TempDir()
	feedFile := filepath.Join(dir, "list.txt")
	_ = os.WriteFile(feedFile, []byte("192.0.2.1/32\n192.0.2.2/32\n"), 0o600)

	mgr := NewManager(onSync, onDelete)
	source, err := mgr.Save(FeedSource{
		Name:     "Test Feed",
		URL:      feedFile,
		List:     "blocklist",
		Interval: time.Hour,
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	count, err := mgr.SyncFeed(context.Background(), source.ID)
	if err != nil || count != 2 {
		t.Fatalf("SyncFeed failed count=%d err=%v", count, err)
	}
	if len(addedPrefixes) != 2 {
		t.Fatalf("expected 2 added prefixes, got %d", len(addedPrefixes))
	}

	// Now delete feed and check cascade deletion
	if err := mgr.Delete(context.Background(), source.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if len(deletedPrefixes) != 2 {
		t.Fatalf("expected 2 deleted prefixes on cascade, got %d", len(deletedPrefixes))
	}
	if deletedPrefixes[0] != "192.0.2.1/32" || deletedPrefixes[1] != "192.0.2.2/32" {
		t.Fatalf("unexpected deleted prefixes: %v", deletedPrefixes)
	}
}

func mustNetipPrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}
