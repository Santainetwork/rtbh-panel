package sqlstore

import (
	"context"
	"testing"
)

func TestSQLStoreSQLite(t *testing.T) {
	ctx := context.Background()
	s, err := Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// 1. Feeds
	err = s.SaveFeed(ctx, FeedSource{
		ID:       "test-feed",
		Name:     "Test Intel",
		List:     "blocklist",
		URL:      "http://example.com/ips.txt",
		Interval: 3600,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("SaveFeed failed: %v", err)
	}

	feeds, err := s.ListFeeds(ctx)
	if err != nil || len(feeds) != 1 {
		t.Fatalf("ListFeeds returned %d feeds: %v", len(feeds), err)
	}

	// 2. Sync policies
	newPrefixes := []string{"192.0.2.1/32", "198.51.100.0/24"}
	added, removed, err := s.SyncFeedPolicies(ctx, "test-feed", "Test Intel", "blocklist", newPrefixes)
	if err != nil {
		t.Fatalf("SyncFeedPolicies failed: %v", err)
	}
	if len(added) != 2 || len(removed) != 0 {
		t.Errorf("got added=%d removed=%d, want 2, 0", len(added), len(removed))
	}

	// 3. Pagination
	items, total, err := s.ListPoliciesPaginated(ctx, "blocklist", "", 1, 10)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("ListPoliciesPaginated total=%d items=%d: %v", total, len(items), err)
	}
	if items[0].Source != "Test Intel" && items[1].Source != "Test Intel" {
		t.Errorf("expected source 'Test Intel', got %s", items[0].Source)
	}

	// 4. Cascade delete feed
	deletedPrefixes, list, err := s.DeleteFeed(ctx, "test-feed")
	if err != nil {
		t.Fatalf("DeleteFeed failed: %v", err)
	}
	if len(deletedPrefixes) != 2 || list != "blocklist" {
		t.Errorf("DeleteFeed returned %d prefixes, list %s", len(deletedPrefixes), list)
	}

	// Check policies are gone
	_, totalAfter, _ := s.ListPoliciesPaginated(ctx, "blocklist", "", 1, 10)
	if totalAfter != 0 {
		t.Errorf("expected 0 policies after feed deletion, got %d", totalAfter)
	}
}
