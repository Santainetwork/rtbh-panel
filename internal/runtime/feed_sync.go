package runtime

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/feed"
)

// SyncFeed loads IPs/CIDRs from a URL or file and applies them to the given list.
func (s *Server) SyncFeed(ctx context.Context, list, source string, expandSlash24 bool) (int, error) {
	if source == "" {
		return 0, nil
	}
	prefixes, err := feed.Fetch(ctx, source, expandSlash24)
	if err != nil {
		return 0, fmt.Errorf("runtime: fetch feed %s: %w", source, err)
	}

	applied := 0
	for _, p := range prefixes {
		mutation := dashboard.PolicyMutation{
			Action: "add",
			List:   list,
			Prefix: p.String(),
		}
		if err := s.controller.Apply(ctx, mutation); err != nil {
			return applied, fmt.Errorf("runtime: apply feed prefix %s: %w", p, err)
		}
		applied++
	}
	return applied, nil
}

func (s *Server) runFeedSync(ctx context.Context) error {
	syncAll := func() {
		if s.config.WhitelistFeed != "" {
			count, err := s.SyncFeed(ctx, "whitelist", s.config.WhitelistFeed, s.config.WhitelistExpandSlash24)
			if err != nil {
				log.Printf("ERROR sync whitelist feed: %v", err)
			} else {
				log.Printf("INFO synced %d prefixes from whitelist feed %s", count, s.config.WhitelistFeed)
			}
		}
		if s.config.BlocklistFeed != "" {
			count, err := s.SyncFeed(ctx, "blocklist", s.config.BlocklistFeed, false)
			if err != nil {
				log.Printf("ERROR sync blocklist feed: %v", err)
			} else {
				log.Printf("INFO synced %d prefixes from blocklist feed %s", count, s.config.BlocklistFeed)
			}
		}
	}

	// Initial sync
	syncAll()

	if s.config.FeedInterval <= 0 {
		return nil
	}

	ticker := time.NewTicker(s.config.FeedInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			syncAll()
		}
	}
}
