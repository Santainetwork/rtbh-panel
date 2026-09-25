package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/feed"
	"github.com/arcelo/rtbh-panel/internal/policystore"
	"github.com/arcelo/rtbh-panel/internal/sqlstore"
)

type policyStoreAdapter struct {
	store  *policystore.Store
	dryRun bool
}

func NewConfiguredAdapter(config Config) (PolicyAdapter, error) {
	if config.DryRun {
		return &DryRunAdapter{}, nil
	}
	targetFile := config.PolicyFile
	if targetFile == "" {
		targetFile = config.DBDSN
	}
	if strings.HasSuffix(targetFile, ".db") || strings.HasSuffix(targetFile, ".sqlite") || config.DBDriver != "" {
		store := policystore.New()
		return &policyStoreAdapter{store: store}, nil
	}
	store, err := policystore.Open(targetFile)
	if err != nil {
		return nil, fmt.Errorf("runtime: open policy store: %w", err)
	}
	return &policyStoreAdapter{store: store}, nil
}

func (a *policyStoreAdapter) Apply(_ context.Context, change agentrpc.PolicyChange) error {
	if a == nil || a.store == nil {
		return errors.New("runtime: policy store is required")
	}
	if a.dryRun {
		return nil
	}
	if change.ExpiresAt != nil {
		prefix, err := netip.ParsePrefix(change.Prefix)
		if err != nil || prefix != prefix.Masked() {
			return errors.New("runtime: canonical policy prefix required")
		}
		_, err = a.store.AddUntil(policystore.Blocklist, prefix, *change.ExpiresAt)
		return err
	}
	return mutateStore(a.store, change.Operation, change.List, change.Prefix)
}

type dashboardBackend struct {
	config     Config
	engine     Engine
	store      *policystore.Store
	sqlStore   *sqlstore.SQLStore
	publish    func(dashboard.PolicyMutation)
	controller *policyController
	feedMgr    *feed.Manager
}

func (b *dashboardBackend) Config(ctx context.Context) (dashboard.Config, error) {
	ranges := make([]string, 0, len(b.config.ListenRanges))
	for _, prefix := range b.config.ListenRanges {
		ranges = append(ranges, prefix.String())
	}

	if b.sqlStore != nil {
		blCount, wlCount, _ := b.sqlStore.GetCounts(ctx)
		var blocklistStrings []string
		var whitelistStrings []string
		var policyItems []dashboard.PolicyItem

		if blItems, _, err := b.sqlStore.ListPoliciesPaginated(ctx, "blocklist", "", 1, 50); err == nil {
			for _, it := range blItems {
				blocklistStrings = append(blocklistStrings, it.Prefix)
				policyItems = append(policyItems, dashboard.PolicyItem{Prefix: it.Prefix, List: it.List, Source: it.Source})
			}
		}
		if wlItems, _, err := b.sqlStore.ListPoliciesPaginated(ctx, "whitelist", "", 1, 50); err == nil {
			for _, it := range wlItems {
				whitelistStrings = append(whitelistStrings, it.Prefix)
				policyItems = append(policyItems, dashboard.PolicyItem{Prefix: it.Prefix, List: it.List, Source: it.Source})
			}
		}

		return dashboard.Config{
			LocalASN:       b.config.LocalASN,
			RouterID:       b.config.RouterID.String(),
			ListenRanges:   ranges,
			PeerGroup:      "rtbh-dynamic",
			AllowedASNs:    b.config.AllowedASNs,
			MaxSessions:    b.config.MaxSessions,
			DefaultPolicy:  "reject",
			DryRun:         b.config.DryRun,
			Blocklist:      blocklistStrings,
			Whitelist:      whitelistStrings,
			Policies:       policyItems,
			BlocklistCount: blCount,
			WhitelistCount: wlCount,
		}, nil
	}

	var blocklistStrings []string
	if bl, err := b.store.Prefixes(policystore.Blocklist); err == nil {
		for _, p := range bl {
			blocklistStrings = append(blocklistStrings, p.String())
		}
	}
	var whitelistStrings []string
	if wl, err := b.store.Prefixes(policystore.Whitelist); err == nil {
		for _, p := range wl {
			whitelistStrings = append(whitelistStrings, p.String())
		}
	}
	var policyItems []dashboard.PolicyItem
	for _, str := range blocklistStrings {
		source := "Manual"
		if b.feedMgr != nil {
			if src, ok := b.feedMgr.PrefixSource(str); ok {
				source = src
			}
		}
		policyItems = append(policyItems, dashboard.PolicyItem{Prefix: str, Source: source, List: "blocklist"})
	}
	for _, str := range whitelistStrings {
		source := "Manual"
		if b.feedMgr != nil {
			if src, ok := b.feedMgr.PrefixSource(str); ok {
				source = src
			}
		}
		policyItems = append(policyItems, dashboard.PolicyItem{Prefix: str, Source: source, List: "whitelist"})
	}
	return dashboard.Config{
		LocalASN:      b.config.LocalASN,
		RouterID:      b.config.RouterID.String(),
		ListenRanges:  ranges,
		PeerGroup:     "rtbh-dynamic",
		AllowedASNs:   append([]uint32(nil), b.config.AllowedASNs...),
		MaxSessions:   b.config.MaxSessions,
		DefaultPolicy: "reject",
		DryRun:        b.config.DryRun,
		Blocklist:     blocklistStrings,
		Whitelist:     whitelistStrings,
		Policies:      policyItems,
	}, nil
}

func (*dashboardBackend) UpdateConfig(context.Context, dashboard.Config) error {
	return errors.New("runtime: live BGP reconfiguration is not supported; restart with validated flags")
}

func (b *dashboardBackend) EstablishedPeers(ctx context.Context) ([]dashboard.Peer, error) {
	status, err := b.engine.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime: BGP status: %w", err)
	}
	peers := make([]dashboard.Peer, 0, len(status.Peers))
	for _, peer := range status.Peers {
		peers = append(peers, dashboard.Peer{Address: peer.Address.String(), ASN: peer.ASN, State: peer.State})
	}
	return peers, nil
}

func (b *dashboardBackend) MutatePolicy(ctx context.Context, mutation dashboard.PolicyMutation) error {
	if b.controller != nil {
		return b.controller.Apply(ctx, mutation)
	}
	if b.config.DryRun {
		return errors.New("runtime: apply rejected while dry-run is enabled")
	}
	if err := (&policyStoreAdapter{store: b.store, dryRun: b.config.DryRun}).Apply(ctx, agentrpc.PolicyChange{
		ID:             "dashboard",
		IdempotencyKey: "dashboard",
		Operation:      mutation.Action,
		List:           mutation.List,
		Prefix:         mutation.Prefix,
	}); err != nil {
		return err
	}
	if !b.config.DryRun && b.publish != nil {
		b.publish(mutation)
	}
	return nil
}

func mutateStore(store *policystore.Store, operation, listName, prefixRaw string) error {
	prefix, err := netip.ParsePrefix(prefixRaw)
	if err != nil || prefix != prefix.Masked() {
		return errors.New("runtime: canonical policy prefix required")
	}
	var list policystore.List
	switch listName {
	case "blocklist":
		list = policystore.Blocklist
	case "whitelist":
		list = policystore.Whitelist
	default:
		return fmt.Errorf("runtime: unsupported list %q", listName)
	}
	switch operation {
	case "add", "replace":
		_, err = store.Add(list, prefix)
	case "remove", "delete":
		_, err = store.Remove(list, prefix)
	default:
		return fmt.Errorf("runtime: unsupported action %q", operation)
	}
	if err != nil {
		return fmt.Errorf("runtime: mutate policy store: %w", err)
	}
	return nil
}

func (b *dashboardBackend) ImportFeed(ctx context.Context, req dashboard.FeedImportRequest) (dashboard.FeedImportResult, error) {
	expand := req.ExpandSubnets || (req.List == "whitelist" && b.config.WhitelistExpandSlash24)
	prefixes, err := feed.Fetch(ctx, req.Source, expand)
	if err != nil {
		return dashboard.FeedImportResult{}, fmt.Errorf("runtime: fetch feed: %w", err)
	}

	result := dashboard.FeedImportResult{
		Applied: req.Apply && !b.config.DryRun,
		DryRun:  !req.Apply || b.config.DryRun,
		Count:   len(prefixes),
	}
	for _, p := range prefixes {
		result.Prefixes = append(result.Prefixes, p.String())
	}

	if !req.Apply || b.config.DryRun {
		return result, nil
	}

	for _, p := range prefixes {
		mutation := dashboard.PolicyMutation{
			Action: "add",
			List:   req.List,
			Prefix: p.String(),
		}
		if err := b.MutatePolicy(ctx, mutation); err != nil {
			return result, fmt.Errorf("runtime: apply prefix %s: %w", p, err)
		}
	}
	return result, nil
}

func (b *dashboardBackend) ListPolicies(ctx context.Context, list, search string, page, limit int) (dashboard.PaginatedPolicies, error) {
	if b.sqlStore != nil {
		items, total, err := b.sqlStore.ListPoliciesPaginated(ctx, list, search, page, limit)
		if err != nil {
			return dashboard.PaginatedPolicies{}, err
		}
		res := dashboard.PaginatedPolicies{
			Page:       page,
			Limit:      limit,
			Total:      total,
			Items:      make([]dashboard.PolicyItem, 0),
		}
		if limit > 0 {
			res.TotalPages = int(math.Ceil(float64(total) / float64(limit)))
		}
		for _, it := range items {
			res.Items = append(res.Items, dashboard.PolicyItem{
				Prefix: it.Prefix,
				List:   it.List,
				Source: it.Source,
			})
		}
		return res, nil
	}

	// In-memory fallback
	var all []string
	targetList := policystore.Blocklist
	if list == "whitelist" {
		targetList = policystore.Whitelist
	}
	if pList, err := b.store.Prefixes(targetList); err == nil {
		for _, p := range pList {
			all = append(all, p.String())
		}
	}
	var filtered []string
	q := strings.ToLower(strings.TrimSpace(search))
	for _, p := range all {
		if q == "" || strings.Contains(strings.ToLower(p), q) {
			filtered = append(filtered, p)
		}
	}
	total := len(filtered)
	if limit <= 0 {
		limit = 25
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	res := dashboard.PaginatedPolicies{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: int(math.Ceil(float64(total) / float64(limit))),
		Items:      make([]dashboard.PolicyItem, 0),
	}
	for _, p := range filtered[start:end] {
		src := "Manual"
		if b.feedMgr != nil {
			if s, ok := b.feedMgr.PrefixSource(p); ok {
				src = s
			}
		}
		res.Items = append(res.Items, dashboard.PolicyItem{
			Prefix: p,
			List:   list,
			Source: src,
		})
	}
	return res, nil
}

func (b *dashboardBackend) ListFeeds(ctx context.Context) ([]dashboard.SourceFeed, error) {
	if b.sqlStore != nil {
		feeds, err := b.sqlStore.ListFeeds(ctx)
		if err != nil {
			return nil, err
		}
		var res []dashboard.SourceFeed
		for _, f := range feeds {
			res = append(res, dashboard.SourceFeed{
				ID:            f.ID,
				Name:          f.Name,
				List:          f.List,
				URL:           f.URL,
				Interval:      f.Interval,
				Enabled:       f.Enabled,
				LastSync:      f.LastSync,
				PrefixCount:   f.PrefixCount,
				LastError:     f.LastError,
				ExpandSubnets: f.ExpandSubnets,
			})
		}
		return res, nil
	}
	if b.feedMgr == nil {
		return []dashboard.SourceFeed{}, nil
	}
	var res []dashboard.SourceFeed
	for _, f := range b.feedMgr.List() {
		lastSync := ""
		if !f.LastSync.IsZero() {
			lastSync = f.LastSync.Format("2006-01-02 15:04:05 UTC")
		}
		res = append(res, dashboard.SourceFeed{
			ID:            f.ID,
			Name:          f.Name,
			List:          f.List,
			URL:           f.URL,
			Interval:      int(f.Interval.Seconds()),
			Enabled:       f.Enabled,
			LastSync:      lastSync,
			PrefixCount:   f.PrefixCount,
			LastError:     f.LastError,
			ExpandSubnets: f.ExpandSubnets,
		})
	}
	return res, nil
}

func (b *dashboardBackend) SaveFeed(ctx context.Context, req dashboard.SourceFeed) (dashboard.SourceFeed, error) {
	if b.sqlStore != nil {
		if req.ID == "" {
			buf := make([]byte, 4)
			_, _ = rand.Read(buf)
			req.ID = "feed-" + hex.EncodeToString(buf)
		}
		if req.Interval <= 0 {
			req.Interval = 21600
		}
		err := b.sqlStore.SaveFeed(ctx, sqlstore.FeedSource{
			ID:            req.ID,
			Name:          req.Name,
			List:          req.List,
			URL:           req.URL,
			Interval:      req.Interval,
			Enabled:       req.Enabled,
			ExpandSubnets: req.ExpandSubnets,
		})
		return req, err
	}
	if b.feedMgr == nil {
		return req, errors.New("feed manager not initialized")
	}
	interval := time.Duration(req.Interval) * time.Second
	if interval <= 0 {
		interval = time.Hour
	}
	saved, err := b.feedMgr.Save(feed.FeedSource{
		ID:            req.ID,
		Name:          req.Name,
		List:          req.List,
		URL:           req.URL,
		Interval:      interval,
		Enabled:       req.Enabled,
		ExpandSubnets: req.ExpandSubnets,
	})
	if err != nil {
		return req, err
	}
	req.ID = saved.ID
	return req, nil
}

func (b *dashboardBackend) DeleteFeed(ctx context.Context, id string) error {
	if b.sqlStore != nil {
		deletedPrefixes, list, err := b.sqlStore.DeleteFeed(ctx, id)
		if err != nil {
			return err
		}
		if len(deletedPrefixes) > 0 {
			_ = b.controller.ApplyBatch(ctx, list, nil, deletedPrefixes)
		}
		return nil
	}
	if b.feedMgr == nil {
		return nil
	}
	return b.feedMgr.Delete(ctx, id)
}

func (b *dashboardBackend) SyncFeed(ctx context.Context, id string) (int, error) {
	if b.sqlStore != nil {
		feeds, err := b.sqlStore.ListFeeds(ctx)
		if err != nil {
			return 0, err
		}
		var target *sqlstore.FeedSource
		for i := range feeds {
			if feeds[i].ID == id {
				target = &feeds[i]
				break
			}
		}
		if target == nil {
			return 0, errors.New("feed not found")
		}
		prefixes, err := feed.Fetch(ctx, target.URL, target.ExpandSubnets)
		if err != nil {
			_ = b.sqlStore.UpdateFeedStatus(ctx, id, 0, "", err.Error())
			return 0, err
		}
		var strPrefixes []string
		for _, p := range prefixes {
			strPrefixes = append(strPrefixes, p.String())
		}
		toAdd, toRemove, err := b.sqlStore.SyncFeedPolicies(ctx, target.ID, target.Name, target.List, strPrefixes)
		if err != nil {
			return 0, err
		}
		if err := b.controller.ApplyBatch(ctx, target.List, toAdd, toRemove); err != nil {
			return len(strPrefixes), err
		}
		return len(strPrefixes), nil
	}
	if b.feedMgr == nil {
		return 0, nil
	}
	return b.feedMgr.SyncFeed(ctx, id)
}
