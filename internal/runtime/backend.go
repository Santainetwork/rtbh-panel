package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/feed"
	"github.com/arcelo/rtbh-panel/internal/policystore"
)

type policyStoreAdapter struct {
	store  *policystore.Store
	dryRun bool
}

func NewConfiguredAdapter(config Config) (PolicyAdapter, error) {
	if config.DryRun {
		return &DryRunAdapter{}, nil
	}
	store, err := policystore.Open(config.PolicyFile)
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
	publish    func(dashboard.PolicyMutation)
	controller *policyController
}

func (b *dashboardBackend) Config(context.Context) (dashboard.Config, error) {
	ranges := make([]string, 0, len(b.config.ListenRanges))
	for _, prefix := range b.config.ListenRanges {
		ranges = append(ranges, prefix.String())
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
