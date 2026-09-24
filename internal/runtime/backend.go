package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
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
	return mutateStore(a.store, change.Operation, change.List, change.Prefix)
}

type dashboardBackend struct {
	config  Config
	engine  Engine
	store   *policystore.Store
	publish func(dashboard.PolicyMutation)
}

func (b *dashboardBackend) Config(context.Context) (dashboard.Config, error) {
	ranges := make([]string, 0, len(b.config.ListenRanges))
	for _, prefix := range b.config.ListenRanges {
		ranges = append(ranges, prefix.String())
	}
	return dashboard.Config{
		LocalASN:      b.config.LocalASN,
		RouterID:      b.config.RouterID.String(),
		ListenRanges:  ranges,
		PeerGroup:     "rtbh-dynamic",
		AllowedASNs:   append([]uint32(nil), b.config.AllowedASNs...),
		MaxSessions:   b.config.MaxSessions,
		DefaultPolicy: "reject",
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
