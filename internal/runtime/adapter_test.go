package runtime

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/policystore"
)

type recordingAdapter struct {
	mu      sync.Mutex
	changes []agentrpc.PolicyChange
}

func (a *recordingAdapter) Apply(_ context.Context, change agentrpc.PolicyChange) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.changes = append(a.changes, change)
	return nil
}

func (a *recordingAdapter) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.changes)
}

func TestDryRunAdapterNeverInvokesExternalSideEffects(t *testing.T) {
	adapter := DryRunAdapter{}
	change := agentrpc.PolicyChange{ID: "p-1", IdempotencyKey: "idem-1", Operation: "add", List: "blocklist", Prefix: "203.0.113.0/24"}
	if err := adapter.Apply(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if adapter.Applied() != 0 {
		t.Fatalf("dry-run applied count = %d", adapter.Applied())
	}
}

func TestNewAgentUsesDryRunAdapterByDefault(t *testing.T) {
	cfg := testConfig(t)
	agent, err := NewAgent(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := agent.adapter.(*DryRunAdapter); !ok {
		t.Fatalf("default adapter = %T, want *DryRunAdapter", agent.adapter)
	}
}

func TestConfiguredAdapterPersistsOnlyInApplyMode(t *testing.T) {
	cfg := testConfig(t)
	change := agentrpc.PolicyChange{ID: "p-1", IdempotencyKey: "idem-1", Operation: "add", List: "blocklist", Prefix: "203.0.113.0/24"}
	adapter, err := NewConfiguredAdapter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if _, err := policystore.Open(cfg.PolicyFile); err != nil {
		t.Fatal(err)
	}

	cfg.DryRun = false
	adapter, err = NewConfiguredAdapter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	store, err := policystore.Open(cfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	prefixes, err := store.Prefixes(policystore.Blocklist)
	if err != nil || len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix(change.Prefix) {
		t.Fatalf("prefixes=%v err=%v", prefixes, err)
	}
}

func TestDashboardBackendRejectsApplyWhileDryRunEnabled(t *testing.T) {
	cfg := testConfig(t)
	backend := &dashboardBackend{config: cfg, store: policystore.New()}
	err := backend.MutatePolicy(context.Background(), dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24"})
	if err == nil {
		t.Fatal("dry-run backend accepted applied dashboard mutation")
	}
}

func TestDashboardBackendReportsDryRunMode(t *testing.T) {
	cfg := testConfig(t)
	cfg.DryRun = false
	backend := &dashboardBackend{config: cfg, store: policystore.New()}
	config, err := backend.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if config.DryRun {
		t.Fatal("dashboard config reports dry-run while apply mode is enabled")
	}
}

type noOpAdapter struct{}

func (noOpAdapter) Apply(context.Context, agentrpc.PolicyChange) error { return nil }
