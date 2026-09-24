package runtime

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/arcelo/rtbh-panel/internal/bgpengine"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/policystore"
)

type recordingRouteEngine struct {
	announced   []bgpengine.Route
	withdrawn   []bgpengine.Route
	announceErr error
}

func (*recordingRouteEngine) Start(context.Context) error { return nil }
func (*recordingRouteEngine) Stop(context.Context) error  { return nil }
func (*recordingRouteEngine) Status(context.Context) (bgpengine.Status, error) {
	return bgpengine.Status{}, nil
}
func (e *recordingRouteEngine) Announce(route bgpengine.Route) error {
	if e.announceErr != nil {
		return e.announceErr
	}
	e.announced = append(e.announced, route)
	return nil
}
func (e *recordingRouteEngine) Withdraw(route bgpengine.Route) error {
	e.withdrawn = append(e.withdrawn, route)
	return nil
}

func testPolicyController(t *testing.T, dryRun bool) (*policyController, *policystore.Store, *recordingRouteEngine) {
	t.Helper()
	store := policystore.New()
	engine := &recordingRouteEngine{}
	controller := newPolicyController(store, engine, dryRun, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::1"), nil)
	return controller, store, engine
}

func TestPolicyControllerBlocklistLifecycle(t *testing.T) {
	controller, store, engine := testPolicyController(t, false)
	mutation := dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24"}
	if err := controller.Apply(context.Background(), mutation); err != nil {
		t.Fatal(err)
	}
	if len(engine.announced) != 1 || engine.announced[0].Communities[0] != bgpengine.BlackholeCommunity {
		t.Fatalf("announced=%#v", engine.announced)
	}
	if err := controller.Apply(context.Background(), mutation); err != nil {
		t.Fatal(err)
	}
	if len(engine.announced) != 1 {
		t.Fatalf("duplicate announced=%d", len(engine.announced))
	}
	mutation.Action = "remove"
	if err := controller.Apply(context.Background(), mutation); err != nil {
		t.Fatal(err)
	}
	if len(engine.withdrawn) != 1 || store.Blocked(netip.MustParseAddr("203.0.113.1")) {
		t.Fatalf("withdrawn=%#v", engine.withdrawn)
	}
}

func TestPolicyControllerWhitelistSuppressesAndRemovalRestoresDeny(t *testing.T) {
	controller, _, engine := testPolicyController(t, false)
	deny := dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24"}
	allow := dashboard.PolicyMutation{Action: "add", List: "whitelist", Prefix: "203.0.113.8/32"}
	if err := controller.Apply(context.Background(), deny); err != nil {
		t.Fatal(err)
	}
	if err := controller.Apply(context.Background(), allow); err != nil {
		t.Fatal(err)
	}
	if len(engine.withdrawn) != 1 {
		t.Fatalf("withdrawn=%#v", engine.withdrawn)
	}
	allow.Action = "remove"
	if err := controller.Apply(context.Background(), allow); err != nil {
		t.Fatal(err)
	}
	if len(engine.announced) != 2 {
		t.Fatalf("announced=%#v", engine.announced)
	}
}

func TestPolicyControllerNeverAnnouncesWhitelist(t *testing.T) {
	controller, _, engine := testPolicyController(t, false)
	if err := controller.Apply(context.Background(), dashboard.PolicyMutation{Action: "add", List: "whitelist", Prefix: "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(engine.announced) != 0 {
		t.Fatalf("announced=%#v", engine.announced)
	}
}

func TestPolicyControllerDryRunHasNoEffects(t *testing.T) {
	controller, store, engine := testPolicyController(t, true)
	err := controller.Apply(context.Background(), dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24"})
	if err == nil || store.Blocked(netip.MustParseAddr("203.0.113.1")) || len(engine.announced) != 0 {
		t.Fatalf("err=%v announced=%v", err, engine.announced)
	}
}

func TestPolicyControllerStartupReconcilesPersistedDeny(t *testing.T) {
	store := policystore.New()
	_, _ = store.Add(policystore.Blocklist, netip.MustParsePrefix("203.0.113.0/24"))
	engine := &recordingRouteEngine{}
	controller := newPolicyController(store, engine, false, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::1"), nil)
	if err := controller.Reconcile(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(engine.announced) != 1 {
		t.Fatalf("announced=%#v", engine.announced)
	}
}

func TestPolicyControllerDoesNotPersistWhenBGPFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	store, err := policystore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	engine := &recordingRouteEngine{announceErr: errors.New("BGP failed")}
	controller := newPolicyController(store, engine, false, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::1"), nil)
	err = controller.Apply(context.Background(), dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24"})
	if err == nil || store.Blocked(netip.MustParseAddr("203.0.113.1")) {
		t.Fatalf("err=%v", err)
	}
}

func TestPolicyControllerExpiresDenyAndWithdraws(t *testing.T) {
	store, err := policystore.Open(filepath.Join(t.TempDir(), "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &recordingRouteEngine{}
	controller := newPolicyController(store, engine, false, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::1"), nil)
	expiresAt := time.Now().Add(time.Minute)
	mutation := dashboard.PolicyMutation{Action: "add", List: "blocklist", Prefix: "203.0.113.0/24", ExpiresAt: &expiresAt}
	if err := controller.Apply(context.Background(), mutation); err != nil {
		t.Fatal(err)
	}
	if err := controller.applyExpired(expiresAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(engine.withdrawn) != 1 || store.Blocked(netip.MustParseAddr("203.0.113.1")) {
		t.Fatalf("withdrawn=%v expirations=%v", engine.withdrawn, store.Expirations())
	}
}
