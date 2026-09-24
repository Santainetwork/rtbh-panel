package runtime

import (
	"context"
	"net/netip"
	"testing"

	"github.com/arcelo/rtbh-panel/internal/bgpengine"
)

type stubEngine struct {
	status bgpengine.Status
}

func (*stubEngine) Start(context.Context) error    { return nil }
func (*stubEngine) Stop(context.Context) error     { return nil }
func (*stubEngine) Announce(bgpengine.Route) error { return nil }
func (*stubEngine) Withdraw(bgpengine.Route) error { return nil }
func (e *stubEngine) Status(context.Context) (bgpengine.Status, error) {
	return e.status, nil
}

var _ Engine = (*stubEngine)(nil)

func TestDashboardBackendUsesEngineInterface(t *testing.T) {
	engine := &stubEngine{status: bgpengine.Status{Peers: []bgpengine.Peer{{
		Address: netip.MustParseAddr("192.0.2.10"),
		ASN:     64512,
		State:   "ESTABLISHED",
	}}}}
	backend := &dashboardBackend{engine: engine}

	peers, err := backend.EstablishedPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Address != "192.0.2.10" || peers[0].ASN != 64512 {
		t.Fatalf("peers = %#v", peers)
	}
}
