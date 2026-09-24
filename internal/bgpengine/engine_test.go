package bgpengine

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func validConfig() Config {
	return Config{
		LocalASN:     64512,
		RouterID:     netip.MustParseAddr("192.0.2.1"),
		ListenPort:   1179,
		ListenRanges: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		AllowedASNs:  []uint32{64513, 64514},
		MaxSessions:  2,
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero local ASN", func(c *Config) { c.LocalASN = 0 }},
		{"non IPv4 router ID", func(c *Config) { c.RouterID = netip.MustParseAddr("2001:db8::1") }},
		{"invalid listen port", func(c *Config) { c.ListenPort = 65536 }},
		{"implicit default listen port", func(c *Config) { c.ListenPort = 0 }},
		{"no listen ranges", func(c *Config) { c.ListenRanges = nil }},
		{"zero allowed ASN", func(c *Config) { c.AllowedASNs = []uint32{0} }},
		{"zero max sessions", func(c *Config) { c.MaxSessions = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validConfig()
			tt.mutate(&config)
			if err := config.validate(); err == nil {
				t.Fatal("validate() = nil, want error")
			}
		})
	}
}

func TestValidateConfigAllowsStandardBGPPort(t *testing.T) {
	config := validConfig()
	config.ListenPort = 179
	if err := config.validate(); err != nil {
		t.Fatalf("validate() error = %v", err)
	}
}

func TestBuildPeerGroupLearnsASNAndRejectsRoutesByDefault(t *testing.T) {
	peerGroup := buildPeerGroup(validConfig())
	if peerGroup.GetConf().GetPeerAsn() != 0 {
		t.Fatalf("PeerAsn = %d, want 0", peerGroup.GetConf().GetPeerAsn())
	}
	if got := peerGroup.GetApplyPolicy().GetImportPolicy().GetDefaultAction(); got.String() != "ROUTE_ACTION_REJECT" {
		t.Fatalf("import default = %s, want ROUTE_ACTION_REJECT", got)
	}
	if got := peerGroup.GetApplyPolicy().GetExportPolicy().GetDefaultAction(); got.String() != "ROUTE_ACTION_REJECT" {
		t.Fatalf("export default = %s, want ROUTE_ACTION_REJECT", got)
	}
}

func TestSessionPolicyAllowsOnlyConfiguredASNAndCapacity(t *testing.T) {
	policy := newSessionPolicy(validConfig())
	if !policy.admitPeer("198.51.100.1", 64513) || !policy.admitPeer("198.51.100.2", 64514) {
		t.Fatal("configured ASNs should be admitted up to capacity")
	}
	if policy.admitPeer("198.51.100.3", 64513) {
		t.Fatal("session over capacity should be rejected")
	}
	if !policy.admitPeer("198.51.100.1", 64513) {
		t.Fatal("duplicate established event should remain admitted")
	}
	policy.releasePeer("198.51.100.1")
	if policy.admitPeer("198.51.100.3", 64515) {
		t.Fatal("unconfigured ASN should be rejected")
	}
	if got := policy.count(); got != 1 {
		t.Fatalf("count() = %d, want 1", got)
	}
}

func TestSessionPolicyAllowsAnyASNWhenAllowlistIsUnset(t *testing.T) {
	config := validConfig()
	config.AllowedASNs = nil
	policy := newSessionPolicy(config)
	if !policy.admitPeer("198.51.100.1", 64496) {
		t.Fatal("optional ASN allowlist rejected an otherwise allowed peer")
	}
}

func TestRoutePath(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		next   string
	}{
		{"IPv4", "203.0.113.0/24", "192.0.2.1"},
		{"IPv6", "2001:db8:1::/48", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := Route{
				Prefix:      netip.MustParsePrefix(tt.prefix),
				NextHop:     netip.MustParseAddr(tt.next),
				Communities: []uint32{0xffff029a},
			}
			path, err := routePath(route)
			if err != nil {
				t.Fatalf("routePath() error = %v", err)
			}
			if path.Nlri == nil || len(path.Attrs) == 0 {
				t.Fatalf("routePath() = %#v, want NLRI and attributes", path)
			}
		})
	}
}

func TestRoutePathRejectsAddressFamilyMismatch(t *testing.T) {
	_, err := routePath(Route{
		Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
		NextHop: netip.MustParseAddr("2001:db8::1"),
	})
	if err == nil {
		t.Fatal("routePath() = nil error, want address family mismatch")
	}
}

func TestStartStopSnapshotWithoutPrivilegedPort(t *testing.T) {
	config := validConfig()
	config.ListenPort = -1
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	if err := engine.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop(context.Background()) })

	status, err := engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.Running || status.LocalASN != config.LocalASN || status.RouterID != config.RouterID || status.ListenPort != -1 {
		t.Fatalf("Status() = %#v", status)
	}
	if len(status.ListenRanges) != 1 || status.ListenRanges[0] != config.ListenRanges[0] {
		t.Fatalf("ListenRanges = %v, want %v", status.ListenRanges, config.ListenRanges)
	}
	if status.Sessions != 0 || len(status.Peers) != 0 {
		t.Fatalf("peer status = sessions %d, peers %v", status.Sessions, status.Peers)
	}
}

func TestLoopbackDynamicNeighborAllowsAnyASNWhenAllowlistUnset(t *testing.T) {
	config := validConfig()
	config.ListenPort = 2179
	config.ListenRanges = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}
	config.AllowedASNs = nil
	config.MaxSessions = 1
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop(context.Background()) })

	remote := server.NewBgpServer()
	go remote.Serve()
	if err := remote.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn: 64513, RouterId: "2.2.2.2", ListenPort: -1,
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	if err := remote.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: config.LocalASN},
		Transport: &api.Transport{RemotePort: 2179},
		Timers: &api.Timers{Config: &api.TimersConfig{
			ConnectRetry:           1,
			IdleHoldTimeAfterReset: 1,
		}},
	}}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := engine.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if status.Sessions == 1 && len(status.Peers) == 1 && status.Peers[0].ASN == 64513 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	status, _ := engine.Status(context.Background())
	var remotePeers []string
	_ = remote.ListPeer(context.Background(), &api.ListPeerRequest{}, func(peer *api.Peer) {
		remotePeers = append(remotePeers, peer.String())
	})
	t.Fatalf("loopback dynamic neighbor did not establish: local=%#v remote=%#v", status, remotePeers)
}

func TestLoopbackDynamicNeighborRejectsDisallowedASN(t *testing.T) {
	config := validConfig()
	config.ListenPort = 3179
	config.ListenRanges = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}
	config.AllowedASNs = []uint32{64513}
	config.MaxSessions = 1
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop(context.Background()) })

	remote := server.NewBgpServer()
	go remote.Serve()
	if err := remote.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn: 64514, RouterId: "3.3.3.3", ListenPort: -1,
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	established := make(chan struct{}, 1)
	reset := make(chan struct{}, 1)
	var wasEstablished atomic.Bool
	if err := remote.WatchEvent(context.Background(), server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(event *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if event.Peer.State.SessionState == bgp.BGP_FSM_ESTABLISHED {
				wasEstablished.Store(true)
				select {
				case established <- struct{}{}:
				default:
				}
			} else if wasEstablished.Load() {
				select {
				case reset <- struct{}{}:
				default:
				}
			}
		},
	}, server.WatchPeer()); err != nil {
		t.Fatal(err)
	}
	if err := remote.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: config.LocalASN},
		Transport: &api.Transport{RemotePort: 3179},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-established:
	case <-time.After(5 * time.Second):
		t.Fatal("remote never established, rejection path was not exercised")
	}
	select {
	case <-reset:
	case <-time.After(5 * time.Second):
		t.Fatal("disallowed ASN was not reset")
	}
	if err := remote.DisablePeer(context.Background(), &api.DisablePeerRequest{Address: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := engine.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if status.Sessions == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("disallowed ASN remained established: %#v", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLoopbackDynamicNeighborEnforcesMaxSessions(t *testing.T) {
	config := validConfig()
	config.ListenPort = 4179
	config.ListenRanges = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}
	config.AllowedASNs = []uint32{64513}
	config.MaxSessions = 1
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop(context.Background()) })

	startRemote := func(routerID, source string) (*server.BgpServer, <-chan struct{}, <-chan struct{}) {
		remote := server.NewBgpServer()
		go remote.Serve()
		if err := remote.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
			Asn: 64513, RouterId: routerID, ListenPort: -1,
		}}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = remote.StopBgp(context.Background(), &api.StopBgpRequest{}) })
		established := make(chan struct{}, 1)
		reset := make(chan struct{}, 1)
		var wasEstablished atomic.Bool
		if err := remote.WatchEvent(context.Background(), server.WatchEventMessageCallbacks{
			OnPeerUpdate: func(event *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
				if event.Peer.State.SessionState == bgp.BGP_FSM_ESTABLISHED {
					wasEstablished.Store(true)
					select {
					case established <- struct{}{}:
					default:
					}
				} else if wasEstablished.Load() {
					select {
					case reset <- struct{}{}:
					default:
					}
				}
			},
		}, server.WatchPeer()); err != nil {
			t.Fatal(err)
		}
		if err := remote.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: config.LocalASN},
			Transport: &api.Transport{LocalAddress: source, RemotePort: 4179},
			Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		}}); err != nil {
			t.Fatal(err)
		}
		return remote, established, reset
	}

	first, firstEstablished, _ := startRemote("4.4.4.4", "127.0.0.2")
	select {
	case <-firstEstablished:
	case <-time.After(5 * time.Second):
		t.Fatal("first session did not establish")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, err := engine.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if status.Sessions == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("first session did not establish: %#v", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	second, secondEstablished, secondReset := startRemote("5.5.5.5", "127.0.0.3")
	t.Cleanup(func() {
		_ = first.DisablePeer(context.Background(), &api.DisablePeerRequest{Address: "127.0.0.1"})
		_ = second.DisablePeer(context.Background(), &api.DisablePeerRequest{Address: "127.0.0.1"})
	})
	select {
	case <-secondEstablished:
	case <-time.After(5 * time.Second):
		t.Fatal("second session did not establish, limit path was not exercised")
	}
	select {
	case <-secondReset:
	case <-time.After(5 * time.Second):
		t.Fatal("second session was not reset at capacity")
	}
	if err := second.DisablePeer(context.Background(), &api.DisablePeerRequest{Address: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, err := engine.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if status.Sessions > 1 {
			t.Fatalf("session limit exceeded: %#v", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
