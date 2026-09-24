package bgpengine

import (
	"context"
	"net/netip"
	"testing"
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
