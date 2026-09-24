package bgpengine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

type Config struct {
	LocalASN        uint32
	RouterID        netip.Addr
	ListenAddresses []string
	ListenPort      int32
	ListenRanges    []netip.Prefix
	AllowedASNs     []uint32
	MaxSessions     int
}

// BlackholeCommunity is the RFC 7999 well-known community
// NO_EXPORT (0xFFFFFF01) is not used; this is BLACKHOLE (65535:666).
const BlackholeCommunity uint32 = 0xffff029a

const (
	rtbhCommunitySetName = "rtbh-blackhole-community"
	rtbhExportPolicyName = "rtbh-export-only-blackhole"
)

type Status struct {
	Running      bool
	LocalASN     uint32
	RouterID     netip.Addr
	ListenPort   int32
	ListenRanges []netip.Prefix
	Sessions     int
	Peers        []Peer
}

type Peer struct {
	Address netip.Addr
	ASN     uint32
	State   string
}

type Route struct {
	Prefix      netip.Prefix
	NextHop     netip.Addr
	Communities []uint32
}

type sessionPolicy struct {
	mu      sync.Mutex
	allowed map[uint32]struct{}
	max     int
	peers   map[string]uint32
}

func newSessionPolicy(c Config) *sessionPolicy {
	allowed := make(map[uint32]struct{}, len(c.AllowedASNs))
	for _, asn := range c.AllowedASNs {
		allowed[asn] = struct{}{}
	}
	return &sessionPolicy{allowed: allowed, max: c.MaxSessions, peers: make(map[string]uint32)}
}
func (p *sessionPolicy) admitPeer(address string, asn uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if current, ok := p.peers[address]; ok {
		return current == asn
	}
	if len(p.allowed) > 0 {
		if _, ok := p.allowed[asn]; !ok {
			return false
		}
	}
	if len(p.peers) >= p.max {
		return false
	}
	p.peers[address] = asn
	return true
}
func (p *sessionPolicy) releasePeer(address string) {
	p.mu.Lock()
	delete(p.peers, address)
	p.mu.Unlock()
}
func (p *sessionPolicy) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.peers) }

func (c Config) validate() error {
	if c.LocalASN == 0 {
		return errors.New("local ASN must be non-zero")
	}
	if !c.RouterID.IsValid() || !c.RouterID.Is4() {
		return errors.New("router ID must be a valid IPv4 address")
	}
	if c.ListenPort < -1 || c.ListenPort == 0 || c.ListenPort > 65535 {
		return errors.New("listen port out of range")
	}
	if len(c.ListenRanges) == 0 {
		return errors.New("at least one listen range is required")
	}
	for _, prefix := range c.ListenRanges {
		if !prefix.IsValid() {
			return errors.New("listen range is invalid")
		}
	}
	if c.MaxSessions < 1 {
		return errors.New("max sessions must be positive")
	}
	for _, asn := range c.AllowedASNs {
		if asn == 0 {
			return errors.New("allowed ASN must be non-zero")
		}
	}
	return nil
}

func buildPeerGroup(c Config) *api.PeerGroup {
	_, policy, assignment := buildRTBHExportPolicy()
	assignment.Policies = []*api.Policy{policy}
	return &api.PeerGroup{
		Conf:      &api.PeerGroupConf{PeerGroupName: "rtbh-dynamic", PeerAsn: 0},
		Transport: &api.Transport{PassiveMode: true},
		ApplyPolicy: &api.ApplyPolicy{
			ImportPolicy: &api.PolicyAssignment{DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT},
			ExportPolicy: assignment,
		},
	}
}

func buildRTBHExportPolicy() (*api.DefinedSet, *api.Policy, *api.PolicyAssignment) {
	set := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
		Name:        rtbhCommunitySetName,
		List:        []string{"65535:666"},
	}
	policy := &api.Policy{
		Name: rtbhExportPolicyName,
		Statements: []*api.Statement{{
			Name: "accept-rfc7999-blackhole",
			Conditions: &api.Conditions{CommunitySet: &api.MatchSet{
				Type: api.MatchSet_TYPE_ANY,
				Name: rtbhCommunitySetName,
			}},
			Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}
	assignment := &api.PolicyAssignment{
		Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
		Policies:      []*api.Policy{policy},
		DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
	}
	return set, policy, assignment
}

func routePath(route Route) (*apiutil.Path, error) {
	if !route.Prefix.IsValid() || !route.NextHop.IsValid() {
		return nil, errors.New("route prefix and next hop are required")
	}
	if route.Prefix.Addr().Is4() != route.NextHop.Is4() {
		return nil, errors.New("route prefix and next hop address families differ")
	}
	nlri, err := bgp.NewIPAddrPrefix(route.Prefix)
	if err != nil {
		return nil, err
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)}
	if route.Prefix.Addr().Is4() {
		nextHop, err := bgp.NewPathAttributeNextHop(route.NextHop)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nextHop)
	} else {
		nextHop, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, route.NextHop)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nextHop)
	}
	if len(route.Communities) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities(route.Communities))
	}
	family := bgp.RF_IPv4_UC
	if route.Prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
	}
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs}, nil
}

type Engine struct {
	config      Config
	bgp         *server.BgpServer
	policy      *sessionPolicy
	mu          sync.RWMutex
	running     bool
	watchCancel context.CancelFunc
}

func New(config Config) (*Engine, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Engine{config: config, bgp: server.NewBgpServer(), policy: newSessionPolicy(config)}, nil
}

func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return errors.New("engine already running")
	}
	go e.bgp.Serve()
	started := false
	defer func() {
		if !e.running && started {
			_ = e.bgp.StopBgp(context.Background(), &api.StopBgpRequest{})
		}
	}()
	if err := e.bgp.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: e.config.LocalASN, RouterId: e.config.RouterID.String(), ListenAddresses: append([]string(nil), e.config.ListenAddresses...), ListenPort: e.config.ListenPort}}); err != nil {
		return fmt.Errorf("start GoBGP: %w", err)
	}
	started = true
	set, policy, _ := buildRTBHExportPolicy()
	if err := e.bgp.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: set}); err != nil {
		return fmt.Errorf("add RTBH community set: %w", err)
	}
	if err := e.bgp.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}); err != nil {
		return fmt.Errorf("add RTBH export policy: %w", err)
	}
	if err := e.bgp.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: buildPeerGroup(e.config)}); err != nil {
		return fmt.Errorf("add peer group: %w", err)
	}
	for _, prefix := range e.config.ListenRanges {
		if err := e.bgp.AddDynamicNeighbor(ctx, &api.AddDynamicNeighborRequest{DynamicNeighbor: &api.DynamicNeighbor{Prefix: prefix.String(), PeerGroup: "rtbh-dynamic"}}); err != nil {
			return fmt.Errorf("add dynamic neighbor %s: %w", prefix, err)
		}
	}
	watchCtx, cancel := context.WithCancel(context.Background())
	e.watchCancel = cancel
	if err := e.bgp.WatchEvent(watchCtx, server.WatchEventMessageCallbacks{OnPeerUpdate: e.onPeerUpdate}, server.WatchPeer()); err != nil {
		cancel()
		return fmt.Errorf("watch peers: %w", err)
	}
	e.running = true
	return nil
}
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return nil
	}
	e.running = false
	if e.watchCancel != nil {
		e.watchCancel()
		e.watchCancel = nil
	}
	return e.bgp.StopBgp(ctx, &api.StopBgpRequest{})
}
func (e *Engine) Status(ctx context.Context) (Status, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	status := Status{Running: e.running, LocalASN: e.config.LocalASN, RouterID: e.config.RouterID, ListenPort: e.config.ListenPort, ListenRanges: append([]netip.Prefix(nil), e.config.ListenRanges...)}
	if !e.running {
		return status, nil
	}
	err := e.bgp.ListPeer(ctx, &api.ListPeerRequest{}, func(peer *api.Peer) {
		state := peer.GetState()
		address, _ := netip.ParseAddr(state.GetNeighborAddress())
		status.Peers = append(status.Peers, Peer{Address: address, ASN: state.GetPeerAsn(), State: state.GetSessionState().String()})
		if state.GetSessionState() == api.PeerState_SESSION_STATE_ESTABLISHED {
			status.Sessions++
		}
	})
	return status, err
}

func (e *Engine) onPeerUpdate(event *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
	peer := event.Peer
	address := peer.State.NeighborAddress.String()
	if peer.State.SessionState != bgp.BGP_FSM_ESTABLISHED {
		e.policy.releasePeer(address)
		return
	}
	if e.policy.admitPeer(address, peer.State.PeerASN) {
		return
	}
	// ponytail: GoBGP reveals a dynamic peer's ASN at ESTABLISHED. Default-reject
	// policies contain it until reset; use a pre-OPEN hook if GoBGP exposes one.
	_ = e.bgp.ResetPeer(context.Background(), &api.ResetPeerRequest{Address: address, Communication: "remote ASN or session limit rejected"})
}
func (e *Engine) Announce(route Route) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.running {
		return errors.New("engine is not running")
	}
	path, err := routePath(route)
	if err != nil {
		return err
	}
	_, err = e.bgp.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	return err
}
func (e *Engine) Withdraw(route Route) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.running {
		return errors.New("engine is not running")
	}
	path, err := routePath(route)
	if err != nil {
		return err
	}
	path.Withdrawal = true
	return e.bgp.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{path}})
}
