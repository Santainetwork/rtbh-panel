package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/arcelo/rtbh-panel/internal/bgpengine"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/policystore"
)

type policyController struct {
	mu        sync.Mutex
	store     *policystore.Store
	engine    Engine
	dryRun    bool
	nextHopV4 netip.Addr
	nextHopV6 netip.Addr
	publish   func(dashboard.PolicyMutation)
	active    map[netip.Prefix]bgpengine.Route
	wake      chan struct{}
}

func newPolicyController(store *policystore.Store, engine Engine, dryRun bool, nextHopV4, nextHopV6 netip.Addr, publish func(dashboard.PolicyMutation)) *policyController {
	return &policyController{store: store, engine: engine, dryRun: dryRun, nextHopV4: nextHopV4, nextHopV6: nextHopV6, publish: publish, active: make(map[netip.Prefix]bgpengine.Route), wake: make(chan struct{}, 1)}
}

func (c *policyController) Reconcile(now time.Time) error {
	if c.dryRun {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	desired, err := c.routes(now)
	if err != nil {
		return err
	}
	return c.applyDelta(desired)
}

func (c *policyController) Apply(_ context.Context, mutation dashboard.PolicyMutation) error {
	if c.dryRun {
		return errors.New("runtime: apply rejected while dry-run is enabled")
	}
	prefix, err := netip.ParsePrefix(mutation.Prefix)
	if err != nil || prefix != prefix.Masked() {
		return errors.New("runtime: canonical policy prefix required")
	}
	list, err := policyList(mutation.List)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	before, err := c.routes(time.Now())
	if err != nil {
		return err
	}
	blocklist, _ := c.store.Prefixes(policystore.Blocklist)
	whitelist, _ := c.store.Prefixes(policystore.Whitelist)
	proposedBlocklist := slices.Clone(blocklist)
	proposedWhitelist := slices.Clone(whitelist)
	target := &proposedBlocklist
	if list == policystore.Whitelist {
		target = &proposedWhitelist
	}
	index := slices.Index(*target, prefix)
	changed := false
	switch mutation.Action {
	case "add", "replace":
		if index < 0 {
			*target = append(*target, prefix)
			changed = true
		}
	case "remove", "delete":
		if index >= 0 {
			*target = slices.Delete(*target, index, index+1)
			changed = true
		}
	default:
		return fmt.Errorf("runtime: unsupported action %q", mutation.Action)
	}
	if !changed {
		return nil
	}
	proposed := effectiveRoutes(proposedBlocklist, proposedWhitelist, c.store.Expirations(), time.Now(), c.nextHopV4, c.nextHopV6)
	if err := c.applyDelta(proposed); err != nil {
		return err
	}
	if err := mutateStore(c.store, mutation.Action, mutation.List, mutation.Prefix); err != nil {
		_ = c.applyDelta(before)
		return err
	}
	if c.publish != nil {
		c.publish(mutation)
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func (c *policyController) routes(now time.Time) (map[netip.Prefix]bgpengine.Route, error) {
	blocklist, err := c.store.Prefixes(policystore.Blocklist)
	if err != nil {
		return nil, err
	}
	whitelist, err := c.store.Prefixes(policystore.Whitelist)
	if err != nil {
		return nil, err
	}
	return effectiveRoutes(blocklist, whitelist, c.store.Expirations(), now, c.nextHopV4, c.nextHopV6), nil
}

func effectiveRoutes(blocklist, whitelist []netip.Prefix, expirations map[netip.Prefix]time.Time, now time.Time, nextHopV4, nextHopV6 netip.Addr) map[netip.Prefix]bgpengine.Route {
	routes := make(map[netip.Prefix]bgpengine.Route)
	for _, prefix := range blocklist {
		if expiry, ok := expirations[prefix]; ok && !expiry.After(now) {
			continue
		}
		suppressed := false
		for _, allowed := range whitelist {
			if prefix.Contains(allowed.Addr()) || allowed.Contains(prefix.Addr()) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}
		nextHop := nextHopV4
		if prefix.Addr().Is6() {
			nextHop = nextHopV6
		}
		routes[prefix] = bgpengine.Route{Prefix: prefix, NextHop: nextHop, Communities: []uint32{bgpengine.BlackholeCommunity}}
	}
	return routes
}

func (c *policyController) applyDelta(desired map[netip.Prefix]bgpengine.Route) error {
	var withdrawn []bgpengine.Route
	for prefix, route := range c.active {
		if _, ok := desired[prefix]; ok {
			continue
		}
		if err := c.engine.Withdraw(route); err != nil {
			return fmt.Errorf("runtime: withdraw %s: %w", prefix, err)
		}
		withdrawn = append(withdrawn, route)
	}
	var announced []bgpengine.Route
	for prefix, route := range desired {
		if _, ok := c.active[prefix]; ok {
			continue
		}
		if err := c.engine.Announce(route); err != nil {
			for _, added := range announced {
				_ = c.engine.Withdraw(added)
			}
			for _, removed := range withdrawn {
				_ = c.engine.Announce(removed)
			}
			return fmt.Errorf("runtime: announce %s: %w", prefix, err)
		}
		announced = append(announced, route)
	}
	c.active = desired
	return nil
}

func policyList(name string) (policystore.List, error) {
	switch name {
	case "blocklist":
		return policystore.Blocklist, nil
	case "whitelist":
		return policystore.Whitelist, nil
	default:
		return "", fmt.Errorf("runtime: unsupported list %q", name)
	}
}
