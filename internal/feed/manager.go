package feed

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FeedSource defines an external threat intelligence or policy feed.
type FeedSource struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	List          string        `json:"list"` // "blocklist" or "whitelist"
	URL           string        `json:"url"`
	Interval      time.Duration `json:"interval"` // e.g. 15m, 1h, 6h, 24h
	Enabled       bool          `json:"enabled"`
	LastSync      time.Time     `json:"last_sync,omitempty"`
	PrefixCount   int           `json:"prefix_count"`
	LastError     string        `json:"last_error,omitempty"`
	ExpandSubnets bool          `json:"expand_subnets"`
	Prefixes      []string      `json:"prefixes,omitempty"`
}

// SyncHandler is invoked whenever a feed's prefixes are synchronized.
// It receives added prefixes and removed prefixes for reconciliation.
type SyncHandler func(ctx context.Context, source FeedSource, toAdd []string, toRemove []string) error

// DeleteHandler is invoked when a feed is deleted, providing its prefixes to clean up.
type DeleteHandler func(ctx context.Context, source FeedSource, prefixes []string) error

// Manager manages and schedules external feed downloads.
type Manager struct {
	mu       sync.RWMutex
	path     string
	sources  map[string]FeedSource
	onSync   SyncHandler
	onDelete DeleteHandler
	wakeCh   chan struct{}
}

// NewManager returns an in-memory feed manager.
func NewManager(onSync SyncHandler, onDelete DeleteHandler) *Manager {
	return &Manager{
		sources:  make(map[string]FeedSource),
		onSync:   onSync,
		onDelete: onDelete,
		wakeCh:   make(chan struct{}, 1),
	}
}

// OpenManager opens or creates a file-backed feed manager.
func OpenManager(path string, onSync SyncHandler, onDelete DeleteHandler) (*Manager, error) {
	m := NewManager(onSync, onDelete)
	if path == "" {
		return m, nil
	}
	m.path = filepath.Clean(path)
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feed manager: read %s: %w", m.path, err)
	}

	var list []FeedSource
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("feed manager: decode %s: %w", m.path, err)
	}
	for _, s := range list {
		m.sources[s.ID] = s
	}
	return m, nil
}

func (m *Manager) persistLocked() error {
	if m.path == "" {
		return nil
	}
	var list []FeedSource
	for _, s := range m.sources {
		list = append(list, s)
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(list); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// List returns all configured feeds.
func (m *Manager) List() []FeedSource {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]FeedSource, 0, len(m.sources))
	for _, s := range m.sources {
		res = append(res, s)
	}
	return res
}

// Get returns one feed by ID.
func (m *Manager) Get(id string) (FeedSource, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sources[id]
	return s, ok
}

// PrefixSource finds which feed owns a given prefix, returning (feedName, true) or ("", false).
func (m *Manager) PrefixSource(prefix string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sources {
		for _, p := range s.Prefixes {
			if p == prefix {
				return s.Name, true
			}
		}
	}
	return "", false
}

// Save adds or updates a feed source.
func (m *Manager) Save(s FeedSource) (FeedSource, error) {
	if s.Name == "" {
		return s, errors.New("feed name is required")
	}
	if s.URL == "" {
		return s, errors.New("feed URL is required")
	}
	if s.List != "blocklist" && s.List != "whitelist" {
		s.List = "blocklist"
	}
	if s.Interval < 0 {
		s.Interval = time.Hour
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s.ID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		s.ID = "feed-" + hex.EncodeToString(b)
	} else if existing, ok := m.sources[s.ID]; ok {
		s.Prefixes = existing.Prefixes
		s.PrefixCount = existing.PrefixCount
		s.LastSync = existing.LastSync
	}

	m.sources[s.ID] = s
	if err := m.persistLocked(); err != nil {
		return s, err
	}

	select {
	case m.wakeCh <- struct{}{}:
	default:
	}
	return s, nil
}

// Delete removes a feed source and invokes onDelete to cascade remove its prefixes.
func (m *Manager) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	source, ok := m.sources[id]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	delete(m.sources, id)
	_ = m.persistLocked()
	m.mu.Unlock()

	if m.onDelete != nil && len(source.Prefixes) > 0 {
		return m.onDelete(ctx, source, source.Prefixes)
	}
	return nil
}

// SyncFeed downloads and applies a specific feed, computing added and removed diffs.
func (m *Manager) SyncFeed(ctx context.Context, id string) (int, error) {
	m.mu.RLock()
	source, ok := m.sources[id]
	m.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("feed %s not found", id)
	}

	fetchedPrefixes, err := Fetch(ctx, source.URL, source.ExpandSubnets)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Re-check under lock
	source = m.sources[id]
	source.LastSync = time.Now().UTC()
	if err != nil {
		source.LastError = err.Error()
		m.sources[id] = source
		_ = m.persistLocked()
		return 0, err
	}

	newPrefixMap := make(map[string]struct{}, len(fetchedPrefixes))
	var newPrefixes []string
	for _, p := range fetchedPrefixes {
		str := p.String()
		if _, exists := newPrefixMap[str]; !exists {
			newPrefixMap[str] = struct{}{}
			newPrefixes = append(newPrefixes, str)
		}
	}

	oldPrefixMap := make(map[string]struct{}, len(source.Prefixes))
	for _, p := range source.Prefixes {
		oldPrefixMap[p] = struct{}{}
	}

	var toAdd []string
	for p := range newPrefixMap {
		if _, exists := oldPrefixMap[p]; !exists {
			toAdd = append(toAdd, p)
		}
	}

	var toRemove []string
	for p := range oldPrefixMap {
		if _, exists := newPrefixMap[p]; !exists {
			toRemove = append(toRemove, p)
		}
	}

	source.LastError = ""
	source.PrefixCount = len(newPrefixes)
	source.Prefixes = newPrefixes
	m.sources[id] = source
	_ = m.persistLocked()

	if m.onSync != nil {
		if err := m.onSync(ctx, source, toAdd, toRemove); err != nil {
			source.LastError = err.Error()
			m.sources[id] = source
			_ = m.persistLocked()
			return len(newPrefixes), err
		}
	}
	return len(newPrefixes), nil
}

// Run schedules periodic synchronization of enabled feeds.
func (m *Manager) Run(ctx context.Context) error {
	for {
		m.mu.RLock()
		var nextRun time.Duration = time.Hour
		now := time.Now()
		var due []string

		for id, s := range m.sources {
			if !s.Enabled || s.Interval <= 0 {
				continue
			}
			elapsed := now.Sub(s.LastSync)
			if s.LastSync.IsZero() || elapsed >= s.Interval {
				due = append(due, id)
			} else {
				rem := s.Interval - elapsed
				if rem < nextRun {
					nextRun = rem
				}
			}
		}
		m.mu.RUnlock()

		for _, id := range due {
			_, _ = m.SyncFeed(ctx, id)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-m.wakeCh:
			// Woken up by new feed or update, recheck
		case <-time.After(nextRun):
		}
	}
}
