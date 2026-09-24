// Package policystore manages CIDR blocklists and whitelists.
package policystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// List identifies a policy list.
type List string

const (
	Blocklist List = "blocklist"
	Whitelist List = "whitelist"
)

// Operation identifies an audited mutation.
type Operation string

const (
	Add    Operation = "add"
	Remove Operation = "remove"
)

// AuditEvent records an effective policy mutation.
type AuditEvent struct {
	Time      time.Time    `json:"time"`
	Operation Operation    `json:"operation"`
	List      List         `json:"list"`
	Prefix    netip.Prefix `json:"prefix"`
}

// Store is safe for concurrent use.
type Store struct {
	mu          sync.RWMutex
	path        string
	blocklist   []netip.Prefix
	whitelist   []netip.Prefix
	expirations map[netip.Prefix]time.Time
	audit       []AuditEvent
}

type diskState struct {
	Blocklist   []netip.Prefix       `json:"blocklist"`
	Whitelist   []netip.Prefix       `json:"whitelist"`
	Audit       []AuditEvent         `json:"audit,omitempty"`
	Expirations map[string]time.Time `json:"expirations,omitempty"`

	expirationsByPrefix map[netip.Prefix]time.Time
}

// New returns an in-memory policy store.
func New() *Store { return &Store{} }

// Open loads a file-backed policy store. A missing file is created on the
// first effective mutation.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("policystore: empty path")
	}

	s := &Store{path: filepath.Clean(path)}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policystore: read: %w", err)
	}

	var state diskState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return nil, fmt.Errorf("policystore: decode: %w", err)
	}
	if err := ensureJSONEnd(dec); err != nil {
		return nil, fmt.Errorf("policystore: decode: %w", err)
	}
	if err := validateState(&state); err != nil {
		return nil, err
	}

	s.blocklist = state.Blocklist
	s.whitelist = state.Whitelist
	s.expirations = state.expirationsByPrefix
	s.audit = state.Audit
	return s, nil
}

// Add inserts a normalized CIDR. It returns false without auditing or writing
// when the CIDR is already present.
func (s *Store) Add(list List, prefix netip.Prefix) (bool, error) {
	return s.mutate(Add, list, prefix)
}

// Remove deletes a normalized CIDR. It returns false without auditing or
// writing when the CIDR is absent.
func (s *Store) Remove(list List, prefix netip.Prefix) (bool, error) {
	return s.mutate(Remove, list, prefix)
}

// AddUntil inserts a blocklist CIDR and records when the block expires.
// Setting an expiry on an existing prefix counts as a change and is audited.
func (s *Store) AddUntil(list List, prefix netip.Prefix, expiry time.Time) (bool, error) {
	if list != Blocklist {
		return false, fmt.Errorf("policystore: expiry requires blocklist, got %q", list)
	}
	if !prefix.IsValid() {
		return false, errors.New("policystore: invalid prefix")
	}
	if expiry.IsZero() {
		return false, errors.New("policystore: zero expiry")
	}
	prefix = prefix.Masked()
	expiry = expiry.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	blocklist := slices.Clone(s.blocklist)
	whitelist := slices.Clone(s.whitelist)
	expirations := maps.Clone(s.expirations)
	if expirations == nil {
		expirations = make(map[netip.Prefix]time.Time)
	}

	index := slices.Index(blocklist, prefix)
	if index < 0 {
		blocklist = append(blocklist, prefix)
		expirations[prefix] = expiry
	} else if existing, ok := expirations[prefix]; ok && existing.Equal(expiry) {
		return false, nil
	} else {
		expirations[prefix] = expiry
	}

	audit := append(slices.Clone(s.audit), AuditEvent{
		Time:      time.Now().UTC(),
		Operation: Add,
		List:      list,
		Prefix:    prefix,
	})
	if s.path != "" {
		state := diskState{Blocklist: blocklist, Whitelist: whitelist, Audit: audit, Expirations: prefixToTimeMap(expirations)}
		if err := persist(s.path, state); err != nil {
			return false, err
		}
	}

	s.blocklist = blocklist
	s.whitelist = whitelist
	s.expirations = expirations
	s.audit = audit
	return true, nil
}

func (s *Store) mutate(operation Operation, list List, prefix netip.Prefix) (bool, error) {
	if !validList(list) {
		return false, fmt.Errorf("policystore: invalid list %q", list)
	}
	if !prefix.IsValid() {
		return false, errors.New("policystore: invalid prefix")
	}
	prefix = prefix.Masked()

	s.mu.Lock()
	defer s.mu.Unlock()

	blocklist := slices.Clone(s.blocklist)
	whitelist := slices.Clone(s.whitelist)
	expirations := maps.Clone(s.expirations)
	var target *[]netip.Prefix
	if list == Blocklist {
		target = &blocklist
	} else {
		target = &whitelist
	}

	index := slices.Index(*target, prefix)
	switch operation {
	case Add:
		if index >= 0 {
			return false, nil
		}
		*target = append(*target, prefix)
	case Remove:
		if index < 0 {
			return false, nil
		}
		*target = slices.Delete(*target, index, index+1)
		if list == Blocklist {
			delete(expirations, prefix)
		}
	default:
		return false, fmt.Errorf("policystore: invalid operation %q", operation)
	}

	audit := append(slices.Clone(s.audit), AuditEvent{
		Time:      time.Now().UTC(),
		Operation: operation,
		List:      list,
		Prefix:    prefix,
	})
	if s.path != "" {
		state := diskState{Blocklist: blocklist, Whitelist: whitelist, Audit: audit, Expirations: prefixToTimeMap(expirations)}
		if err := persist(s.path, state); err != nil {
			return false, err
		}
	}

	s.blocklist = blocklist
	s.whitelist = whitelist
	s.expirations = expirations
	s.audit = audit
	return true, nil
}

// Blocked reports the effective policy for an address. Any containing
// whitelist CIDR takes precedence over every containing blocklist CIDR.
func (s *Store) Blocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if contains(s.whitelist, addr) {
		return false
	}
	return contains(s.blocklist, addr)
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Prefixes returns a copy of one list.
func (s *Store) Prefixes(list List) ([]netip.Prefix, error) {
	if !validList(list) {
		return nil, fmt.Errorf("policystore: invalid list %q", list)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if list == Blocklist {
		return slices.Clone(s.blocklist), nil
	}
	return slices.Clone(s.whitelist), nil
}

// Expiry reports when a blocklist prefix expires.
func (s *Store) Expiry(prefix netip.Prefix) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiry, ok := s.expirations[prefix.Masked()]
	return expiry, ok
}

// Expirations returns a copy of the expiry map.
func (s *Store) Expirations() map[netip.Prefix]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.expirations)
}

// Audit returns a copy of the audit log.
func (s *Store) Audit() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.audit)
}

func validList(list List) bool { return list == Blocklist || list == Whitelist }

func validateState(state *diskState) error {
	var err error
	state.Blocklist, err = validatePrefixes(Blocklist, state.Blocklist)
	if err != nil {
		return err
	}
	state.Whitelist, err = validatePrefixes(Whitelist, state.Whitelist)
	if err != nil {
		return err
	}
	state.expirationsByPrefix, err = validateExpirations(state.Blocklist, state.Expirations)
	if err != nil {
		return err
	}
	for i, event := range state.Audit {
		if event.Time.IsZero() || !validList(event.List) ||
			(event.Operation != Add && event.Operation != Remove) || !event.Prefix.IsValid() {
			return fmt.Errorf("policystore: invalid audit event %d", i)
		}
		state.Audit[i].Prefix = event.Prefix.Masked()
	}
	return nil
}

func validatePrefixes(list List, prefixes []netip.Prefix) ([]netip.Prefix, error) {
	validated := make([]netip.Prefix, 0, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("policystore: invalid %s prefix %d", list, i)
		}
		prefix = prefix.Masked()
		if slices.Contains(validated, prefix) {
			return nil, fmt.Errorf("policystore: duplicate %s prefix %q", list, prefix)
		}
		validated = append(validated, prefix)
	}
	return validated, nil
}

func validateExpirations(blocklist []netip.Prefix, expirations map[string]time.Time) (map[netip.Prefix]time.Time, error) {
	if len(expirations) == 0 {
		return nil, nil
	}
	validated := make(map[netip.Prefix]time.Time, len(expirations))
	for key, expiry := range expirations {
		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			return nil, fmt.Errorf("policystore: invalid expiration key %q", key)
		}
		prefix = prefix.Masked()
		if expiry.IsZero() {
			return nil, fmt.Errorf("policystore: zero expiry for %q", key)
		}
		if _, dup := validated[prefix]; dup {
			return nil, fmt.Errorf("policystore: duplicate expiration key %q", prefix)
		}
		if !slices.Contains(blocklist, prefix) {
			return nil, fmt.Errorf("policystore: orphan expiration %q", prefix)
		}
		validated[prefix] = expiry.UTC()
	}
	return validated, nil
}

func prefixToTimeMap(expirations map[netip.Prefix]time.Time) map[string]time.Time {
	if len(expirations) == 0 {
		return nil
	}
	out := make(map[string]time.Time, len(expirations))
	for prefix, expiry := range expirations {
		out[prefix.String()] = expiry
	}
	return out
}

func ensureJSONEnd(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func persist(path string, state diskState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("policystore: encode: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("policystore: create temporary file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)

	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("policystore: secure temporary file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("policystore: write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("policystore: sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("policystore: close temporary file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("policystore: replace file: %w", err)
	}

	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("policystore: open parent directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("policystore: sync parent directory: %w", err)
	}
	return nil
}
