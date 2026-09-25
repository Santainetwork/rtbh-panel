// Package feed fetches and parses IP/CIDR text lists from URLs or local files.
package feed

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// ParseList parses a line-separated text list of IPs or CIDRs.
// Lines beginning with '#' or '//' and blank lines are ignored.
// Bare IPs (e.g. 1.2.3.4 or 2001:db8::1) are normalized to /32 or /128.
// If expandSlash24 is true, any IPv4 /24 prefix is expanded into 256 individual /32 host prefixes.
func ParseList(r io.Reader, expandSlash24 bool) ([]netip.Prefix, error) {
	scanner := bufio.NewScanner(r)
	var prefixes []netip.Prefix
	seen := make(map[netip.Prefix]struct{})

	addPrefix := func(p netip.Prefix) {
		p = p.Masked()
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			prefixes = append(prefixes, p)
		}
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip trailing inline comments if any
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		var prefix netip.Prefix
		if !strings.Contains(line, "/") {
			addr, err := netip.ParseAddr(line)
			if err != nil {
				return nil, fmt.Errorf("feed: line %d: invalid IP address %q: %w", lineNum, line, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		} else {
			var err error
			prefix, err = netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("feed: line %d: invalid CIDR %q: %w", lineNum, line, err)
			}
		}

		prefix = prefix.Masked()
		if expandSlash24 && prefix.Addr().Is4() && prefix.Bits() >= 16 && prefix.Bits() < 32 {
			for _, p32 := range ExpandIPv4ToSlash32(prefix) {
				addPrefix(p32)
			}
		} else {
			addPrefix(prefix)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("feed: read error: %w", err)
	}
	return prefixes, nil
}

// ExpandIPv4ToSlash32 expands an IPv4 subnet (/16 to /31, e.g. /19, /22, /23, /24) into all individual /32 host prefixes.
// Prefixes wider than /16 are not expanded to prevent accidental memory exhaustion.
func ExpandIPv4ToSlash32(prefix netip.Prefix) []netip.Prefix {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() == 32 {
		return []netip.Prefix{prefix}
	}
	count := 1 << (32 - prefix.Bits())
	b := prefix.Addr().As4()
	baseInt := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])

	res := make([]netip.Prefix, count)
	for i := 0; i < count; i++ {
		curr := baseInt + uint32(i)
		addr := netip.AddrFrom4([4]byte{
			byte(curr >> 24),
			byte(curr >> 16),
			byte(curr >> 8),
			byte(curr),
		})
		res[i] = netip.PrefixFrom(addr, 32)
	}
	return res
}

// ExpandIPv4Slash24 is a backward-compatible alias for ExpandIPv4ToSlash32.
func ExpandIPv4Slash24(prefix netip.Prefix) []netip.Prefix {
	return ExpandIPv4ToSlash32(prefix)
}

// Fetch loads and parses a feed from an HTTP(S) URL or local file path.
func Fetch(ctx context.Context, source string, expandSlash24 bool) ([]netip.Prefix, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, nil
	}

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, fmt.Errorf("feed: create request: %w", err)
		}
		req.Header.Set("User-Agent", "RTBH-Panel-FeedFetcher/1.0")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("feed: download %s: %w", source, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("feed: download %s returned status %d", source, resp.StatusCode)
		}
		return ParseList(resp.Body, expandSlash24)
	}

	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("feed: open file %s: %w", source, err)
	}
	defer f.Close()
	return ParseList(f, expandSlash24)
}

// SlicesContains is a helper checking if slice contains prefix.
func SlicesContains(list []netip.Prefix, p netip.Prefix) bool {
	return slices.Contains(list, p.Masked())
}
