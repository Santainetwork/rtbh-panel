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
		if expandSlash24 && prefix.Addr().Is4() && prefix.Bits() == 24 {
			for _, p32 := range ExpandIPv4Slash24(prefix) {
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

// ExpandIPv4Slash24 expands an IPv4 /24 prefix into all 256 /32 prefixes (.0 to .255).
func ExpandIPv4Slash24(prefix netip.Prefix) []netip.Prefix {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return []netip.Prefix{prefix}
	}
	b := prefix.Addr().As4()
	res := make([]netip.Prefix, 256)
	for i := 0; i < 256; i++ {
		addr := netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(i)})
		res[i] = netip.PrefixFrom(addr, 32)
	}
	return res
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
