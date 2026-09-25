// Package feed fetches and parses IP/CIDR text lists from URLs or local files.
package feed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
				// Skip non-IP entries gracefully (e.g. domain names like 365bet.one)
				continue
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
				// Skip invalid CIDRs gracefully
				continue
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

	parsed, parseErr := url.Parse(source)
	if parseErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		if err := ValidatePublicURL(ctx, source); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, fmt.Errorf("feed: create request: %w", err)
		}
		req.Header.Set("User-Agent", "RTBH-Panel-FeedFetcher/1.0")

		client := publicHTTPClient()
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
	if parseErr != nil || parsed.Scheme != "" {
		return nil, errors.New("feed: source must be an HTTP(S) URL or local file path")
	}

	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("feed: open file %s: %w", source, err)
	}
	defer f.Close()
	return ParseList(f, expandSlash24)
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ValidatePublicURL accepts only HTTP(S) URLs whose current addresses are public.
func ValidatePublicURL(ctx context.Context, raw string) error {
	normalized, err := validateURLFormat(raw)
	if err != nil {
		return err
	}
	parsed, _ := url.Parse(normalized)
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", parsed.Hostname())
	if err != nil {
		return fmt.Errorf("feed: resolve public URL host: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("feed: public URL host has no addresses")
	}
	for _, address := range addresses {
		if !isPublicIP(address) {
			return fmt.Errorf("feed: URL host resolves to non-public address %s", address)
		}
	}
	return nil
}

func validateURLFormat(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	parsed, err := url.Parse(normalized)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		return "", errors.New("feed: source must be a public HTTP(S) URL without userinfo")
	}
	return normalized, nil
}

func isPublicIP(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func publicHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("feed: invalid destination: %w", err)
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("feed: resolve destination host %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("feed: destination host %q has no addresses", host)
		}
		for _, resolved := range addresses {
			if !isPublicIP(resolved) {
				return nil, fmt.Errorf("feed: destination resolves to non-public address %s", resolved)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("feed: too many redirects")
			}
			return ValidatePublicURL(req.Context(), req.URL.String())
		},
	}
}

// SlicesContains is a helper checking if slice contains prefix.
func SlicesContains(list []netip.Prefix, p netip.Prefix) bool {
	return slices.Contains(list, p.Masked())
}
