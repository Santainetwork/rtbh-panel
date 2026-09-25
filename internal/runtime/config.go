package runtime

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxMessageBytes = 1 << 20
	defaultMaxInFlight     = 16
)

var configEnvironmentKeys = []string{
	"RTBH_LOCAL_ASN", "RTBH_ROUTER_ID", "RTBH_BGP_LISTEN", "RTBH_HTTP_LISTEN",
	"RTBH_SYNC_LISTEN", "RTBH_SYNC_SERVER", "RTBH_LISTEN_RANGES", "RTBH_ALLOWED_ASNS",
	"RTBH_MAX_SESSIONS", "RTBH_MAX_MESSAGE_BYTES", "RTBH_MAX_IN_FLIGHT",
	"RTBH_RECONNECT_MIN", "RTBH_RECONNECT_MAX", "RTBH_POLICY_FILE", "RTBH_CURSOR_FILE",
	"RTBH_DRY_RUN", "RTBH_SHUTDOWN_TIMEOUT", "RTBH_INSECURE_LISTEN",
	"RTBH_NEXT_HOP_V4", "RTBH_NEXT_HOP_V6",
	"RTBH_BLOCKLIST_FEED", "RTBH_WHITELIST_FEED", "RTBH_FEED_INTERVAL", "RTBH_WHITELIST_EXPAND_SLASH24",
}

type Config struct {
	LocalASN                uint32
	RouterID                netip.Addr
	BGPListenAddress        string
	HTTPListenAddress       string
	SyncListenAddress       string
	SyncServerAddress       string
	ListenRanges            []netip.Prefix
	AllowedASNs             []uint32
	MaxSessions             int
	SyncMaxMessageBytes     int
	SyncMaxInFlight         int
	ReconnectMin            time.Duration
	ReconnectMax            time.Duration
	PolicyFile              string
	CursorFile              string
	DryRun                  bool
	ShutdownTimeout         time.Duration
	InsecureListen          bool
	RTBHNextHopV4           netip.Addr
	RTBHNextHopV6           netip.Addr
	BlocklistFeed           string
	WhitelistFeed           string
	FeedInterval            time.Duration
	WhitelistExpandSlash24 bool
}

func DefaultConfig() Config {
	return Config{
		LocalASN:            65000,
		RouterID:            netip.MustParseAddr("192.0.2.1"),
		BGPListenAddress:    "127.0.0.1:4179",
		HTTPListenAddress:   "127.0.0.1:8080",
		SyncListenAddress:   "127.0.0.1:17900",
		SyncServerAddress:   "127.0.0.1:17900",
		ListenRanges:        []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")},
		MaxSessions:         8,
		SyncMaxMessageBytes: defaultMaxMessageBytes,
		SyncMaxInFlight:     defaultMaxInFlight,
		ReconnectMin:        250 * time.Millisecond,
		ReconnectMax:        5 * time.Second,
		DryRun:              true,
		ShutdownTimeout:        5 * time.Second,
		RTBHNextHopV6:          netip.MustParseAddr("::1"),
		WhitelistExpandSlash24: true,
	}
}

type configMode uint8

const (
	configAll configMode = iota
	configServer
	configAgent
)

// LoadConfig applies all supported flags over environment variables over safe local defaults.
func LoadConfig(fs *flag.FlagSet, args []string) (Config, error) {
	return loadConfig(fs, args, configAll)
}

func LoadServerConfig(fs *flag.FlagSet, args []string) (Config, error) {
	return loadConfig(fs, args, configServer)
}

func LoadAgentConfig(fs *flag.FlagSet, args []string) (Config, error) {
	return loadConfig(fs, args, configAgent)
}

func loadConfig(fs *flag.FlagSet, args []string, mode configMode) (Config, error) {
	if fs == nil {
		return Config{}, errors.New("runtime: flag set is required")
	}
	config := DefaultConfig()
	if err := applyEnvironment(&config); err != nil {
		return Config{}, err
	}

	localASN := strconv.FormatUint(uint64(config.LocalASN), 10)
	routerID := config.RouterID.String()
	listenRanges := joinPrefixes(config.ListenRanges)
	allowedASNs := joinASNs(config.AllowedASNs)
	rtbhNextHopV4 := ""
	if config.RTBHNextHopV4.IsValid() {
		rtbhNextHopV4 = config.RTBHNextHopV4.String()
	}
	rtbhNextHopV6 := config.RTBHNextHopV6.String()
	if mode != configAgent {
		fs.StringVar(&localASN, "local-asn", localASN, "local BGP ASN")
		fs.StringVar(&routerID, "router-id", routerID, "IPv4 BGP router ID")
		fs.StringVar(&config.BGPListenAddress, "bgp-listen", config.BGPListenAddress, "BGP listen address; port -1 disables listening")
		fs.StringVar(&config.HTTPListenAddress, "http-listen", config.HTTPListenAddress, "dashboard HTTP listen address")
		fs.StringVar(&config.SyncListenAddress, "sync-listen", config.SyncListenAddress, "policy-sync server listen address")
		fs.StringVar(&listenRanges, "listen-ranges", listenRanges, "comma-separated dynamic-neighbor CIDRs")
		fs.StringVar(&allowedASNs, "allowed-asns", allowedASNs, "comma-separated allowed peer ASNs")
		fs.IntVar(&config.MaxSessions, "max-sessions", config.MaxSessions, "maximum established dynamic sessions")
		fs.DurationVar(&config.ShutdownTimeout, "shutdown-timeout", config.ShutdownTimeout, "graceful shutdown timeout")
		fs.IntVar(&config.SyncMaxMessageBytes, "sync-max-message-bytes", config.SyncMaxMessageBytes, "alias for --max-message-bytes")
		fs.IntVar(&config.SyncMaxInFlight, "sync-max-inflight", config.SyncMaxInFlight, "alias for --max-in-flight")
		fs.StringVar(&rtbhNextHopV4, "rtbh-next-hop-v4", rtbhNextHopV4, "RTBH route IPv4 next hop; defaults to router ID")
		fs.StringVar(&rtbhNextHopV6, "rtbh-next-hop-v6", rtbhNextHopV6, "RTBH route IPv6 next hop")
		fs.StringVar(&config.BlocklistFeed, "blocklist-feed", config.BlocklistFeed, "optional URL or file path for blocklist feed")
		fs.StringVar(&config.WhitelistFeed, "whitelist-feed", config.WhitelistFeed, "optional URL or file path for whitelist feed")
		fs.DurationVar(&config.FeedInterval, "feed-interval", config.FeedInterval, "periodic feed download interval (0 disables periodic reload)")
		fs.BoolVar(&config.WhitelistExpandSlash24, "whitelist-expand-slash24", config.WhitelistExpandSlash24, "expand /24 in whitelist feed into 256 /32 prefixes")
	}
	if mode != configServer {
		fs.StringVar(&config.SyncServerAddress, "sync-server", config.SyncServerAddress, "policy-sync server address")
		fs.DurationVar(&config.ReconnectMin, "reconnect-min", config.ReconnectMin, "minimum reconnect delay")
		fs.DurationVar(&config.ReconnectMax, "reconnect-max", config.ReconnectMax, "maximum reconnect delay")
	}
	fs.IntVar(&config.SyncMaxMessageBytes, "max-message-bytes", config.SyncMaxMessageBytes, "maximum policy-sync frame size")
	fs.IntVar(&config.SyncMaxInFlight, "max-in-flight", config.SyncMaxInFlight, "maximum unacknowledged policy messages")
	fs.StringVar(&config.PolicyFile, "policy-file", config.PolicyFile, "optional policy store file")
	fs.StringVar(&config.CursorFile, "cursor-file", config.CursorFile, "optional applied-cursor file")
	fs.BoolVar(&config.DryRun, "dry-run", config.DryRun, "use the no-op policy adapter")
	fs.BoolVar(&config.InsecureListen, "insecure-listen", config.InsecureListen, "allow non-loopback HTTP and sync listen addresses without TLS")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("runtime: unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	parsedASN, err := strconv.ParseUint(localASN, 10, 32)
	if err != nil {
		return Config{}, fmt.Errorf("runtime: local ASN: %w", err)
	}
	config.LocalASN = uint32(parsedASN)

	config.RouterID, err = netip.ParseAddr(routerID)
	if err != nil || !config.RouterID.Is4() {
		return Config{}, errors.New("runtime: router ID must be IPv4")
	}
	config.RTBHNextHopV4, err = parseNextHop(rtbhNextHopV4, config.RouterID)
	if err != nil {
		return Config{}, err
	}
	config.RTBHNextHopV6, err = parseNextHop(rtbhNextHopV6, netip.MustParseAddr("::1"))
	if err != nil {
		return Config{}, err
	}
	config.ListenRanges, err = parsePrefixes(listenRanges)
	if err != nil {
		return Config{}, err
	}
	config.AllowedASNs, err = parseASNs(allowedASNs)
	if err != nil {
		return Config{}, err
	}
	if err := config.validateCommon(); err != nil {
		return Config{}, err
	}
	if mode != configAgent {
		err = config.validateServer()
	}
	if err == nil && mode != configServer {
		err = config.validateAgent()
	}
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) validate() error {
	if err := config.validateCommon(); err != nil {
		return err
	}
	if err := config.validateServer(); err != nil {
		return err
	}
	return config.validateAgent()
}

func (config Config) validateCommon() error {
	if config.SyncMaxMessageBytes < 1 || config.SyncMaxInFlight < 1 {
		return errors.New("runtime: policy-sync limits must be positive")
	}
	if !config.DryRun && strings.TrimSpace(config.PolicyFile) == "" {
		return errors.New("runtime: policy file is required when apply mode is enabled")
	}
	return nil
}

func (config Config) validateServer() error {
	if config.LocalASN == 0 || config.MaxSessions < 1 {
		return errors.New("runtime: ASN and max sessions must be positive")
	}
	if !config.RouterID.Is4() || len(config.ListenRanges) == 0 {
		return errors.New("runtime: IPv4 router ID and listen range are required")
	}
	for _, prefix := range config.ListenRanges {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return errors.New("runtime: listen ranges must be canonical CIDRs")
		}
	}
	for _, asn := range config.AllowedASNs {
		if asn == 0 {
			return errors.New("runtime: allowed ASNs must be non-zero")
		}
	}
	if config.ShutdownTimeout <= 0 {
		return errors.New("runtime: shutdown timeout must be positive")
	}
	for name, address := range map[string]string{
		"BGP listen":  config.BGPListenAddress,
		"HTTP listen": config.HTTPListenAddress,
		"sync listen": config.SyncListenAddress,
	} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("runtime: invalid %s address %q: %w", name, address, err)
		}
	}
	if !config.InsecureListen {
		if err := validateLocalAddress("HTTP listen", config.HTTPListenAddress); err != nil {
			return err
		}
		if err := validateLocalAddress("sync listen", config.SyncListenAddress); err != nil {
			return err
		}
	}
	return nil
}

func (config Config) validateAgent() error {
	if config.ReconnectMin <= 0 || config.ReconnectMax < config.ReconnectMin {
		return errors.New("runtime: reconnect bounds are invalid")
	}
	if _, _, err := net.SplitHostPort(config.SyncServerAddress); err != nil {
		return fmt.Errorf("runtime: invalid sync server address %q: %w", config.SyncServerAddress, err)
	}
	if !config.InsecureListen {
		return validateLocalAddress("sync server", config.SyncServerAddress)
	}
	return nil
}

func (config Config) syncConfig() agentRPCConfig {
	return agentRPCConfig{MaxMessageBytes: config.SyncMaxMessageBytes, MaxInFlight: config.SyncMaxInFlight}
}

type agentRPCConfig struct {
	MaxMessageBytes int
	MaxInFlight     int
}

func applyEnvironment(config *Config) error {
	var err error
	if config.LocalASN, err = envUint32("RTBH_LOCAL_ASN", config.LocalASN); err != nil {
		return err
	}
	if raw := os.Getenv("RTBH_ROUTER_ID"); raw != "" {
		config.RouterID, err = netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("runtime: RTBH_ROUTER_ID: %w", err)
		}
	}
	applyStringEnv(&config.BGPListenAddress, "RTBH_BGP_LISTEN")
	applyStringEnv(&config.HTTPListenAddress, "RTBH_HTTP_LISTEN")
	applyStringEnv(&config.SyncListenAddress, "RTBH_SYNC_LISTEN")
	applyStringEnv(&config.SyncServerAddress, "RTBH_SYNC_SERVER")
	if raw := os.Getenv("RTBH_LISTEN_RANGES"); raw != "" {
		config.ListenRanges, err = parsePrefixes(raw)
		if err != nil {
			return fmt.Errorf("runtime: RTBH_LISTEN_RANGES: %w", err)
		}
	}
	if raw := os.Getenv("RTBH_ALLOWED_ASNS"); raw != "" {
		config.AllowedASNs, err = parseASNs(raw)
		if err != nil {
			return fmt.Errorf("runtime: RTBH_ALLOWED_ASNS: %w", err)
		}
	}
	if config.MaxSessions, err = envInt("RTBH_MAX_SESSIONS", config.MaxSessions); err != nil {
		return err
	}
	if config.SyncMaxMessageBytes, err = envInt("RTBH_MAX_MESSAGE_BYTES", config.SyncMaxMessageBytes); err != nil {
		return err
	}
	if config.SyncMaxInFlight, err = envInt("RTBH_MAX_IN_FLIGHT", config.SyncMaxInFlight); err != nil {
		return err
	}
	if config.ReconnectMin, err = envDuration("RTBH_RECONNECT_MIN", config.ReconnectMin); err != nil {
		return err
	}
	if config.ReconnectMax, err = envDuration("RTBH_RECONNECT_MAX", config.ReconnectMax); err != nil {
		return err
	}
	applyStringEnv(&config.PolicyFile, "RTBH_POLICY_FILE")
	applyStringEnv(&config.CursorFile, "RTBH_CURSOR_FILE")
	if config.DryRun, err = envBool("RTBH_DRY_RUN", config.DryRun); err != nil {
		return err
	}
	if config.InsecureListen, err = envBool("RTBH_INSECURE_LISTEN", config.InsecureListen); err != nil {
		return err
	}
	applyStringEnv(&config.BlocklistFeed, "RTBH_BLOCKLIST_FEED")
	applyStringEnv(&config.WhitelistFeed, "RTBH_WHITELIST_FEED")
	if config.FeedInterval, err = envDuration("RTBH_FEED_INTERVAL", config.FeedInterval); err != nil {
		return err
	}
	if config.WhitelistExpandSlash24, err = envBool("RTBH_WHITELIST_EXPAND_SLASH24", config.WhitelistExpandSlash24); err != nil {
		return err
	}
	if raw := os.Getenv("RTBH_NEXT_HOP_V4"); raw != "" {
		config.RTBHNextHopV4, err = netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("runtime: RTBH_NEXT_HOP_V4: %w", err)
		}
	}
	if raw := os.Getenv("RTBH_NEXT_HOP_V6"); raw != "" {
		config.RTBHNextHopV6, err = netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("runtime: RTBH_NEXT_HOP_V6: %w", err)
		}
	}
	config.ShutdownTimeout, err = envDuration("RTBH_SHUTDOWN_TIMEOUT", config.ShutdownTimeout)
	return err
}

func parseNextHop(raw string, fallback netip.Addr) (netip.Addr, error) {
	if raw == "" {
		return fallback, nil
	}
	nextHop, err := netip.ParseAddr(raw)
	if err != nil || nextHop.Is4() != fallback.Is4() {
		return netip.Addr{}, fmt.Errorf("runtime: next hop %q must be %s", raw, familyName(fallback))
	}
	return nextHop, nil
}

func familyName(addr netip.Addr) string {
	if addr.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	parts := splitCSV(raw)
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix != prefix.Masked() {
			return nil, fmt.Errorf("runtime: listen range %q must be a canonical CIDR", part)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseASNs(raw string) ([]uint32, error) {
	parts := splitCSV(raw)
	asns := make([]uint32, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("runtime: allowed ASN %q must be a non-zero uint32", part)
		}
		asns = append(asns, uint32(value))
	}
	return asns, nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = prefix.String()
	}
	return strings.Join(values, ",")
}

func joinASNs(asns []uint32) string {
	values := make([]string, len(asns))
	for index, asn := range asns {
		values[index] = strconv.FormatUint(uint64(asn), 10)
	}
	return strings.Join(values, ",")
}

func applyStringEnv(target *string, key string) {
	if value := os.Getenv(key); value != "" {
		*target = value
	}
}

func envInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("runtime: %s: %w", key, err)
	}
	return parsed, nil
}

func envUint32(key string, fallback uint32) (uint32, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("runtime: %s: %w", key, err)
	}
	return uint32(parsed), nil
}

func envBool(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("runtime: %s: %w", key, err)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("runtime: %s: %w", key, err)
	}
	return parsed, nil
}

func validateLocalAddress(name, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("runtime: %s must use a loopback address without TLS", name)
	}
	return nil
}
