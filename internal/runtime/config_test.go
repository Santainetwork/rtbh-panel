package runtime

import (
	"flag"
	"net/netip"
	"testing"
	"time"
)

func TestLoadConfigUsesSafeLocalDefaults(t *testing.T) {
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}
	cfg, err := LoadConfig(flag.NewFlagSet("test", flag.ContinueOnError), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LocalASN != 65000 || cfg.RouterID != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("identity defaults = ASN %d router %s", cfg.LocalASN, cfg.RouterID)
	}
	if cfg.BGPListenAddress != "127.0.0.1:4179" || cfg.HTTPListenAddress != "127.0.0.1:8080" || cfg.SyncListenAddress != "127.0.0.1:17900" {
		t.Fatalf("unsafe listen defaults: %#v", cfg)
	}
	if !cfg.DryRun || cfg.MaxSessions != 8 || cfg.SyncMaxInFlight < 1 || cfg.SyncMaxMessageBytes < 1 {
		t.Fatalf("unsafe operational defaults: %#v", cfg)
	}
}

func TestLoadConfigFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("RTBH_LOCAL_ASN", "64512")
	t.Setenv("RTBH_LISTEN_RANGES", "10.0.0.0/8")
	t.Setenv("RTBH_ALLOWED_ASNS", "64513")
	t.Setenv("RTBH_DRY_RUN", "true")
	cfg, err := LoadConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{
		"--local-asn=65010",
		"--listen-ranges=192.0.2.0/24,198.51.100.0/24",
		"--allowed-asns=65020,65021",
		"--dry-run=false",
		"--policy-file=" + t.TempDir() + "/policy.json",
		"--reconnect-min=250ms",
		"--reconnect-max=2s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LocalASN != 65010 || cfg.DryRun {
		t.Fatalf("flag precedence failed: %#v", cfg)
	}
	if len(cfg.ListenRanges) != 2 || len(cfg.AllowedASNs) != 2 || cfg.ReconnectMin != 250*time.Millisecond || cfg.ReconnectMax != 2*time.Second {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestLoadConfigRejectsInvalidSafetyValues(t *testing.T) {
	for _, args := range [][]string{
		{"--listen-ranges=not-a-cidr"},
		{"--allowed-asns=0"},
		{"--max-sessions=0"},
		{"--max-in-flight=0"},
		{"--reconnect-min=2s", "--reconnect-max=1s"},
		{"--dry-run=false"},
	} {
		if _, err := LoadConfig(flag.NewFlagSet("test", flag.ContinueOnError), args); err == nil {
			t.Fatalf("LoadConfig(%v) unexpectedly succeeded", args)
		}
	}
}

func TestLoadConfigRequiresPolicyFileWhenApplyIsEnabled(t *testing.T) {
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}
	_, err := LoadConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{"--dry-run=false"})
	if err == nil {
		t.Fatal("apply mode without policy file unexpectedly accepted")
	}
}

func TestLoadServerConfigNextHops(t *testing.T) {
	config, err := LoadServerConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{
		"--rtbh-next-hop-v4=192.0.2.254", "--rtbh-next-hop-v6=2001:db8::ffff",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.RTBHNextHopV4.String() != "192.0.2.254" || config.RTBHNextHopV6.String() != "2001:db8::ffff" {
		t.Fatalf("next hops = %s, %s", config.RTBHNextHopV4, config.RTBHNextHopV6)
	}
}

func TestLoadServerConfigInsecureListen(t *testing.T) {
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}
	_, err := LoadServerConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{
		"--http-listen=0.0.0.0:8080",
	})
	if err == nil {
		t.Fatal("expected non-loopback http-listen to fail without --insecure-listen")
	}

	cfg, err := LoadServerConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{
		"--http-listen=0.0.0.0:8080",
		"--insecure-listen=true",
	})
	if err != nil {
		t.Fatalf("unexpected error with --insecure-listen: %v", err)
	}
	if !cfg.InsecureListen || cfg.HTTPListenAddress != "0.0.0.0:8080" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadServerConfigRejectsMismatchedNextHopFamily(t *testing.T) {
	_, err := LoadServerConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{"--rtbh-next-hop-v4=2001:db8::1"})
	if err == nil {
		t.Fatal("LoadServerConfig accepted IPv6 v4 next hop")
	}
	_, err = LoadServerConfig(flag.NewFlagSet("test", flag.ContinueOnError), []string{"--rtbh-next-hop-v6=192.0.2.1"})
	if err == nil {
		t.Fatal("LoadServerConfig accepted IPv4 v6 next hop")
	}
}
