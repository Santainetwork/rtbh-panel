package runtime

import (
	"errors"
	"flag"
	"io"
	"testing"
)

func TestLoadConfigDefaultsAndFlagHelp(t *testing.T) {
	server := flag.NewFlagSet("rtbh-server", flag.ContinueOnError)
	cfg, err := LoadConfig(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DryRun || cfg.HTTPListenAddress != "127.0.0.1:8080" || cfg.BGPListenAddress != "127.0.0.1:4179" {
		t.Fatalf("unsafe defaults: %#v", cfg)
	}
	for _, name := range []string{"dry-run", "http-listen", "bgp-listen", "sync-listen", "sync-server"} {
		if server.Lookup(name) == nil {
			t.Fatalf("flag %q missing", name)
		}
	}
}

func TestLoadConfigHelp(t *testing.T) {
	flags := flag.NewFlagSet("rtbh-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if _, err := LoadConfig(flags, []string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("LoadConfig(--help) error = %v, want flag.ErrHelp", err)
	}
}

func TestCommandSpecificFlagsAreMinimal(t *testing.T) {
	server := flag.NewFlagSet("rtbh-server", flag.ContinueOnError)
	if _, err := LoadServerConfig(server, nil); err != nil {
		t.Fatal(err)
	}
	if server.Lookup("sync-server") != nil || server.Lookup("bgp-listen") == nil {
		t.Fatal("server flags contain agent-only settings or omit BGP settings")
	}

	agent := flag.NewFlagSet("rtbh-agent", flag.ContinueOnError)
	if _, err := LoadAgentConfig(agent, nil); err != nil {
		t.Fatal(err)
	}
	if agent.Lookup("bgp-listen") != nil || agent.Lookup("sync-listen") != nil || agent.Lookup("sync-server") == nil {
		t.Fatal("agent flags contain server-only settings or omit sync endpoint")
	}
}
