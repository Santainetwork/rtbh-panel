//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arcelo/rtbh-panel/internal/runtime"
	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

const blackholeCommunity uint32 = 0xffff029a

func postPolicy(t *testing.T, base, endpoint, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

func waitPrefix(t *testing.T, remote *server.BgpServer, want string, present bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		_ = remote.ListPath(apiutil.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_ADJ_IN,
			Family:    bgp.RF_IPv4_UC,
			Name:      "127.0.0.1",
		}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
			if prefix.String() != want || len(paths) == 0 {
				return
			}
			for _, attr := range paths[0].Attrs {
				if attr.GetType() != bgp.BGP_ATTR_TYPE_COMMUNITIES {
					continue
				}
				communities := attr.(*bgp.PathAttributeCommunities)
				if len(communities.Value) == 1 && communities.Value[0] == blackholeCommunity {
					found = true
				}
			}
		})
		if found == present {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("prefix %s present=%v never observed", want, present)
}

func TestRTBHRouteLifecycleOverLoopback(t *testing.T) {
	policyFile := t.TempDir() + "/policy.json"
	cursorFile := t.TempDir() + "/server.cursor"
	config, err := runtime.LoadServerConfig(flag.NewFlagSet("integration", flag.ContinueOnError), []string{
		"--bgp-listen=127.0.0.1:25280",
		"--http-listen=127.0.0.1:0",
		"--sync-listen=127.0.0.1:0",
		"--listen-ranges=127.0.0.0/24",
		"--allowed-asns=64513",
		"--policy-file=" + policyFile,
		"--cursor-file=" + cursorFile,
		"--dry-run=false",
		"--shutdown-timeout=3s",
	})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	select {
	case <-rt.Started():
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}

	remote := server.NewBgpServer()
	go remote.Serve()
	if err := remote.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: 64513, RouterId: "2.2.2.2", ListenPort: -1}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	if err := remote.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65000},
		Transport: &api.Transport{LocalAddress: "127.0.0.2", RemotePort: 25280},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
	}}); err != nil {
		t.Fatal(err)
	}

	base := "http://" + rt.HTTPAddress()
	if got := postPolicy(t, base, "/api/v1/block", `{"action":"add","prefix":"203.0.113.0/24","apply":true}`); got != http.StatusOK {
		t.Fatalf("add deny status=%d", got)
	}
	waitPrefix(t, remote, "203.0.113.0/24", true)

	if got := postPolicy(t, base, "/api/v1/whitelist", `{"action":"add","prefix":"203.0.113.8/32","apply":true}`); got != http.StatusOK {
		t.Fatalf("add whitelist status=%d", got)
	}
	waitPrefix(t, remote, "203.0.113.0/24", false)

	if got := postPolicy(t, base, "/api/v1/whitelist", `{"action":"remove","prefix":"203.0.113.8/32","apply":true}`); got != http.StatusOK {
		t.Fatalf("remove whitelist status=%d", got)
	}
	waitPrefix(t, remote, "203.0.113.0/24", true)

	if got := postPolicy(t, base, "/api/v1/block", `{"action":"remove","prefix":"203.0.113.0/24","apply":true}`); got != http.StatusOK {
		t.Fatalf("remove deny status=%d", got)
	}
	waitPrefix(t, remote, "203.0.113.0/24", false)

	// Verify the same listener serves the embedded SPA and versioned API.
	index, err := http.Get(base + "/")
	if err != nil || index.StatusCode != http.StatusOK {
		t.Fatalf("index response=%v err=%v", index.StatusCode, err)
	}
	defer index.Body.Close()
	var configResponse struct {
		DryRun bool `json:"dry_run"`
	}
	response, err := http.Get(base + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(&configResponse); err != nil || configResponse.DryRun {
		t.Fatalf("config=%+v err=%v", configResponse, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}
