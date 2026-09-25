package runtime

import (
	"context"
	"flag"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
)

func TestServerRunsDashboardAndPolicySyncOnLoopback(t *testing.T) {
	cfg := testConfig(t)
	cfg.BGPListenAddress = "127.0.0.1:-1"
	cfg.HTTPListenAddress = "127.0.0.1:0"
	cfg.SyncListenAddress = "127.0.0.1:0"
	cfg.DryRun = false
	cfg.APIToken = "test-token"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	select {
	case <-server.Started():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}

	response, err := http.Get("http://" + server.HTTPAddress() + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard API status=%d", response.StatusCode)
	}
	requestWithToken, err := http.NewRequest(http.MethodGet, "http://"+server.HTTPAddress()+"/api/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestWithToken.Header.Set("Authorization", "Bearer test-token")
	response, err = http.DefaultClient.Do(requestWithToken)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated dashboard API status=%d", response.StatusCode)
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.SyncAddress())
	if err != nil {
		t.Fatal(err)
	}
	session, err := agentrpc.NewSession(connection, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+server.HTTPAddress()+"/api/block", strings.NewReader(`{"action":"add","prefix":"203.0.113.0/24","apply":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-token")
	mutationResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	mutationResponse.Body.Close()
	if mutationResponse.StatusCode != http.StatusOK {
		t.Fatalf("mutation status=%d", mutationResponse.StatusCode)
	}
	message, err := session.Receive(ctx)
	if err != nil || message.Sequence != 1 || message.Policy == nil || message.Policy.Prefix != "203.0.113.0/24" {
		t.Fatalf("policy=%#v err=%v", message, err)
	}
	if err := session.Ack(ctx, message.Sequence); err != nil {
		t.Fatal(err)
	}
	connection.Close()

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

func TestServerResumesPolicySequenceAfterReconnectWithoutCursorFile(t *testing.T) {
	cfg := testConfig(t)
	cfg.DryRun = false
	cfg.BGPListenAddress = "127.0.0.1:-1"
	cfg.HTTPListenAddress = "127.0.0.1:0"
	cfg.SyncListenAddress = "127.0.0.1:0"
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	select {
	case <-server.Started():
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}

	connect := func() (*agentrpc.Session, net.Conn) {
		t.Helper()
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.SyncAddress())
		if err != nil {
			t.Fatal(err)
		}
		session, err := agentrpc.NewSession(connection, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{})
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		return session, connection
	}
	session, connection := connect()
	postMutation := func(prefix string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+server.HTTPAddress()+"/api/block", strings.NewReader(`{"action":"add","prefix":"`+prefix+`","apply":true}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("mutation status=%d", response.StatusCode)
		}
	}
	postMutation("203.0.113.0/24")
	first, err := session.Receive(ctx)
	if err != nil || first.Sequence != 1 {
		t.Fatalf("first policy=%#v err=%v", first, err)
	}
	if err := session.Ack(ctx, first.Sequence); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	// The server closes the previous sync connection before accepting its replacement.
	deadline := time.Now().Add(time.Second)
	for {
		secondConnection, dialErr := (&net.Dialer{}).DialContext(ctx, "tcp", server.SyncAddress())
		if dialErr != nil {
			if time.Now().After(deadline) {
				t.Fatal(dialErr)
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		secondSession, sessionErr := agentrpc.NewSession(secondConnection, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{AppliedCursor: 1})
		if sessionErr != nil {
			secondConnection.Close()
			t.Fatal(sessionErr)
		}
		session, connection = secondSession, secondConnection
		break
	}
	defer connection.Close()
	postMutation("198.51.100.0/24")
	second, err := session.Receive(ctx)
	if err != nil || second.Sequence != 2 || second.Policy == nil || second.Policy.Prefix != "198.51.100.0/24" {
		t.Fatalf("resumed policy=%#v err=%v", second, err)
	}
	if err := session.Ack(ctx, second.Sequence); err != nil {
		t.Fatal(err)
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

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig(flag.NewFlagSet("test", flag.ContinueOnError), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PolicyFile = t.TempDir() + "/policy.json"
	cfg.ListenRanges = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}
	return cfg
}
