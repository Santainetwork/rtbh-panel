package runtime

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
)

func TestAgentDryRunDoesNotAcknowledgePolicy(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	cfg := testConfig(t)
	agent, err := NewAgent(cfg, &DryRunAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := agentrpc.NewSession(left, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := agentrpc.NewSession(right, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- agent.consume(context.Background(), receiver, new(uint64))
	}()
	change := agentrpc.PolicyChange{ID: "p-1", IdempotencyKey: "i-1", Operation: "add", List: "blocklist", Prefix: "198.51.100.9/32"}
	if _, err := sender.SendPolicy(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrDryRunPolicy) {
		t.Fatalf("consume error = %v, want ErrDryRunPolicy", err)
	}
}

func TestAgentReceivesAppliesAndAcknowledgesPolicy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	cfg := testConfig(t)
	cfg.SyncServerAddress = listener.Addr().String()
	cfg.CursorFile = t.TempDir() + "/cursor"
	cfg.DryRun = false
	cfg.PolicyFile = t.TempDir() + "/policy.json"
	cfg.ReconnectMin = 5 * time.Millisecond
	cfg.ReconnectMax = 20 * time.Millisecond
	adapter := &recordingAdapter{}
	agent, err := NewAgent(cfg, adapter)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	session, err := agentrpc.NewSession(connection, agentrpc.Config{MaxMessageBytes: cfg.SyncMaxMessageBytes, MaxInFlight: cfg.SyncMaxInFlight}, agentrpc.Resume{})
	if err != nil {
		t.Fatal(err)
	}
	change := agentrpc.PolicyChange{ID: "p-1", IdempotencyKey: "i-1", Operation: "add", List: "blocklist", Prefix: "198.51.100.9/32"}
	if _, err := session.SendPolicy(ctx, change); err != nil {
		t.Fatal(err)
	}
	ack, err := session.Receive(ctx)
	if err != nil || ack.Cursor != 1 {
		t.Fatalf("ACK=%#v err=%v", ack, err)
	}
	connection.Close()

	deadline := time.Now().Add(time.Second)
	for adapter.Count() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if adapter.Count() != 1 {
		t.Fatal("agent did not apply policy")
	}
	if cursor, err := loadCursor(cfg.CursorFile); err != nil || cursor != 1 {
		t.Fatalf("cursor=%d err=%v", cursor, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not stop")
	}
}
