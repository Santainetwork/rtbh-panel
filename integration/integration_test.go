//go:build integration

package integration

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
)

func TestPolicySyncOverLoopbackResumesFromACKCursor(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := agentrpc.Config{MaxMessageBytes: 4096, MaxInFlight: 2}
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		session, err := agentrpc.NewSession(connection, config, agentrpc.Resume{AppliedCursor: 1})
		if err == nil {
			var message agentrpc.Message
			message, err = session.Receive(context.Background())
			if err == nil && message.Sequence != 2 {
				err = &sequenceError{got: message.Sequence}
			}
			if err == nil {
				err = session.Ack(context.Background(), message.Sequence)
			}
		}
		serverResult <- err
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client, err := agentrpc.NewSession(connection, config, agentrpc.Resume{PeerCursor: 1})
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := client.SendPolicy(context.Background(), agentrpc.PolicyChange{ID: "policy-2", IdempotencyKey: "request-2", Operation: "add", List: "blocklist", Prefix: "203.0.113.0/24"})
	if err != nil || sequence != 2 {
		t.Fatalf("SendPolicy() = %d, %v", sequence, err)
	}
	ack, err := client.Receive(context.Background())
	if err != nil || ack.Cursor != 2 {
		t.Fatalf("Receive() = %#v, %v", ack, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

type sequenceError struct{ got uint64 }

func (e *sequenceError) Error() string { return "unexpected policy sequence" }

type mockDashboard struct{ mutations int }

func (*mockDashboard) Config(context.Context) (dashboard.Config, error) {
	return dashboard.Config{}, nil
}
func (*mockDashboard) UpdateConfig(context.Context, dashboard.Config) error       { return nil }
func (*mockDashboard) EstablishedPeers(context.Context) ([]dashboard.Peer, error) { return nil, nil }
func (m *mockDashboard) MutatePolicy(context.Context, dashboard.PolicyMutation) error {
	m.mutations++
	return nil
}

func TestDashboardPolicyIsDryRunByDefault(t *testing.T) {
	backend := &mockDashboard{}
	handler := dashboard.NewHandler(backend, func(*http.Request) bool { return true })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/block", strings.NewReader(`{"action":"add","prefix":"192.0.2.0/24"}`)))
	if response.Code != http.StatusOK || backend.mutations != 0 || !strings.Contains(response.Body.String(), `"dry_run":true`) {
		t.Fatalf("response=%d mutations=%d body=%s", response.Code, backend.mutations, response.Body.String())
	}
}
