package agentrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func testConfig() Config { return Config{MaxMessageBytes: 1024, MaxInFlight: 2} }

func TestPolicyIsAcknowledgedAndAdvancesResumeCursor(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client, err := NewSession(clientConn, testConfig(), Resume{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(serverConn, testConfig(), Resume{})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		message, err := server.Receive(context.Background())
		if err == nil && (message.Sequence != 1 || message.Policy.Prefix != "203.0.113.0/24") {
			err = errors.New("server received unexpected policy")
		}
		if err == nil {
			err = server.Ack(context.Background(), message.Sequence)
		}
		done <- err
	}()

	sequence, err := client.SendPolicy(context.Background(), PolicyChange{
		Operation: "add", List: "blocklist", Prefix: "203.0.113.0/24",
	})
	if err != nil || sequence != 1 {
		t.Fatalf("SendPolicy() = %d, %v", sequence, err)
	}
	ack, err := client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ack.Type != TypeACK || ack.Cursor != 1 || client.PeerCursor() != 1 {
		t.Fatalf("ACK = %#v, peer cursor = %d", ack, client.PeerCursor())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDuplicatePolicyIsAcknowledgedButNotDeliveredAgain(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	server, err := NewSession(serverConn, testConfig(), Resume{AppliedCursor: 1})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		encoder := json.NewEncoder(clientConn)
		_ = encoder.Encode(Message{Type: TypePolicy, Sequence: 1, Policy: &PolicyChange{Operation: "add", List: "blocklist", Prefix: "192.0.2.0/24"}})
		_ = encoder.Encode(Message{Type: TypePolicy, Sequence: 2, Policy: &PolicyChange{Operation: "add", List: "blocklist", Prefix: "198.51.100.0/24"}})
	}()
	ackResult := make(chan Message, 1)
	go func() {
		var ack Message
		_ = json.NewDecoder(clientConn).Decode(&ack)
		ackResult <- ack
	}()

	message, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if message.Sequence != 2 {
		t.Fatalf("delivered sequence = %d, want 2", message.Sequence)
	}
	if ack := <-ackResult; ack.Type != TypeACK || ack.Cursor != 1 {
		t.Fatalf("duplicate ACK = %#v", ack)
	}
}

func TestBackpressureRejectsMoreThanConfiguredInFlight(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	config := testConfig()
	config.MaxInFlight = 1
	client, err := NewSession(clientConn, config, Resume{})
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(peerConn).ReadString('\n')
		close(read)
	}()
	if _, err := client.SendPolicy(context.Background(), PolicyChange{Operation: "add", List: "blocklist", Prefix: "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	<-read
	if _, err := client.SendPolicy(context.Background(), PolicyChange{Operation: "add", List: "blocklist", Prefix: "198.51.100.0/24"}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("second SendPolicy() error = %v, want ErrBackpressure", err)
	}
}

func TestReceiveRejectsOversizedFrame(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	config := testConfig()
	config.MaxMessageBytes = 32
	server, err := NewSession(serverConn, config, Resume{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = clientConn.Write([]byte(strings.Repeat("x", 33) + "\n")) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := server.Receive(ctx); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Receive() error = %v, want ErrMessageTooLarge", err)
	}
}

func TestNewSessionRejectsUnboundedConfiguration(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := NewSession(left, Config{}, Resume{}); err == nil {
		t.Fatal("NewSession accepted zero limits")
	}
}
