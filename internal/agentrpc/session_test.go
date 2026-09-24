package agentrpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testConfig() Config { return Config{MaxMessageBytes: 1024, MaxInFlight: 2} }

func writeTestFrame(t *testing.T, conn net.Conn, message Message) {
	t.Helper()
	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := conn.Write(append(header[:], payload...)); err != nil {
		t.Error(err)
	}
}

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
		ID: "policy-1", IdempotencyKey: "request-1", Operation: "add", List: "blocklist", Prefix: "203.0.113.0/24",
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
		writeTestFrame(t, clientConn, Message{Type: TypePolicy, Sequence: 1, Policy: &PolicyChange{ID: "policy-1", IdempotencyKey: "request-1", Operation: "add", List: "blocklist", Prefix: "192.0.2.0/24"}})
		writeTestFrame(t, clientConn, Message{Type: TypePolicy, Sequence: 2, Policy: &PolicyChange{ID: "policy-2", IdempotencyKey: "request-2", Operation: "add", List: "blocklist", Prefix: "198.51.100.0/24"}})
	}()
	ackResult := make(chan Message, 1)
	go func() {
		var header [4]byte
		var ack Message
		_, _ = io.ReadFull(clientConn, header[:])
		payload := make([]byte, binary.BigEndian.Uint32(header[:]))
		_, _ = io.ReadFull(clientConn, payload)
		_ = json.Unmarshal(payload, &ack)
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
		var header [4]byte
		_, _ = io.ReadFull(peerConn, header[:])
		_, _ = io.CopyN(io.Discard, peerConn, int64(binary.BigEndian.Uint32(header[:])))
		close(read)
	}()
	if _, err := client.SendPolicy(context.Background(), PolicyChange{ID: "policy-1", IdempotencyKey: "request-1", Operation: "add", List: "blocklist", Prefix: "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	<-read
	if _, err := client.SendPolicy(context.Background(), PolicyChange{ID: "policy-2", IdempotencyKey: "request-2", Operation: "add", List: "blocklist", Prefix: "198.51.100.0/24"}); !errors.Is(err, ErrBackpressure) {
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
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 33)
		_, _ = clientConn.Write(header[:])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := server.Receive(ctx); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Receive() error = %v, want ErrMessageTooLarge", err)
	}
}

func TestSendPolicyUsesLengthPrefixedJSON(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	client, err := NewSession(clientConn, testConfig(), Resume{})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		var header [4]byte
		if _, err := io.ReadFull(peerConn, header[:]); err != nil {
			done <- err
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > uint32(testConfig().MaxMessageBytes) {
			done <- errors.New("invalid frame size")
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(peerConn, payload); err != nil {
			done <- err
			return
		}
		var message Message
		if err := json.Unmarshal(payload, &message); err != nil {
			done <- err
			return
		}
		if message.Type != TypePolicy || message.Sequence != 1 {
			done <- errors.New("unexpected frame")
			return
		}
		done <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.SendPolicy(ctx, PolicyChange{ID: "policy-1", IdempotencyKey: "request-1", Operation: "add", List: "blocklist", Prefix: "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
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

func TestPolicyValidationRequiresIdempotencyKey(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	session, err := NewSession(left, testConfig(), Resume{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.SendPolicy(context.Background(), PolicyChange{
		Operation: "replace",
		List:      "blocklist",
		Prefix:    "192.0.2.0/24",
	}); err == nil {
		t.Fatal("SendPolicy accepted an empty idempotency key")
	}
}

func TestPolicyValidationAcceptsProtocolOperations(t *testing.T) {
	for _, operation := range []string{"replace", "delete"} {
		t.Run(operation, func(t *testing.T) {
			if err := validatePolicy(PolicyChange{
				ID:             "edge-a",
				IdempotencyKey: operation + "-42",
				Operation:      operation,
				List:           "blocklist",
				Prefix:         "192.0.2.0/24",
			}); err != nil {
				t.Fatalf("validatePolicy() error = %v", err)
			}
		})
	}
}
