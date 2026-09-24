// Package agentrpc implements the policy-sync transport between server and agent.
// It never carries BGP sessions or BGP protocol messages.
package agentrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	TypePolicy = "policy"
	TypeACK    = "ack"
)

var (
	ErrBackpressure    = errors.New("policy sync backpressure limit reached")
	ErrMessageTooLarge = errors.New("policy sync message too large")
)

type Config struct {
	MaxMessageBytes int
	MaxInFlight     int
}

// Resume restores durable cursors after reconnect. NextSequence defaults to
// PeerCursor + 1, so acknowledged outbound updates are not retransmitted.
type Resume struct {
	AppliedCursor uint64
	PeerCursor    uint64
	NextSequence  uint64
}

type PolicyChange struct {
	Operation string `json:"operation"`
	List      string `json:"list"`
	Prefix    string `json:"prefix"`
}

type Message struct {
	Type     string        `json:"type"`
	Sequence uint64        `json:"sequence,omitempty"`
	Cursor   uint64        `json:"cursor,omitempty"`
	Policy   *PolicyChange `json:"policy,omitempty"`
}

// Session is safe for one concurrent reader and one or more writers.
type Session struct {
	conn   net.Conn
	config Config
	reader *bufio.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex
	stateMu sync.Mutex

	nextSequence  uint64
	appliedCursor uint64
	peerCursor    uint64
	pending       map[uint64]struct{}
}

func NewSession(conn net.Conn, config Config, resume Resume) (*Session, error) {
	if conn == nil {
		return nil, errors.New("policy sync connection is required")
	}
	if config.MaxMessageBytes < 1 || config.MaxInFlight < 1 {
		return nil, errors.New("policy sync limits must be positive")
	}
	next := resume.NextSequence
	if next == 0 {
		next = resume.PeerCursor + 1
	}
	if next <= resume.PeerCursor {
		return nil, errors.New("next sequence must exceed peer cursor")
	}
	return &Session{
		conn:          conn,
		config:        config,
		reader:        bufio.NewReaderSize(conn, config.MaxMessageBytes+1),
		nextSequence:  next,
		appliedCursor: resume.AppliedCursor,
		peerCursor:    resume.PeerCursor,
		pending:       make(map[uint64]struct{}),
	}, nil
}

func (s *Session) SendPolicy(ctx context.Context, change PolicyChange) (uint64, error) {
	if err := validatePolicy(change); err != nil {
		return 0, err
	}

	s.stateMu.Lock()
	if len(s.pending) >= s.config.MaxInFlight {
		s.stateMu.Unlock()
		return 0, ErrBackpressure
	}
	sequence := s.nextSequence
	s.nextSequence++
	s.pending[sequence] = struct{}{}
	s.stateMu.Unlock()

	if err := s.write(ctx, Message{Type: TypePolicy, Sequence: sequence, Policy: &change}); err != nil {
		s.stateMu.Lock()
		delete(s.pending, sequence)
		s.stateMu.Unlock()
		return 0, err
	}
	return sequence, nil
}

// Receive returns the next new policy or ACK. Already-applied policies are
// ACKed automatically and skipped, providing idempotent reconnect replay.
func (s *Session) Receive(ctx context.Context) (Message, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		message, err := s.read(ctx)
		if err != nil {
			return Message{}, err
		}
		switch message.Type {
		case TypeACK:
			if message.Cursor == 0 {
				return Message{}, errors.New("policy sync ACK cursor must be non-zero")
			}
			s.stateMu.Lock()
			if message.Cursor > s.peerCursor {
				s.peerCursor = message.Cursor
				for sequence := range s.pending {
					if sequence <= message.Cursor {
						delete(s.pending, sequence)
					}
				}
			}
			s.stateMu.Unlock()
			return message, nil
		case TypePolicy:
			if message.Policy == nil || message.Sequence == 0 {
				return Message{}, errors.New("policy sync policy message is incomplete")
			}
			if err := validatePolicy(*message.Policy); err != nil {
				return Message{}, err
			}
			s.stateMu.Lock()
			cursor := s.appliedCursor
			s.stateMu.Unlock()
			if message.Sequence <= cursor {
				if err := s.write(ctx, Message{Type: TypeACK, Cursor: cursor}); err != nil {
					return Message{}, err
				}
				continue
			}
			if message.Sequence != cursor+1 {
				return Message{}, fmt.Errorf("policy sync sequence gap: got %d after %d", message.Sequence, cursor)
			}
			return message, nil
		default:
			return Message{}, fmt.Errorf("unknown policy sync message type %q", message.Type)
		}
	}
}

// Ack commits one successfully applied inbound sequence and sends its cursor.
func (s *Session) Ack(ctx context.Context, sequence uint64) error {
	s.stateMu.Lock()
	if sequence != s.appliedCursor+1 {
		s.stateMu.Unlock()
		return fmt.Errorf("policy sync ACK sequence %d does not follow cursor", sequence)
	}
	s.appliedCursor = sequence
	s.stateMu.Unlock()
	if err := s.write(ctx, Message{Type: TypeACK, Cursor: sequence}); err != nil {
		// Cursor remains advanced. Retrying the same policy triggers an automatic
		// ACK, preserving apply-at-most-once semantics after a broken connection.
		return err
	}
	return nil
}

func (s *Session) PeerCursor() uint64 {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.peerCursor
}

func (s *Session) AppliedCursor() uint64 {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.appliedCursor
}

func (s *Session) read(ctx context.Context) (Message, error) {
	stop := setDeadline(ctx, s.conn.SetReadDeadline)
	defer stop()
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.config.MaxMessageBytes {
		return Message{}, ErrMessageTooLarge
	}
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Message{}, io.EOF
		}
		if ctx.Err() != nil {
			return Message{}, ctx.Err()
		}
		return Message{}, fmt.Errorf("read policy sync message: %w", err)
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Message{}, errors.New("empty policy sync message")
	}
	var message Message
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return Message{}, fmt.Errorf("decode policy sync message: %w", err)
	}
	return message, nil
}

func (s *Session) write(ctx context.Context, message Message) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode policy sync message: %w", err)
	}
	data = append(data, '\n')
	if len(data) > s.config.MaxMessageBytes {
		return ErrMessageTooLarge
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	stop := setDeadline(ctx, s.conn.SetWriteDeadline)
	defer stop()
	if _, err := s.conn.Write(data); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("write policy sync message: %w", err)
	}
	return nil
}

func setDeadline(ctx context.Context, setter func(time.Time) error) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = setter(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = setter(time.Now()) })
	return func() {
		stop()
		_ = setter(time.Time{})
	}
}

func validatePolicy(change PolicyChange) error {
	if change.Operation != "add" && change.Operation != "remove" {
		return errors.New("policy operation must be add or remove")
	}
	if change.List != "blocklist" && change.List != "whitelist" {
		return errors.New("policy list must be blocklist or whitelist")
	}
	prefix, err := netip.ParsePrefix(change.Prefix)
	if err != nil || prefix != prefix.Masked() {
		return errors.New("policy prefix must be a canonical CIDR")
	}
	return nil
}
