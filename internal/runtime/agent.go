package runtime

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
)

type Agent struct {
	config  Config
	adapter PolicyAdapter
	dialer  net.Dialer
}

var ErrDryRunPolicy = errors.New("runtime: policy observed in dry-run mode and was not acknowledged")

func NewAgent(config Config, adapter PolicyAdapter) (*Agent, error) {
	if adapter == nil {
		if !config.DryRun {
			return nil, errors.New("runtime: policy adapter is required when apply mode is enabled")
		}
		adapter = &DryRunAdapter{}
	}
	if err := config.validateCommon(); err != nil {
		return nil, err
	}
	if err := config.validateAgent(); err != nil {
		return nil, err
	}
	return &Agent{config: config, adapter: adapter}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	cursor, err := loadCursor(a.config.CursorFile)
	if err != nil {
		return err
	}
	delay := a.config.ReconnectMin
	for {
		connection, err := a.dialer.DialContext(ctx, "tcp", a.config.SyncServerAddress)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !sleepContext(ctx, jitter(delay)) {
				return nil
			}
			delay = min(delay*2, a.config.ReconnectMax)
			continue
		}
		delay = a.config.ReconnectMin
		session, err := agentrpc.NewSession(connection, agentrpc.Config{MaxMessageBytes: a.config.SyncMaxMessageBytes, MaxInFlight: a.config.SyncMaxInFlight}, agentrpc.Resume{AppliedCursor: cursor})
		if err == nil {
			err = a.consume(ctx, session, &cursor)
		}
		closeErr := connection.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("runtime: close policy-sync connection: %w", closeErr)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !sleepContext(ctx, jitter(delay)) {
			return nil
		}
		delay = min(delay*2, a.config.ReconnectMax)
	}
}

func (a *Agent) consume(ctx context.Context, session *agentrpc.Session, cursor *uint64) error {
	for {
		message, err := session.Receive(ctx)
		if err != nil {
			return err
		}
		if message.Type != agentrpc.TypePolicy || message.Policy == nil {
			continue
		}
		if err := a.adapter.Apply(ctx, *message.Policy); err != nil {
			return fmt.Errorf("runtime: apply policy: %w", err)
		}
		if a.config.DryRun {
			return ErrDryRunPolicy
		}
		if err := saveCursor(a.config.CursorFile, message.Sequence); err != nil {
			return err
		}
		if err := session.Ack(ctx, message.Sequence); err != nil {
			*cursor = session.AppliedCursor()
			return fmt.Errorf("runtime: acknowledge policy: %w", err)
		}
		*cursor = session.AppliedCursor()
	}
}

func jitter(delay time.Duration) time.Duration {
	if delay <= time.Millisecond {
		return delay
	}
	half := delay / 2
	return half + time.Duration(rand.Int64N(int64(delay-half)+1))
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
