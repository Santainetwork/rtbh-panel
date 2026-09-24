package runtime

import (
	"context"
	"sync/atomic"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
)

type PolicyAdapter interface {
	Apply(context.Context, agentrpc.PolicyChange) error
}

// DryRunAdapter deliberately performs no route, shell, or external side effect.
type DryRunAdapter struct {
	observed atomic.Uint64
}

func (a *DryRunAdapter) Apply(context.Context, agentrpc.PolicyChange) error {
	a.observed.Add(1)
	return nil
}

// Applied is always zero because this adapter never applies externally.
func (*DryRunAdapter) Applied() uint64 { return 0 }

func (a *DryRunAdapter) Observed() uint64 { return a.observed.Load() }
