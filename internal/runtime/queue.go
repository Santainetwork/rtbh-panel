package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
)

type policyQueue struct {
	mu      sync.Mutex
	pending []agentrpc.PolicyChange
	notify  chan struct{}
	nextID  uint64
}

func newPolicyQueue() *policyQueue {
	return &policyQueue{notify: make(chan struct{}, 1)}
}

func (q *policyQueue) publish(mutation dashboard.PolicyMutation) {
	q.mu.Lock()
	q.nextID++
	q.pending = append(q.pending, agentrpc.PolicyChange{
		ID:             fmt.Sprintf("dashboard-%d", q.nextID),
		IdempotencyKey: fmt.Sprintf("dashboard-%d", q.nextID),
		Operation:      mutation.Action,
		List:           mutation.List,
		Prefix:         mutation.Prefix,
	})
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *policyQueue) next(ctx context.Context) (agentrpc.PolicyChange, error) {
	for {
		q.mu.Lock()
		if len(q.pending) > 0 {
			change := q.pending[0]
			q.mu.Unlock()
			return change, nil
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return agentrpc.PolicyChange{}, ctx.Err()
		case <-q.notify:
		}
	}
}

func (q *policyQueue) commit(change agentrpc.PolicyChange) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) > 0 && q.pending[0].IdempotencyKey == change.IdempotencyKey {
		q.pending = q.pending[1:]
	}
}
