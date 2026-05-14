package approvers

// dashboard approver: built-in, no HCL block. `approve = [dashboard]`
// works without any explicit declaration. pool.Add → wait for the
// dashboard's PUT /api/hitl/decide. No external notification —
// operator sees the pending entry on the HITL panel directly.

import (
	"context"
	"fmt"

	"github.com/denoland/clawpatrol/config/runtime"
)

// DashboardApprover is part of the clawpatrol plugin API.
type DashboardApprover struct{}

// Approve is part of the clawpatrol plugin API.
func (DashboardApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if req.Pool == nil {
		return runtime.ApproveVerdict{}, fmt.Errorf("dashboard approver: no pool")
	}
	pending := buildPending(req)
	id, ch := req.Pool.Add(pending)
	defer req.Pool.Discard(id)
	select {
	case d := <-ch:
		return runtime.ApproveVerdict{
			Decision: decision(d.Allow),
			Reason:   d.Reason,
			By:       d.By,
		}, nil
	case <-ctx.Done():
		state, reason := hitlCancelStateForContext(ctx.Err())
		cancelPending(req.Pool, id, state, reason)
		return runtime.ApproveVerdict{}, ctx.Err()
	}
}
