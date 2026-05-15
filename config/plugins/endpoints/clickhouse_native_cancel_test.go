package endpoints

import (
	"context"
	"net"
	"testing"
	"time"

	chgoproto "github.com/ClickHouse/ch-go/proto"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/facet"
	"github.com/denoland/clawpatrol/config/runtime"
)

// chCancelPeekFixture pairs a test-controlled agent connection with a
// chApproveCancelState wired into the runtime side. The Approve
// callback blocks on releaseApprove until the test signals it to
// return, so we can exercise the "byte arrives mid-approval" path
// deterministically.
type chCancelPeekFixture struct {
	agent      net.Conn
	runtime    net.Conn
	state      *chApproveCancelState
	released   chan struct{}
	approveRet runtime.ApproveVerdict
}

func newChCancelPeekFixture(t *testing.T, verdict runtime.ApproveVerdict) *chCancelPeekFixture {
	t.Helper()
	agentSide, runtimeSide := net.Pipe()
	released := make(chan struct{})
	mock := &runtime.ConnHandle{
		Conn:     runtimeSide,
		Endpoint: &config.CompiledEndpoint{Name: "fixture", Family: "sql"},
		Approve: func(req runtime.ApproveCallRequest) runtime.ApproveVerdict {
			// Block until released — the test writes its peek byte
			// in between so chApproveCancelState's goroutine has time
			// to consume it.
			select {
			case <-released:
			case <-req.Cancel:
			}
			return verdict
		},
	}
	state := &chApproveCancelState{
		agentReader: chgoproto.NewReader(runtimeSide),
		ch:          mock,
	}
	return &chCancelPeekFixture{
		agent:      agentSide,
		runtime:    runtimeSide,
		state:      state,
		released:   released,
		approveRet: verdict,
	}
}

func (f *chCancelPeekFixture) close() {
	_ = f.agent.Close()
	_ = f.runtime.Close()
}

func TestChApproveCancelStateClientCancelClosesCancelChan(t *testing.T) {
	f := newChCancelPeekFixture(t, runtime.ApproveVerdict{Decision: "allow"})
	defer f.close()

	// Run state.run in a goroutine. The approver inside is parked on
	// req.Cancel | f.released; we expect the peek to fire close on
	// req.Cancel after seeing the cancel byte.
	done := make(chan runtime.ApproveVerdict, 1)
	go func() {
		done <- f.state.run(runtime.ApproveCallRequest{})
	}()

	if _, err := f.agent.Write([]byte{byte(chgoproto.ClientCodeCancel)}); err != nil {
		t.Fatalf("write cancel byte: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state.run did not return after cancel byte arrival")
	}

	if !f.state.canceled {
		t.Errorf("state.canceled = false, want true")
	}
	if f.state.rewound != nil {
		t.Errorf("state.rewound = non-nil for cancel byte; should be swallowed")
	}
}

func TestChApproveCancelStateNonCancelByteRewinds(t *testing.T) {
	f := newChCancelPeekFixture(t, runtime.ApproveVerdict{Decision: "allow"})
	defer f.close()

	done := make(chan runtime.ApproveVerdict, 1)
	go func() {
		done <- f.state.run(runtime.ApproveCallRequest{})
	}()

	// Agent sends a ClientCodeData byte mid-approval (INSERT's
	// trailing data block). chApproveCancelState must NOT treat it
	// as a cancel; instead it should leave canceled=false and
	// surface a rewound reader holding that byte.
	if _, err := f.agent.Write([]byte{byte(chgoproto.ClientCodeData)}); err != nil {
		t.Fatalf("write data byte: %v", err)
	}
	// Give the peek goroutine a moment to consume the byte before we
	// release the approver — otherwise the SetReadDeadline kick fires
	// before the byte lands and we test the wrong path.
	time.Sleep(20 * time.Millisecond)
	close(f.released)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state.run did not return")
	}

	if f.state.canceled {
		t.Errorf("state.canceled = true; want false for non-cancel byte")
	}
	if f.state.rewound == nil {
		t.Fatal("state.rewound = nil; want chRewindReader with the buffered byte")
	}
	b, err := f.state.rewound.UInt8()
	if err != nil {
		t.Fatalf("read rewound byte: %v", err)
	}
	if chgoproto.ClientCode(b) != chgoproto.ClientCodeData {
		t.Errorf("rewound byte = %d, want ClientCodeData (%d)", b, chgoproto.ClientCodeData)
	}
}

func TestChApproveCancelStateNoByteCleanReturn(t *testing.T) {
	f := newChCancelPeekFixture(t, runtime.ApproveVerdict{Decision: "allow"})
	defer f.close()

	done := make(chan runtime.ApproveVerdict, 1)
	go func() {
		done <- f.state.run(runtime.ApproveCallRequest{})
	}()

	// Release approver immediately; the agent sends nothing. The peek
	// goroutine should be interrupted by SetReadDeadline once Approve
	// returns, and state.run should exit cleanly with no cancel and
	// no rewound reader.
	close(f.released)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state.run did not return without a byte")
	}

	if f.state.canceled {
		t.Errorf("state.canceled = true; want false")
	}
	if f.state.rewound != nil {
		t.Errorf("state.rewound = non-nil; want nil when no byte arrived")
	}
}

// TestChEvaluateSQLCancelDuringApprovalReturnsAllowVerdict pins the
// fact that chEvaluateSQL still returns the approver's verdict — the
// "canceled by agent" reason is overlaid by chHandleQuery once it
// inspects approveSt.canceled. Keeping chEvaluateSQL's contract
// minimal here prevents surprising the existing non-cancel tests.
func TestChEvaluateSQLCancelDuringApprovalReturnsAllowVerdict(t *testing.T) {
	approveCondition := "sql.verb == 'drop'"
	approveRule := &config.CompiledRule{
		Name:      "approve-drops",
		Condition: approveCondition,
		Outcome: config.Outcome{
			Approve: []config.ApproveStage{{Name: "human"}},
		},
	}
	m, err := facet.NewMatcher("sql", approveCondition)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	approveRule.Matcher = m
	ep := chBuildEndpoint(t, approveRule)

	mock, _ := chNewMockHandle(t, ep)
	mock.Approve = chMockApprove("allow", "ok")

	verdict, _, _ := chEvaluateSQL(context.Background(), mock.ConnHandle, "DROP TABLE events", "ch-cred", "", false, nil)
	if verdict != "" {
		t.Errorf("approver allow → verdict %q, want empty (chEvaluateSQL no longer overlays cancel reason)", verdict)
	}
}
