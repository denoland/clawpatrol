package endpoints

// Postgres CancelRequest handling.
//
// A postgres `Ctrl+C` does not travel down the existing session's
// connection. The client opens a fresh TCP connection to the gateway
// and sends a CancelRequest message — [int32 length=16][int32
// code=80877102][int32 backend_pid][int32 secret_key]. The gateway
// must:
//
//  1. Recognize the CancelRequest at the same entry point that
//     handles StartupMessage / SSLRequest (HandleConn's first 8 bytes).
//  2. Map (pid, key) to a live session via a process-global registry.
//  3. If the session is parked waiting for HITL approval, abort the
//     approval (so the agent's psql sees the cancel as an error +
//     ReadyForQuery instead of waiting indefinitely).
//  4. Otherwise, forward the cancel to the upstream postgres using the
//     real (pid, key) we captured when relaying the upstream's
//     BackendKeyData. Postgres servers expect this pattern — the
//     CancelRequest connection is one-shot, gets no response, and the
//     server drops it after acting (or ignoring an unknown key).
//
// The session-side (pid, key) we publish to the agent is gateway-
// minted: the gateway picks two random uint32s, rewrites the
// BackendKeyData (the `'K'` post-auth frame) before forwarding it,
// and registers them here keyed on the synth pair. This is also a
// security improvement — the agent never learns the upstream's real
// PID, so an agent that knows another tenant's BackendKeyData can't
// cancel queries it didn't issue.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// pgStartupCodeV3 is the wire protocol version sent by every modern
	// libpq StartupMessage.
	pgStartupCodeV3 uint32 = 196608
	// pgCancelRequestCode is the magic int32 a postgres CancelRequest
	// puts in its protocol-version slot. Sent on a fresh TCP connection
	// to the same TCP port that accepts StartupMessages.
	pgCancelRequestCode uint32 = 80877102
	// pgCancelRequestLen is the fixed total length of a CancelRequest.
	// 4 (length) + 4 (code) + 4 (pid) + 4 (secret_key).
	pgCancelRequestLen uint32 = 16
)

// pgCancelEntry tracks one live postgres session's cancel state.
// Each pgClientToServer pump owns exactly one entry from the moment
// it relays the synthesized BackendKeyData to the agent until
// HandleConn returns.
type pgCancelEntry struct {
	// upstreamAddr is the host:port that upstream was dialed on; the
	// fallback path (session not parked) opens a fresh TCP connection
	// there to forward the CancelRequest.
	upstreamAddr string
	// upstreamPID / upstreamKey are the real BackendKeyData the
	// upstream postgres assigned to this session. Cancel forwarding
	// uses them in the CancelRequest body.
	upstreamPID uint32
	upstreamKey uint32

	mu sync.Mutex
	// parked is true between pgMarkParked and pgMarkUnparked. While
	// parked, an inbound CancelRequest closes parkCancel; otherwise the
	// CancelRequest forwards to upstream.
	parked bool
	// parkCancel is the channel the parking pgEvaluate hands to
	// ch.Approve via ApproveCallRequest.Cancel. Closed at most once;
	// pgEvaluate re-creates it on each park.
	parkCancel chan struct{}
	// closed prevents a double-close of parkCancel when two cancel
	// requests race or when the session itself transitions out of park
	// at the same instant.
	closed bool
}

// markParked records that the session is waiting on HITL. The plugin
// passes parkCancel to the approver chain via ApproveCallRequest.Cancel
// so a subsequent CancelRequest can abort the chain.
func (e *pgCancelEntry) markParked(parkCancel chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.parked = true
	e.parkCancel = parkCancel
	e.closed = false
}

// markUnparked records that the approval call has returned. After
// this, an inbound CancelRequest skips the parkCancel close and falls
// through to the upstream-forward path.
func (e *pgCancelEntry) markUnparked() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.parked = false
	e.parkCancel = nil
}

// cancelParked closes parkCancel if the session is currently parked.
// Returns whether the close happened — callers (the CancelRequest
// handler) use the result to decide between "agent saw a cancel
// already wired through approval" and "forward to upstream as a
// fallback".
func (e *pgCancelEntry) cancelParked() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.parked || e.closed || e.parkCancel == nil {
		return false
	}
	close(e.parkCancel)
	e.closed = true
	return true
}

// pgCancelRegistry holds the (synth pid, synth key) → entry mapping
// for every postgres session in the process. Cancel requests look up
// here from a brand-new TCP connection; sessions register on auth
// completion and deregister on HandleConn exit.
type pgCancelRegistry struct {
	mu sync.Mutex
	m  map[uint64]*pgCancelEntry
}

func newPgCancelRegistry() *pgCancelRegistry {
	return &pgCancelRegistry{m: make(map[uint64]*pgCancelEntry)}
}

func pgRegistryKey(pid, key uint32) uint64 {
	return uint64(pid)<<32 | uint64(key)
}

func (r *pgCancelRegistry) register(pid, key uint32, e *pgCancelEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[pgRegistryKey(pid, key)] = e
}

func (r *pgCancelRegistry) unregister(pid, key uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, pgRegistryKey(pid, key))
}

func (r *pgCancelRegistry) lookup(pid, key uint32) *pgCancelEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[pgRegistryKey(pid, key)]
}

// pgCancelReg is the process-global registry the HandleConn entry
// reads and writes. Tests that need isolation can swap this through
// the test hooks below.
var pgCancelReg = newPgCancelRegistry()

// pgGenerateBackendKey mints a fresh (pid, key) pair the gateway
// publishes to the agent as a synthetic BackendKeyData. Each field is
// 4 random bytes — a 64-bit collision space across concurrent
// sessions, which is comfortably larger than any realistic
// connection-count target. crypto/rand is used because the value is
// also the secret that authorizes a cancel, and a predictable PRNG
// would let one agent guess another's key.
func pgGenerateBackendKey() (pid, key uint32, err error) {
	var b [8]byte
	if _, err = rand.Read(b[:]); err != nil {
		return 0, 0, err
	}
	pid = binary.BigEndian.Uint32(b[0:4])
	key = binary.BigEndian.Uint32(b[4:8])
	return pid, key, nil
}

// pgEncodeBackendKeyData builds a wire `K` frame carrying (pid, key).
// Body layout matches the postgres v3 protocol: int32 pid, int32 key.
func pgEncodeBackendKeyData(pid, key uint32) []byte {
	out := make([]byte, 0, 13)
	out = append(out, 'K')
	out = append(out, encUint32(12)...) // 4 (length) + 4 (pid) + 4 (key)
	out = append(out, encUint32(pid)...)
	out = append(out, encUint32(key)...)
	return out
}

// pgSwapBackendKeyData walks the postAuth byte slice the upstream
// auth handshake collected, finds the upstream's BackendKeyData
// frame, and rewrites it in place with the gateway's synthetic
// (newPID, newKey). Returns the rewritten buffer and the upstream's
// original (pid, key) so the caller can stash them on a pgCancelEntry
// for the forwarding path.
//
// If postAuth does not contain a BackendKeyData (some servers send it
// out of order, future protocol revisions might drop it), returns
// (postAuth, 0, 0, false). The agent then sees no key and cannot
// trigger a cancel — postgres treats missing BackendKeyData as
// "cancellation unavailable", which is the safe fallback.
func pgSwapBackendKeyData(postAuth []byte, newPID, newKey uint32) (out []byte, upstreamPID, upstreamKey uint32, ok bool) {
	// Walk type-prefixed frames: 1B type + 4B length (length includes
	// itself; payload follows). Looking for type 'K' with length=12.
	i := 0
	for i+5 <= len(postAuth) {
		typ := postAuth[i]
		length := binary.BigEndian.Uint32(postAuth[i+1 : i+5])
		if length < 4 || int(length)+1 > len(postAuth)-i {
			return postAuth, 0, 0, false
		}
		frameEnd := i + 1 + int(length)
		if typ == 'K' && length == 12 {
			upstreamPID = binary.BigEndian.Uint32(postAuth[i+5 : i+9])
			upstreamKey = binary.BigEndian.Uint32(postAuth[i+9 : i+13])
			rewritten := make([]byte, 0, len(postAuth))
			rewritten = append(rewritten, postAuth[:i]...)
			rewritten = append(rewritten, pgEncodeBackendKeyData(newPID, newKey)...)
			rewritten = append(rewritten, postAuth[frameEnd:]...)
			return rewritten, upstreamPID, upstreamKey, true
		}
		i = frameEnd
	}
	return postAuth, 0, 0, false
}

// pgReadCancelRequestBody pulls the [pid:4][secret_key:4] payload of
// a CancelRequest message off `r`. The 8-byte head (length + code)
// was already consumed by the HandleConn entry; this is the
// remainder. Returns (0,0,err) on short read.
func pgReadCancelRequestBody(r io.Reader) (pid, key uint32, err error) {
	body := make([]byte, 8)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, 0, err
	}
	pid = binary.BigEndian.Uint32(body[0:4])
	key = binary.BigEndian.Uint32(body[4:8])
	return pid, key, nil
}

// pgHandleCancelRequest dispatches an inbound CancelRequest. The
// caller has already read the 8-byte head; this function reads the
// remaining 8-byte body off `conn`, looks up the (pid, key) in the
// registry, and either aborts the parked approval or forwards the
// cancel upstream. Always returns nil — the only side effects are
// closing the parkCancel chan or dialing upstream; the caller closes
// conn afterwards (CancelRequest has no protocol response).
func pgHandleCancelRequest(conn net.Conn, reg *pgCancelRegistry, dial pgUpstreamDialer) error {
	pid, key, err := pgReadCancelRequestBody(conn)
	if err != nil {
		return fmt.Errorf("read CancelRequest body: %w", err)
	}
	entry := reg.lookup(pid, key)
	if entry == nil {
		// Unknown (pid, key) — silent drop matches postgres-server
		// behavior. An agent that guessed wrong sees the same
		// nothing-happened that a real postgres server would emit.
		return nil
	}
	if entry.cancelParked() {
		// Parked approval aborted; the live session's pgEvaluate
		// turns the resulting non-allow verdict into a pgWriteDeny
		// on the agent's original connection.
		return nil
	}
	// Not parked → the upstream is either running a query the gateway
	// already approved or sitting idle. Forward the cancel so upstream
	// can abort or no-op. pgForwardCancel makes a best-effort attempt
	// on a short deadline; the cancel path stays unobservable to the
	// agent regardless of outcome.
	pgForwardCancel(entry.upstreamAddr, entry.upstreamPID, entry.upstreamKey, dial)
	return nil
}

// pgUpstreamDialer is the dialer signature pgForwardCancel uses to
// open a one-shot TCP connection to the upstream postgres for the
// purpose of sending a CancelRequest. ConnHandle's DialUpstream
// signature matches; tests pass a synthetic dialer to assert
// forwarding without hitting the network.
type pgUpstreamDialer func(network, addr string) (net.Conn, error)

const pgForwardCancelTimeout = 5 * time.Second

// pgForwardCancel opens a fresh TCP connection to upstreamAddr and
// sends one CancelRequest with the real (pid, key) the gateway saw in
// the upstream's BackendKeyData. The connection is closed
// immediately afterwards — CancelRequest is one-shot and gets no
// response per the postgres protocol.
//
// Best-effort: dial / write errors are swallowed (logging is the
// caller's concern). The gateway can't promise the upstream honored
// the cancel; what it promises is that it relayed the request.
func pgForwardCancel(upstreamAddr string, pid, key uint32, dial pgUpstreamDialer) {
	if upstreamAddr == "" {
		return
	}
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, pgForwardCancelTimeout)
		}
	}
	conn, err := dial("tcp", upstreamAddr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(pgForwardCancelTimeout))
	body := make([]byte, 0, 16)
	body = append(body, encUint32(pgCancelRequestLen)...)
	body = append(body, encUint32(pgCancelRequestCode)...)
	body = append(body, encUint32(pid)...)
	body = append(body, encUint32(key)...)
	_, _ = conn.Write(body)
}
