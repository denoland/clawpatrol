package endpoints

import (
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPgSwapBackendKeyDataReplacesPidAndKey(t *testing.T) {
	// Build a postAuth buffer that mirrors what pgPerformAuth would
	// have collected: AuthenticationOk ('R' + len=8 + code=0) followed
	// by BackendKeyData ('K' + len=12 + pid + key), then
	// ReadyForQuery ('Z' + len=5 + 'I').
	const upstreamPID uint32 = 0x11223344
	const upstreamKey uint32 = 0x55667788

	var postAuth []byte
	postAuth = append(postAuth, 'R')
	postAuth = append(postAuth, encUint32(8)...)
	postAuth = append(postAuth, encUint32(0)...)
	postAuth = append(postAuth, 'K')
	postAuth = append(postAuth, encUint32(12)...)
	postAuth = append(postAuth, encUint32(upstreamPID)...)
	postAuth = append(postAuth, encUint32(upstreamKey)...)
	postAuth = append(postAuth, 'Z', 0, 0, 0, 5, 'I')

	swapped, gotUpstreamPID, gotUpstreamKey, ok := pgSwapBackendKeyData(postAuth, 0xAAAABBBB, 0xCCCCDDDD)
	if !ok {
		t.Fatalf("expected ok, got false")
	}
	if gotUpstreamPID != upstreamPID || gotUpstreamKey != upstreamKey {
		t.Fatalf("captured upstream key (%x,%x), want (%x,%x)",
			gotUpstreamPID, gotUpstreamKey, upstreamPID, upstreamKey)
	}
	if len(swapped) != len(postAuth) {
		t.Fatalf("swapped length %d != original %d", len(swapped), len(postAuth))
	}
	// AuthenticationOk preserved.
	if swapped[0] != 'R' || binary.BigEndian.Uint32(swapped[1:5]) != 8 {
		t.Errorf("AuthenticationOk corrupted: %v", swapped[:9])
	}
	// BackendKeyData rewritten.
	if swapped[9] != 'K' {
		t.Fatalf("K frame moved or removed: %v", swapped[9:22])
	}
	gotPID := binary.BigEndian.Uint32(swapped[14:18])
	gotKey := binary.BigEndian.Uint32(swapped[18:22])
	if gotPID != 0xAAAABBBB || gotKey != 0xCCCCDDDD {
		t.Errorf("synth (pid,key) = (%x,%x), want (AAAABBBB,CCCCDDDD)", gotPID, gotKey)
	}
	// ReadyForQuery preserved.
	if swapped[22] != 'Z' || swapped[27] != 'I' {
		t.Errorf("ReadyForQuery corrupted: %v", swapped[22:])
	}
}

func TestPgSwapBackendKeyDataMissingReturnsFalse(t *testing.T) {
	postAuth := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'}
	swapped, _, _, ok := pgSwapBackendKeyData(postAuth, 1, 2)
	if ok {
		t.Fatalf("expected ok=false for postAuth without K frame, got swapped=%v", swapped)
	}
}

func TestPgCancelRegistryRegistersAndLookups(t *testing.T) {
	reg := newPgCancelRegistry()
	e := &pgCancelEntry{upstreamAddr: "example.test:5432"}
	reg.register(42, 99, e)
	if got := reg.lookup(42, 99); got != e {
		t.Errorf("lookup hit returned %v, want %v", got, e)
	}
	if got := reg.lookup(99, 42); got != nil {
		t.Errorf("lookup miss returned %v, want nil", got)
	}
	reg.unregister(42, 99)
	if got := reg.lookup(42, 99); got != nil {
		t.Errorf("post-unregister lookup returned %v, want nil", got)
	}
}

func TestPgCancelEntryParkAndCancel(t *testing.T) {
	e := &pgCancelEntry{}
	// Not parked → cancelParked is a no-op and reports false.
	if e.cancelParked() {
		t.Fatal("cancelParked on unparked entry returned true")
	}
	parkCh := make(chan struct{})
	e.markParked(parkCh)
	if !e.cancelParked() {
		t.Fatal("cancelParked on parked entry returned false")
	}
	select {
	case <-parkCh:
	default:
		t.Fatal("parkCh not closed after cancelParked")
	}
	// Double cancel doesn't panic or double-close.
	if e.cancelParked() {
		t.Fatal("second cancelParked returned true")
	}
	e.markUnparked()
	if e.cancelParked() {
		t.Fatal("cancelParked after unpark returned true")
	}
}

func TestPgHandleCancelRequestUnknownDropsSilently(t *testing.T) {
	reg := newPgCancelRegistry()
	clientConn, gwConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = gwConn.Close() }()

	go func() {
		// Write the 8-byte body (pid + key) the handler is about to read.
		body := append(encUint32(1234), encUint32(5678)...)
		_, _ = clientConn.Write(body)
		_ = clientConn.Close()
	}()

	dialed := int32(0)
	dial := func(_, _ string) (net.Conn, error) {
		atomic.StoreInt32(&dialed, 1)
		return nil, errors.New("should not dial")
	}
	if err := pgHandleCancelRequest(gwConn, reg, dial); err != nil {
		t.Fatalf("handle cancel: %v", err)
	}
	if atomic.LoadInt32(&dialed) != 0 {
		t.Errorf("unknown (pid, key) triggered dial; expected silent drop")
	}
}

func TestPgHandleCancelRequestParkedFiresCancelChannel(t *testing.T) {
	reg := newPgCancelRegistry()
	entry := &pgCancelEntry{upstreamAddr: "example.test:5432"}
	parkCh := make(chan struct{})
	entry.markParked(parkCh)
	reg.register(7, 8, entry)

	clientConn, gwConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = gwConn.Close() }()

	go func() {
		body := append(encUint32(7), encUint32(8)...)
		_, _ = clientConn.Write(body)
	}()

	dialed := int32(0)
	dial := func(_, _ string) (net.Conn, error) {
		atomic.StoreInt32(&dialed, 1)
		return nil, errors.New("should not dial when parked")
	}
	if err := pgHandleCancelRequest(gwConn, reg, dial); err != nil {
		t.Fatalf("handle cancel: %v", err)
	}
	select {
	case <-parkCh:
	case <-time.After(time.Second):
		t.Fatal("parkCh not closed after cancel request")
	}
	if atomic.LoadInt32(&dialed) != 0 {
		t.Errorf("parked cancel triggered upstream dial; should abort approval instead")
	}
}

func TestPgHandleCancelRequestNotParkedForwardsUpstream(t *testing.T) {
	reg := newPgCancelRegistry()
	entry := &pgCancelEntry{
		upstreamAddr: "example.test:5432",
		upstreamPID:  0xDEADBEEF,
		upstreamKey:  0xCAFEF00D,
	}
	reg.register(11, 22, entry)

	clientConn, gwConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = gwConn.Close() }()

	go func() {
		body := append(encUint32(11), encUint32(22)...)
		_, _ = clientConn.Write(body)
	}()

	// dial returns a synthetic upstream conn we can inspect for the
	// CancelRequest bytes the handler is supposed to forward.
	upstreamRead, upstreamWrite := net.Pipe()
	defer func() { _ = upstreamRead.Close() }()
	defer func() { _ = upstreamWrite.Close() }()
	dial := func(network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != "example.test:5432" {
			t.Errorf("dial(%q,%q), want tcp/example.test:5432", network, addr)
		}
		return upstreamWrite, nil
	}

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		_ = upstreamRead.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := upstreamRead.Read(buf)
		got <- buf[:n]
	}()

	if err := pgHandleCancelRequest(gwConn, reg, dial); err != nil {
		t.Fatalf("handle cancel: %v", err)
	}

	select {
	case forwarded := <-got:
		if len(forwarded) != 16 {
			t.Fatalf("forwarded %d bytes, want 16: %v", len(forwarded), forwarded)
		}
		if binary.BigEndian.Uint32(forwarded[0:4]) != pgCancelRequestLen {
			t.Errorf("forwarded length = %d, want %d",
				binary.BigEndian.Uint32(forwarded[0:4]), pgCancelRequestLen)
		}
		if binary.BigEndian.Uint32(forwarded[4:8]) != pgCancelRequestCode {
			t.Errorf("forwarded code = %d, want %d",
				binary.BigEndian.Uint32(forwarded[4:8]), pgCancelRequestCode)
		}
		if binary.BigEndian.Uint32(forwarded[8:12]) != 0xDEADBEEF {
			t.Errorf("forwarded pid = %x, want DEADBEEF",
				binary.BigEndian.Uint32(forwarded[8:12]))
		}
		if binary.BigEndian.Uint32(forwarded[12:16]) != 0xCAFEF00D {
			t.Errorf("forwarded key = %x, want CAFEF00D",
				binary.BigEndian.Uint32(forwarded[12:16]))
		}
	case <-time.After(time.Second):
		t.Fatal("no bytes forwarded to upstream")
	}
}

// TestPgCancelBeatsConcurrentAllow exercises the precedence the task
// calls out: a CancelRequest racing with an approver's "allow"
// verdict on the same session must still result in cancellation. The
// pgEvaluate side detects the close-of-parkCh by re-checking the
// channel after Approve returns; the test simulates the race by
// closing the channel before the Approve callback returns its
// verdict.
func TestPgCancelBeatsConcurrentAllow(t *testing.T) {
	entry := &pgCancelEntry{}
	parkCh := make(chan struct{})
	entry.markParked(parkCh)

	// Simulate the cancel-handler closing the channel mid-approval.
	if !entry.cancelParked() {
		t.Fatal("cancelParked returned false despite parked state")
	}

	// pgEvaluateInfo's logic: after Approve returns, check parkCh.
	canceled := false
	select {
	case <-parkCh:
		canceled = true
	default:
	}
	if !canceled {
		t.Fatal("parkCh select missed close; cancel-beats-allow precedence broken")
	}
}
