package extplugin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Brokered dial: an endpoint plugin asks the gateway to open an
// upstream connection on its behalf (DialUpstreamRequest frames on
// the HandleConn stream). The plugin process needs no network of its
// own; the gateway validates the target against operator-written
// HCL, routes through the endpoint's bound tunnel, optionally
// terminates upstream TLS, and audits every attempt.
const (
	// maxBrokeredDialsPerConn bounds concurrently open brokered
	// upstream connections per agent connection.
	maxBrokeredDialsPerConn = 16
	// brokeredDialTimeout bounds connect + TLS handshake.
	brokeredDialTimeout = 15 * time.Second
	// brokeredDialIdleTimeout closes an upstream conn that has moved
	// no bytes in either direction for this long.
	brokeredDialIdleTimeout = 5 * time.Minute
	brokeredDialChunk       = 32 * 1024
	brokeredWriteQueueDepth = 32
)

// brokeredDial is one gateway-held upstream connection serving a
// plugin's DialUpstreamRequest.
type brokeredDial struct {
	id     string
	writeQ chan []byte
	done   chan struct{}

	mu sync.Mutex
	up net.Conn // set once the dial completes

	closeOnce sync.Once
}

func (d *brokeredDial) setConn(c net.Conn) {
	d.mu.Lock()
	d.up = c
	d.mu.Unlock()
}

func (d *brokeredDial) conn() net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.up
}

// close releases the dial: signals both pump goroutines and closes
// the upstream conn if one was established. Idempotent.
func (d *brokeredDial) close() {
	d.closeOnce.Do(func() {
		close(d.done)
		if c := d.conn(); c != nil {
			_ = c.Close()
		}
	})
}

// dialRegistry tracks the open brokered dials of one HandleConn
// stream.
type dialRegistry struct {
	mu     sync.Mutex
	m      map[string]*brokeredDial
	closed bool
}

func newDialRegistry() *dialRegistry {
	return &dialRegistry{m: map[string]*brokeredDial{}}
}

// add registers a new dial slot. Errors when the registry has been
// closed (the stream is tearing down), the id is taken, or the
// concurrency cap is reached. Refusing after close closes the race
// where a handleDialRequest goroutine spawned just before closeAll
// would otherwise open an upstream that nothing tracks or tears down.
func (r *dialRegistry) add(id string) (*brokeredDial, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, fmt.Errorf("connection is closing")
	}
	if id == "" {
		return nil, fmt.Errorf("empty dial_id")
	}
	if _, dup := r.m[id]; dup {
		return nil, fmt.Errorf("dial_id %q already in use", id)
	}
	if len(r.m) >= maxBrokeredDialsPerConn {
		return nil, fmt.Errorf("too many concurrent brokered dials (max %d)", maxBrokeredDialsPerConn)
	}
	d := &brokeredDial{
		id:     id,
		writeQ: make(chan []byte, brokeredWriteQueueDepth),
		done:   make(chan struct{}),
	}
	r.m[id] = d
	return d, nil
}

func (r *dialRegistry) get(id string) *brokeredDial {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}

func (r *dialRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
}

// closeAll tears down every open dial; called when the HandleConn
// stream ends.
func (r *dialRegistry) closeAll() {
	r.mu.Lock()
	r.closed = true
	dials := make([]*brokeredDial, 0, len(r.m))
	for _, d := range r.m {
		dials = append(dials, d)
	}
	r.m = map[string]*brokeredDial{}
	r.mu.Unlock()
	for _, d := range dials {
		d.close()
	}
}

// checkDialTarget validates one `dial = [...]` entry at config
// decode time: "host:port" or "*.suffix.tld:port", port required and
// numeric.
func checkDialTarget(entry string) error {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		return fmt.Errorf("expected \"host:port\" or \"*.suffix:port\": %w", err)
	}
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q must be numeric (1-65535)", port)
	}
	if strings.HasPrefix(host, "*") && !strings.HasPrefix(host, "*.") {
		return fmt.Errorf("wildcard must take the form \"*.suffix.tld\"")
	}
	if strings.Count(host, "*") > 1 || strings.Contains(strings.TrimPrefix(host, "*."), "*") {
		return fmt.Errorf("only one leading \"*.\" wildcard label is supported")
	}
	return nil
}

// validateBrokeredDialTarget decides whether a plugin-requested dial
// target is legitimate for this connection. Allowed iff it matches:
//
//  1. the exact (host, port) the agent originally dialed,
//  2. an entry of the endpoint's operator-written `hosts` list
//     ("h:p" exact; bare "h" with the agent's dst port or 443/80), or
//  3. an entry of the operator-written `dial` allow-list
//     ("host:port" exact, "*.suffix.tld:port" wildcard).
//
// Plugin-controlled data (canonical JSON) is deliberately not
// consulted: a malicious plugin must not be able to mint its own
// dial permissions.
func validateBrokeredDialTarget(ch *runtime.ConnHandle, hosts, dialTargets []string, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("addr %q: expected \"host:port\": %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("addr %q: invalid port", addr)
	}
	host = strings.ToLower(host)

	// (1) the agent's original target.
	if ch.UpstreamHost != "" && host == strings.ToLower(ch.UpstreamHost) && port == int(ch.DstPort) {
		return nil
	}

	// (2) the endpoint's hosts list.
	for _, h := range hosts {
		hh, hp, perr := net.SplitHostPort(h)
		if perr != nil {
			hh, hp = h, ""
		}
		if !strings.EqualFold(hh, host) {
			continue
		}
		if hp == "" {
			if port == int(ch.DstPort) || port == 443 || port == 80 {
				return nil
			}
			continue
		}
		if hp == portStr {
			return nil
		}
	}

	// (3) the dial allow-list.
	for _, d := range dialTargets {
		dh, dp, derr := net.SplitHostPort(d)
		if derr != nil || dp != portStr {
			continue
		}
		dh = strings.ToLower(dh)
		if suffix, ok := strings.CutPrefix(dh, "*"); ok {
			// suffix starts with "." — checkDialTarget enforced the
			// "*." shape, so "*.x.y" matches "a.x.y" but not "x.y".
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return nil
			}
			continue
		}
		if dh == host {
			return nil
		}
	}

	return fmt.Errorf("target %q is not permitted for endpoint %q: not the agent's original target, not in the endpoint's hosts, and not in its dial allow-list", addr, chEndpointName(ch))
}

func chEndpointName(ch *runtime.ConnHandle) string {
	if ch.Endpoint == nil {
		return ""
	}
	return ch.Endpoint.Name
}

// handleDialRequest services one DialUpstreamRequest off the recv
// loop: validate, dial (through the endpoint's tunnel via
// ch.DialUpstream*), audit, reply, then pump bytes until either side
// closes. Every attempt — refused, failed, or allowed — lands on the
// event sink so brokered dials are auditable.
func handleDialRequest(ctx context.Context, ch *runtime.ConnHandle, reg *dialRegistry, req *pb.DialUpstreamRequest, doSend func(*pb.ConnMessage) error) {
	emit := func(action, reason string) {
		if ch.Emit == nil {
			return
		}
		ch.Emit(runtime.ConnEvent{
			Action:  action,
			Reason:  reason,
			Verb:    "dial",
			Summary: req.Network + " " + req.Addr,
		})
	}
	refuse := func(action, reason string) {
		emit(action, reason)
		_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialReply{DialReply: &pb.DialUpstreamReply{
			DialId: req.DialId, Error: reason,
		}}})
	}

	if req.Network != "tcp" {
		refuse("deny", fmt.Sprintf("network %q not supported for brokered dial (tcp only)", req.Network))
		return
	}
	var hosts, dialTargets []string
	if body, ok := ch.Endpoint.Body.(*dynamicEndpointBody); ok {
		hosts, dialTargets = body.hosts, body.dialTargets
	}
	if err := validateBrokeredDialTarget(ch, hosts, dialTargets, req.Addr); err != nil {
		refuse("deny", err.Error())
		return
	}
	if ch.DialUpstream == nil {
		refuse("error", "host has no upstream dialer wired")
		return
	}

	d, err := reg.add(req.DialId)
	if err != nil {
		refuse("deny", err.Error())
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, brokeredDialTimeout)
	up, err := dialBrokeredUpstream(dialCtx, ch, req)
	cancel()
	if err != nil {
		reg.remove(req.DialId)
		d.close()
		refuse("error", fmt.Sprintf("dial %s: %v", req.Addr, err))
		return
	}
	d.setConn(up)

	// The done channel may already be closed (the stream tore down
	// while we were dialing). A real upstream was opened, so audit it
	// before dropping it.
	select {
	case <-d.done:
		emit("allow", "connection closed before use")
		_ = up.Close()
		reg.remove(req.DialId)
		return
	default:
	}

	emit("allow", "")
	if err := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialReply{DialReply: &pb.DialUpstreamReply{
		DialId: req.DialId,
	}}}); err != nil {
		reg.remove(req.DialId)
		d.close()
		return
	}

	// upstream -> plugin
	go func() {
		defer func() {
			reg.remove(req.DialId)
			d.close()
		}()
		buf := make([]byte, brokeredDialChunk)
		for {
			_ = up.SetReadDeadline(time.Now().Add(brokeredDialIdleTimeout))
			n, err := up.Read(buf)
			if n > 0 {
				if serr := doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialData{DialData: &pb.DialUpstreamData{
					DialId: req.DialId, Payload: append([]byte(nil), buf[:n]...),
				}}}); serr != nil {
					return
				}
			}
			if err != nil {
				_ = doSend(&pb.ConnMessage{Kind: &pb.ConnMessage_DialClose{DialClose: &pb.DialUpstreamClose{
					DialId: req.DialId, Reason: dialCloseReason(err),
				}}})
				return
			}
		}
	}()

	// plugin -> upstream (frames arrive via the recv loop, which
	// pushes into writeQ)
	go func() {
		for {
			select {
			case p := <-d.writeQ:
				if _, err := up.Write(p); err != nil {
					d.close()
					return
				}
				// Bidirectional activity keeps the conn alive: a
				// write refreshes the read deadline the reader set.
				_ = up.SetReadDeadline(time.Now().Add(brokeredDialIdleTimeout))
			case <-d.done:
				return
			}
		}
	}()
}

// dialBrokeredUpstream opens the upstream connection, with
// gateway-terminated TLS when the plugin asked for it. Routing
// through the endpoint's bound tunnel happens inside the host's
// DialUpstream / DialUpstreamTLS callbacks.
func dialBrokeredUpstream(ctx context.Context, ch *runtime.ConnHandle, req *pb.DialUpstreamRequest) (net.Conn, error) {
	if !req.Tls {
		return ch.DialUpstream(ctx, req.Network, req.Addr)
	}
	serverName := req.TlsServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(req.Addr)
		if err != nil {
			return nil, fmt.Errorf("addr %q: %w", req.Addr, err)
		}
		serverName = host
	}
	if ch.DialUpstreamTLS != nil {
		return ch.DialUpstreamTLS(ctx, req.Network, req.Addr, serverName)
	}
	raw, err := ch.DialUpstream(ctx, req.Network, req.Addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialCloseReason maps an upstream read error to the reason string
// shipped on DialUpstreamClose. Clean shutdown shapes (EOF, conn
// closed by our own teardown) read as a clean close; anything else
// (including the idle-timeout deadline) is surfaced to the plugin.
func dialCloseReason(err error) string {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return ""
	}
	return err.Error()
}
