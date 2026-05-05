package endpoints

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

const clickhouseNativeDefaultPort = 9440

type ClickhouseNativeEndpointRuntime struct{}

func (ClickhouseNativeEndpointRuntime) HandleConn(ctx context.Context, ch *runtime.ConnHandle) error {
	defer ch.Conn.Close()
	if ch.Endpoint == nil || ch.Endpoint.Plugin.Type != "clickhouse_native" {
		return fmt.Errorf("clickhouse native runtime invoked on endpoint %v", ch.Endpoint)
	}

	initial, err := chReadInitialHello(ch.Conn)
	if err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return fmt.Errorf("read client hello: %w", err)
	}
	hello, err := chParseHello(initial)
	if err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return fmt.Errorf("parse client hello: %w", err)
	}
	cc := chResolveCredential(ch.Endpoint)
	if cc == nil {
		err := fmt.Errorf("no credential bound to clickhouse_native endpoint")
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return err
	}
	auth, ok := cc.Credential.Body.(runtime.ClickhouseAuthCredential)
	if !ok {
		err := fmt.Errorf("credential %q has no ClickHouse auth", cc.Credential.Symbol.Name)
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return err
	}
	sec, err := ch.Secrets.Get(cc.Credential.Symbol.Name, ch.Profile)
	if err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: "fetch secret: " + err.Error()})
		return err
	}
	realUser, realPassword := auth.ClickhouseAuth(sec)
	if realUser == "" {
		err := fmt.Errorf("clickhouse credential %q missing user", cc.Credential.Symbol.Name)
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return err
	}
	if realPassword == "" {
		err := fmt.Errorf("clickhouse credential %q missing password", cc.Credential.Symbol.Name)
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return err
	}

	hello.Username = realUser
	hello.Password = realPassword

	host, port, upstreamAddr := chUpstream(ch.Endpoint)
	if upstreamAddr == "" {
		err := fmt.Errorf("clickhouse_native endpoint %q has no host", ch.Endpoint.Name)
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: err.Error()})
		return err
	}
	upstream, err := ch.DialUpstream(ctx, "tcp", upstreamAddr)
	if err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: "dial upstream: " + err.Error()})
		return err
	}
	defer upstream.Close()

	tlsConn := tls.Client(upstream, &tls.Config{ServerName: host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: "upstream tls: " + err.Error()})
		return err
	}
	upstream = tlsConn

	if _, err := upstream.Write(chSerializeHello(hello)); err != nil {
		chEmit(ch, runtime.ConnEvent{Action: "error", Verb: "connect", Reason: "write upstream hello: " + err.Error()})
		return err
	}

	database := hello.Database
	if database == "" {
		database = "default"
	}
	summary := fmt.Sprintf("%s@%s:%d/%s", hello.Username, host, port, database)
	chEmit(ch, runtime.ConnEvent{
		Action:  "allow",
		Verb:    "connect",
		Summary: summary,
	})
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, ch.Conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ch.Conn, upstream)
		done <- struct{}{}
	}()
	<-done
	return nil
}

func chReadInitialHello(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < 1<<20 {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if _, parseErr := chParseHello(buf); parseErr == nil {
				return buf, nil
			} else if !chNeedsMore(parseErr) {
				return nil, parseErr
			}
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return nil, fmt.Errorf("incomplete Hello packet")
			}
			return nil, err
		}
	}
	return nil, fmt.Errorf("Hello packet exceeds 1 MiB")
}

func chNeedsMore(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "short varuint") || strings.Contains(msg, "string extends beyond buffer")
}

func chResolveCredential(ep *config.CompiledEndpoint) *config.CompiledCredential {
	if ep == nil || len(ep.Credentials) == 0 {
		return nil
	}
	return ep.Credentials[0]
}

func chUpstream(ep *config.CompiledEndpoint) (host string, port int, addr string) {
	if ep == nil {
		return "", 0, ""
	}
	port = clickhouseNativeDefaultPort
	if body, ok := ep.Body.(*ClickhouseNativeEndpoint); ok && body.Port != 0 {
		port = body.Port
	}
	for _, h := range ep.Hosts {
		if h == "" {
			continue
		}
		host = h
		if splitHost, splitPort, err := net.SplitHostPort(h); err == nil {
			host = splitHost
			if p, convErr := strconv.Atoi(splitPort); convErr == nil {
				port = p
			}
		}
		return host, port, net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "", port, ""
}

func chEmit(ch *runtime.ConnHandle, ev runtime.ConnEvent) {
	if ch.Emit != nil {
		ch.Emit(ev)
	}
}

var _ runtime.ConnEndpointRuntime = ClickhouseNativeEndpointRuntime{}
