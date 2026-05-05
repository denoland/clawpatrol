package endpoints

import (
	"bytes"
	"testing"

	"github.com/denoland/clawpatrol/config"
	"github.com/google/go-cmp/cmp"
)

func TestClickhouseVarUIntRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 127, 128, 255, 300, 16384, 1<<32 + 17} {
		wire := chWriteVarUInt(n)
		got, read, err := chReadVarUInt(wire, 0)
		if err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if got != n || read != len(wire) {
			t.Fatalf("roundtrip %d got value=%d read=%d len=%d", n, got, read, len(wire))
		}
	}
}

func TestClickhouseStringRoundTrip(t *testing.T) {
	wire := chWriteString("clickhouse-client")
	got, read, err := chReadString(wire, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "clickhouse-client" || read != len(wire) {
		t.Fatalf("got %q read=%d len=%d", got, read, len(wire))
	}
}

func TestClickhouseHelloRoundTrip(t *testing.T) {
	want := clickhouseHello{
		PacketType:       0,
		ClientName:       "ClickHouse client",
		VersionMajor:     24,
		VersionMinor:     3,
		ProtocolRevision: 54468,
		Database:         "default",
		Username:         "PH_user",
		Password:         "PH_pass",
		Trailing:         []byte{1, 2, 3},
	}
	wire := chSerializeHello(want)
	got, err := chParseHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("hello mismatch (-want +got):\n%s", diff)
	}
	if !bytes.Equal(chSerializeHello(got), wire) {
		t.Fatalf("serialized hello changed on roundtrip")
	}
}

func TestClickhouseHelloRejectsNonHello(t *testing.T) {
	wire := append(chWriteVarUInt(1), chWriteString("not hello")...)
	if _, err := chParseHello(wire); err == nil {
		t.Fatalf("expected non-Hello packet to fail")
	}
}

func TestClickhouseNativePortDefaultAndOverride(t *testing.T) {
	cases := []struct {
		name string
		body *ClickhouseNativeEndpoint
		want string
		port int
	}{
		{
			name: "default port",
			body: &ClickhouseNativeEndpoint{Hosts: []string{"clickhouse.example.com"}},
			want: "clickhouse.example.com:9440",
			port: 9440,
		},
		{
			name: "configured port",
			body: &ClickhouseNativeEndpoint{Hosts: []string{"clickhouse.example.com"}, Port: 9441},
			want: "clickhouse.example.com:9441",
			port: 9441,
		},
		{
			name: "host port wins",
			body: &ClickhouseNativeEndpoint{Hosts: []string{"clickhouse.example.com:9442"}, Port: 9441},
			want: "clickhouse.example.com:9442",
			port: 9442,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := &config.CompiledEndpoint{Body: tc.body, Hosts: tc.body.Hosts}
			_, port, addr := chUpstream(ep)
			if addr != tc.want || port != tc.port {
				t.Fatalf("addr=%q port=%d want addr=%q port=%d", addr, port, tc.want, tc.port)
			}
		})
	}
}
