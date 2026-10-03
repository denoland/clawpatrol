package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Approvals run concurrently: the approve handler mints each key in its
// own goroutine, with its own onboarder. Every approval must get its own
// address, and the device must route each address to the key that was
// handed out with it.
func TestMintKeyConcurrentApprovalsGetDistinctAddresses(t *testing.T) {
	wg := startTestWGServer(t, "10.55.0.0/24")
	ts := JoinConfig{WGEnabled: true, WGSubnetCIDR: "10.55.0.0/24", WGEndpoint: "198.51.100.10:51820"}

	const n = 16
	type minted struct {
		conf, ip string
		err      error
	}
	results := make([]minted, n)
	start := make(chan struct{})
	var done sync.WaitGroup
	for i := range n {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			conf, _, ip, err := newOnboarder(ts).MintKey(context.Background(), "", true)
			results[i] = minted{conf, ip, err}
		}()
	}
	close(start)
	done.Wait()

	routes := deviceRoutes(t, wg)
	seen := map[string]bool{}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("approval %d failed: %v", i, r.err)
		}
		if seen[r.ip] {
			t.Fatalf("address %s was handed to two devices", r.ip)
		}
		seen[r.ip] = true
		if got, want := routes[r.ip], pubHexFromConf(t, r.conf); got != want {
			t.Errorf("address %s routes to peer %.8s, want the key handed out with it, %.8s", r.ip, got, want)
		}
	}
}

// Approvals overlap with other writes to the same database: the approve
// handler stores the device's API token and row while the next approval
// registers its peer. Registration must wait for the database rather
// than fail with SQLITE_BUSY.
func TestMintKeySucceedsWhileTheDatabaseIsBeingWritten(t *testing.T) {
	startTestWGServer(t, "10.55.0.0/24")
	ts := JoinConfig{WGEnabled: true, WGSubnetCIDR: "10.55.0.0/24", WGEndpoint: "198.51.100.10:51820"}
	if _, err := globalDB.Exec("CREATE TABLE test_writes (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	stop := make(chan struct{})
	var writers sync.WaitGroup
	for range 4 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = globalDB.Exec("INSERT INTO test_writes (n) VALUES (?)", n)
			}
		}()
	}
	defer func() { close(stop); writers.Wait() }()

	const n = 32
	errs := make([]error, n)
	var done sync.WaitGroup
	for i := range n {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _, _, errs[i] = newOnboarder(ts).MintKey(context.Background(), "", true)
		}()
	}
	done.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("approval %d failed while the database was being written: %v", i, err)
		}
	}
}

// A registration whose row cannot be stored must leave the device as it
// was: a peer the table does not record must never take over a live
// peer's address.
func TestAddPeerLeavesTheDeviceAloneWhenTheRowFails(t *testing.T) {
	wg := startTestWGServer(t, "10.55.0.0/24")
	owner := testPeerKey(t)
	if err := wg.AddPeer(owner, "10.55.0.2"); err != nil {
		t.Fatalf("AddPeer(owner): %v", err)
	}

	_ = wg.db.Close()
	if err := wg.AddPeer(testPeerKey(t), "10.55.0.2"); err == nil {
		t.Fatal("AddPeer succeeded although its row could not be stored")
	}
	if got := deviceRoutes(t, wg)["10.55.0.2"]; got != owner {
		t.Fatalf("10.55.0.2 routes to peer %.8s after a failed registration, want the owner %.8s", got, owner)
	}
}

// startTestWGServer boots a WireGuard server on a fresh database and
// installs both as the globals the onboarder uses.
func startTestWGServer(t *testing.T, subnet string) *WGServer {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	prevDB, prevWG := globalDB, globalWG
	setDB(db)
	t.Cleanup(func() { setDB(prevDB); setWGServer(prevWG) })

	wg, err := StartWGServer(JoinConfig{WGSubnetCIDR: subnet, WGListenPort: freeUDPPort(t)})
	if err != nil {
		t.Fatalf("StartWGServer: %v", err)
	}
	t.Cleanup(func() { wg.dev.Close() })
	setWGServer(wg)
	return wg
}

// deviceRoutes maps each IPv4 address the device routes to a peer onto
// that peer's public key (hex), as wireguard-go reports them.
func deviceRoutes(t *testing.T, wg *WGServer) map[string]string {
	t.Helper()
	cfg, err := wg.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	routes := map[string]string{}
	var peer string
	for _, line := range strings.Split(cfg, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "public_key":
			peer = value
		case "allowed_ip":
			if addr, ok := strings.CutSuffix(value, "/32"); ok {
				routes[addr] = peer
			}
		}
	}
	return routes
}

// pubHexFromConf derives the public key (hex) of the private key in a
// minted wg-quick config.
func pubHexFromConf(t *testing.T, conf string) string {
	t.Helper()
	for _, line := range strings.Split(conf, "\n") {
		if b64, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
			priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
			if err != nil {
				t.Fatalf("PrivateKey is not base64: %v", err)
			}
			pub, err := wgPubFromPrivHex(hex.EncodeToString(priv))
			if err != nil {
				t.Fatalf("wgPubFromPrivHex: %v", err)
			}
			return pub
		}
	}
	t.Fatal("minted config has no PrivateKey line")
	return ""
}

func testPeerKey(t *testing.T) string {
	t.Helper()
	_, pub, _, err := wgGenKeypair()
	if err != nil {
		t.Fatalf("wgGenKeypair: %v", err)
	}
	return pub
}
