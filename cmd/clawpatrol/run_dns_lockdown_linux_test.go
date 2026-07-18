//go:build linux

package main

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalHostsFile(t *testing.T) {
	got := minimalHostsFile("devbox")
	for _, want := range []string{
		"127.0.0.1 localhost\n",
		"::1 localhost ip6-localhost ip6-loopback\n",
		"127.0.1.1 devbox\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("minimalHostsFile(devbox) missing %q:\n%s", want, got)
		}
	}

	got = minimalHostsFile("")
	if strings.Contains(got, "127.0.1.1") {
		t.Errorf("minimalHostsFile(\"\") should have no 127.0.1.1 line:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1 localhost\n") {
		t.Errorf("minimalHostsFile(\"\") missing localhost line:\n%s", got)
	}
}

// findOverride returns the override for target, or nil.
func findOverride(plan dnsLockdown, target string) *etcOverride {
	for i := range plan.Overrides {
		if plan.Overrides[i].Target == target {
			return &plan.Overrides[i]
		}
	}
	return nil
}

func TestComputeDNSLockdown(t *testing.T) {
	const resolv = "nameserver 100.64.0.1\n"

	base := dnsLockdownInputs{
		ResolvBody:          resolv,
		NsswitchRaw:         "hosts: files dns\n",
		HostsExists:         true,
		Hostname:            "devbox",
		VarlinkSocketExists: false,
	}

	t.Run("fedora resolve short-circuit", func(t *testing.T) {
		in := base
		in.NsswitchRaw = "passwd: files\nhosts: files resolve [!UNAVAIL=return] dns\n"
		in.VarlinkSocketExists = true
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if o := findOverride(plan, "/etc/resolv.conf"); o == nil || o.Body != resolv {
			t.Errorf("resolv.conf override wrong: %+v", o)
		}
		o := findOverride(plan, "/etc/nsswitch.conf")
		if o == nil {
			t.Fatalf("missing nsswitch override")
		}
		if !strings.Contains(o.Body, "hosts:      files dns") || strings.Contains(o.Body, "resolve") {
			t.Errorf("nsswitch body not sanitized:\n%s", o.Body)
		}
		ho := findOverride(plan, "/etc/hosts")
		if ho == nil || !strings.Contains(ho.Body, "127.0.1.1 devbox") {
			t.Errorf("hosts override wrong: %+v", ho)
		}
		if len(plan.Masks) != 1 || plan.Masks[0] != "/run/systemd/resolve/io.systemd.Resolve" {
			t.Errorf("Masks = %v, want the resolved varlink socket", plan.Masks)
		}
	})

	t.Run("ubuntu files dns needs no nsswitch override", func(t *testing.T) {
		plan, err := computeDNSLockdown(base)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if o := findOverride(plan, "/etc/nsswitch.conf"); o != nil {
			t.Errorf("unexpected nsswitch override: %+v", o)
		}
		if findOverride(plan, "/etc/resolv.conf") == nil || findOverride(plan, "/etc/hosts") == nil {
			t.Errorf("resolv/hosts overrides missing: %+v", plan.Overrides)
		}
		if len(plan.Masks) != 0 {
			t.Errorf("Masks = %v, want none", plan.Masks)
		}
	})

	t.Run("musl without nsswitch is fine", func(t *testing.T) {
		in := base
		in.NsswitchRaw = ""
		in.NsswitchErr = fs.ErrNotExist
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("missing nsswitch.conf must not error: %v", err)
		}
		if o := findOverride(plan, "/etc/nsswitch.conf"); o != nil {
			t.Errorf("unexpected nsswitch override: %+v", o)
		}
		if findOverride(plan, "/etc/resolv.conf") == nil {
			t.Errorf("resolv override missing")
		}
	})

	t.Run("nsswitch read error is fatal", func(t *testing.T) {
		in := base
		in.NsswitchRaw = ""
		in.NsswitchErr = fs.ErrPermission
		if _, err := computeDNSLockdown(in); err == nil {
			t.Fatalf("want error on unreadable nsswitch.conf, got nil")
		}
	})

	t.Run("keep-resolv escape hatch skips everything", func(t *testing.T) {
		in := base
		in.KeepResolv = true
		in.NsswitchErr = fs.ErrPermission // must not even be looked at
		in.VarlinkSocketExists = true
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(plan.Overrides) != 0 || len(plan.Masks) != 0 {
			t.Errorf("keep-resolv plan not empty: %+v", plan)
		}
	})

	t.Run("nscd runtime dir is dir-masked", func(t *testing.T) {
		// nscd answers getaddrinfo BEFORE the NSS chain runs, so the
		// planner must hide its runtime directory even when nsswitch
		// needs no rewrite at all (#765). The whole directory — not the
		// socket file — so a socket re-created mid-run stays invisible.
		in := base
		in.NscdDirsPresent = []string{"/run/nscd", "/var/run/nscd"}
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(plan.DirMasks, in.NscdDirsPresent) {
			t.Errorf("DirMasks = %v, want %v", plan.DirMasks, in.NscdDirsPresent)
		}
		if len(plan.Masks) != 0 {
			t.Errorf("Masks = %v, want none", plan.Masks)
		}
	})

	t.Run("nscd dir and varlink socket masked together", func(t *testing.T) {
		in := base
		in.NsswitchRaw = "hosts: files resolve [!UNAVAIL=return] dns\n"
		in.VarlinkSocketExists = true
		in.NscdDirsPresent = []string{"/var/run/nscd"}
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"/run/systemd/resolve/io.systemd.Resolve"}; !reflect.DeepEqual(plan.Masks, want) {
			t.Errorf("Masks = %v, want %v", plan.Masks, want)
		}
		if want := []string{"/var/run/nscd"}; !reflect.DeepEqual(plan.DirMasks, want) {
			t.Errorf("DirMasks = %v, want %v", plan.DirMasks, want)
		}
	})

	t.Run("keep-resolv skips nscd masking too", func(t *testing.T) {
		in := base
		in.KeepResolv = true
		in.NscdDirsPresent = []string{"/run/nscd"}
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(plan.Masks) != 0 || len(plan.DirMasks) != 0 {
			t.Errorf("keep-resolv masks = %v / %v, want none", plan.Masks, plan.DirMasks)
		}
	})

	t.Run("missing /etc/hosts needs no override", func(t *testing.T) {
		in := base
		in.HostsExists = false
		plan, err := computeDNSLockdown(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if o := findOverride(plan, "/etc/hosts"); o != nil {
			t.Errorf("unexpected hosts override: %+v", o)
		}
	})
}

// Discovery must fail closed: only a definite "not there" counts as
// absent — a permission or I/O failure silently skipping a mask would
// reopen the leak the mask exists to close (#765).
func TestClassifyStatErr(t *testing.T) {
	if present, err := classifyStatErr("/x", nil); !present || err != nil {
		t.Errorf("nil err: present=%v err=%v, want true/nil", present, err)
	}
	if present, err := classifyStatErr("/x", fs.ErrNotExist); present || err != nil {
		t.Errorf("ENOENT: present=%v err=%v, want false/nil", present, err)
	}
	// Stat through a missing parent ("/run/nscd/socket" where /run/nscd
	// is a file) reports ENOTDIR — also a definite absence.
	if present, err := classifyStatErr("/x", unix.ENOTDIR); present || err != nil {
		t.Errorf("ENOTDIR: present=%v err=%v, want false/nil", present, err)
	}
	if present, err := classifyStatErr("/x", fs.ErrPermission); present || err == nil {
		t.Errorf("EPERM: present=%v err=%v, want false/error", present, err)
	}
	if _, err := classifyStatErr("/x", errors.New("io weirdness")); err == nil {
		t.Errorf("unknown stat failure must be fatal, got nil error")
	}
}

func TestGatherDNSLockdownInputsKeepResolv(t *testing.T) {
	// The escape hatch must short-circuit discovery entirely, so it
	// still works on hosts where the probes themselves would fail.
	t.Setenv("CLAWPATROL_RUN_KEEP_RESOLV", "1")
	in, err := gatherDNSLockdownInputs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !in.KeepResolv {
		t.Fatalf("KeepResolv = false, want true")
	}
}
