package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// commandPlatform builds the namespace or Landlock wrapper command:
// a re-exec of /proc/self/exe whose Stage1 hook performs the setup
// and then execs the plugin binary in place (so go-plugin's SIGKILL
// lands on the real plugin).
func commandPlatform(spec Spec, mode Mode) (*exec.Cmd, error) {
	switch mode {
	case ModeNamespaces, ModeLandlock:
		return wrapperCmd(spec, mode, stage1Exec)
	default:
		return nil, fmt.Errorf("sandbox: backend %q is not supported on linux", mode)
	}
}

func wrapperCmd(spec Spec, mode Mode, action string) (*exec.Cmd, error) {
	payload, err := json.Marshal(stage1Payload{Spec: spec, Mode: mode})
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(BaseEnv(spec),
		EnvStage1+"="+action,
		EnvSpec+"="+string(payload),
	)
	sys := &syscall.SysProcAttr{
		// The plugin must not outlive the gateway, even if the
		// gateway dies without running go-plugin's Kill. Pdeathsig
		// survives the (non-setuid) exec into the plugin binary.
		Pdeathsig: syscall.SIGKILL,
	}
	if mode == ModeNamespaces {
		flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
		if spec.Network == NetworkNone {
			flags |= syscall.CLONE_NEWNET
		}
		// Map the gateway user to root (uid 0) inside the user
		// namespace — the rootless-container model. A non-root ns uid
		// cannot change mount propagation or pivot_root (the inherited
		// mounts are owned by an ancestor user namespace), so the
		// sandbox setup needs uid 0 here. Stage-1 then drops every
		// capability and sets SECBIT_NOROOT before exec'ing the
		// plugin, so the plugin runs as a powerless uid 0: it cannot
		// remount the read-only binds or otherwise abuse the userns.
		uid, gid := os.Getuid(), os.Getgid()
		sys.Cloneflags = uintptr(flags)
		sys.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}
		sys.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}}
		sys.GidMappingsEnableSetgroups = false
	}
	cmd.SysProcAttr = sys
	return cmd, nil
}

func probePlatform(force Mode) (Availability, error) {
	switch force {
	case "":
		nsErr := probeNamespaces()
		if nsErr == nil {
			return Availability{Mode: ModeNamespaces}, nil
		}
		av, llErr := probeLandlock()
		if llErr == nil {
			av.Warning = fmt.Sprintf("user namespaces unavailable (%v); %s", nsErr, av.Warning)
			return av, nil
		}
		return Availability{}, fmt.Errorf("no sandbox backend works on this host: user namespaces unavailable (%w); Landlock unavailable (%w)", nsErr, llErr)
	case ModeNamespaces:
		if err := probeNamespaces(); err != nil {
			return Availability{}, fmt.Errorf("forced backend %q: %w", force, err)
		}
		return Availability{Mode: ModeNamespaces}, nil
	case ModeLandlock:
		av, err := probeLandlock()
		if err != nil {
			return Availability{}, fmt.Errorf("forced backend %q: %w", force, err)
		}
		av.Warning = "Landlock backend forced via " + EnvBackend + "; " + av.Warning
		return av, nil
	default:
		return Availability{}, fmt.Errorf("backend %q is not supported on linux (have: namespaces, landlock)", force)
	}
}

// probeNamespaces runs the real stage-1 setup (clone flags, mounts,
// pivot_root) against a throwaway spec and reports why it failed.
func probeNamespaces() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/tmp", "cp-probe-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmp := dir + "/tmp"
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	spec := Spec{
		PluginName: "probe",
		BinaryPath: exe,
		SocketDir:  dir,
		TmpDir:     tmp,
		Network:    NetworkNone,
	}
	cmd, err := wrapperCmd(spec, ModeNamespaces, stage1Probe)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(out.String())
		if detail == "" {
			detail = err.Error()
		}
		if hint := usernsBlockHint(); hint != "" {
			detail += "; " + hint
		}
		return fmt.Errorf("%s", detail)
	}
	return nil
}

// usernsBlockHint inspects the sysctls that commonly disable
// unprivileged user namespaces and names the fix.
func usernsBlockHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return "unprivileged user namespaces are disabled; fix: sudo sysctl -w kernel.unprivileged_userns_clone=1"
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return "AppArmor restricts unprivileged user namespaces; fix: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
		}
	}
	return ""
}

func probeLandlock() (Availability, error) {
	abi := landlockABI()
	if abi < 1 {
		return Availability{}, fmt.Errorf("kernel lacks Landlock (need >= 5.13 with CONFIG_SECURITY_LANDLOCK)")
	}
	warn := "using Landlock file-system sandbox (degraded: no mount/pid isolation"
	if abi >= 4 {
		warn += ", TCP-only network restriction)"
	} else {
		warn += ", no network restriction)"
	}
	return Availability{Mode: ModeLandlock, Warning: warn, LandlockABI: abi}, nil
}
