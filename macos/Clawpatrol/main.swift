// Container app — saves a transparent-proxy configuration into
// NETransparentProxyManager. The extension does the per-process
// filtering itself by walking each flow's audit-token chain back to
// `dev.clawpatrol.app`, so we don't need NEAppRule/matchTools here
// (which on macOS require an MDM-pushed appmapping payload).
//
// CLI invocation:
//   Clawpatrol install                — save proxy profile (per-process)
//   Clawpatrol install --whole-machine — save proxy profile (all flows)
//   Clawpatrol start <conf-file>      — load wg-quick conf, start proxy
//   Clawpatrol stop                   — stop proxy
//   Clawpatrol run -- <cmd> [args]    — fork+exec cmd as child of clawpatrol
//                                       so the extension's PPID-walk
//                                       picks it up
import AppKit
import Darwin
import Foundation
import NetworkExtension
import SystemExtensions

let extBundleID = "dev.clawpatrol.app.extension"
let parentBundleID = "dev.clawpatrol.app"
let proxyProfileName = "clawpatrol"

func usage() -> Never {
    FileHandle.standardError.write(Data("usage: Clawpatrol {install [--whole-machine]|start <conf>|stop|run -- <cmd> [args...]}\n".utf8))
    exit(2)
}

let cmd = CommandLine.arguments.count >= 2 ? CommandLine.arguments[1] : "install"
let wholeMachineFlag = CommandLine.arguments.contains("--whole-machine")
// nil → preserve existing mode (subsequent `Clawpatrol install` from
// `clawpatrol run` shouldn't downgrade a profile that was previously
// installed with --whole-machine). Set explicitly only when the flag
// is on the command line.
let wholeMachine: Bool? = wholeMachineFlag ? true : nil

switch cmd {
case "install": installSystemExtension(wholeMachine: wholeMachine ?? false, explicit: wholeMachine != nil)
case "start":
    guard CommandLine.arguments.count >= 3 else { usage() }
    startProxy(confPath: CommandLine.arguments[2])
case "stop": stopProxy()
case "wipe": wipeAllConfigs()
case "run": runWrapped()    // synchronous; calls exit() — never reaches runloop
default: usage()
}

NSApplication.shared.run()

// `Clawpatrol run -- <cmd>` forks + execs cmd. Stays foreground so
// the extension's PPID walk finds Clawpatrol's signing identifier in
// the cmd's parent chain → flows from cmd (and its descendants) get
// tunneled. Exec'ing in-place would replace our process with cmd's
// signing identity, breaking the match.
func runWrapped() {
    let argv = Array(CommandLine.arguments.dropFirst(2)).filter { $0 != "--" }
    if argv.isEmpty { usage() }

    // IPC handshake — synchronously register our PID with the
    // extension's session listener before posix_spawn'ing the child.
    // The handshake guarantees the ext has the PID in its registry
    // before the child's first flow can fire. See sessionRegister()
    // in Provider.swift for protocol details.
    sessionIPC("register \(getpid())")
    defer { sessionIPC("unregister \(getpid())") }

    var pid: pid_t = 0
    let cargs = argv.map { strdup($0) } + [nil]
    var actions: posix_spawn_file_actions_t? = nil
    posix_spawn_file_actions_init(&actions)
    let rc = posix_spawnp(&pid, argv[0], &actions, nil, cargs, environ)
    posix_spawn_file_actions_destroy(&actions)
    cargs.compactMap { $0 }.forEach { free($0) }
    if rc != 0 {
        FileHandle.standardError.write(Data("posix_spawnp \(argv[0]): \(String(cString: strerror(rc)))\n".utf8))
        exit(127)
    }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    exit((status >> 8) & 0xff)
}

// sessionIPC dials /tmp/clawpatrol.sock and sends a single newline-
// framed verb. Best-effort: failures (sysext not yet running, sandbox
// quirk) just no-op. The wrapped child won't be tunneled in that
// case, but blocking the user's command on extension plumbing is
// worse than passthrough.
func sessionIPC(_ msg: String) {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return }
    defer { Darwin.close(fd) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = "/tmp/clawpatrol.sock".utf8CString
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: bytes.count) { p in
            for (i, b) in bytes.enumerated() {
                p.advanced(by: i).pointee = b
            }
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { ap -> Int32 in
        ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.connect(fd, sa, len)
        }
    }
    if rc != 0 { return }
    var line = msg + "\n"
    _ = line.withUTF8 { buf in
        Darwin.write(fd, buf.baseAddress, buf.count)
    }
    var reply = [UInt8](repeating: 0, count: 8)
    _ = reply.withUnsafeMutableBufferPointer { p in
        Darwin.read(fd, p.baseAddress, p.count)
    }
}

class ExtDelegate: NSObject, OSSystemExtensionRequestDelegate {
    let wholeMachine: Bool
    let explicit: Bool
    init(wholeMachine: Bool, explicit: Bool) {
        self.wholeMachine = wholeMachine
        self.explicit = explicit
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("system extension: \(result.rawValue)")
        if result == .completed { saveProxyProfileAndExit(wholeMachine: wholeMachine, explicit: explicit) } else { exit(1) }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        FileHandle.standardError.write(Data("system extension failed: \(error)\n".utf8))
        exit(1)
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("waiting for user approval in System Settings → Login Items & Extensions…")
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension new: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

var extDelegate: ExtDelegate?

func installSystemExtension(wholeMachine: Bool, explicit: Bool) {
    let delegate = ExtDelegate(wholeMachine: wholeMachine, explicit: explicit)
    extDelegate = delegate
    let req = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extBundleID, queue: .main)
    req.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(req)
}

// saveProxyProfileAndExit writes the NETransparentProxy profile.
// `explicit` is true when --whole-machine was passed on the command
// line; when false, an existing profile's `mode` is preserved so the
// idempotent `Clawpatrol install` from `clawpatrol run` can't downgrade
// a whole-machine setup back to per-process.
func saveProxyProfileAndExit(wholeMachine: Bool, explicit: Bool) {
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        let existing = managers?.first(where: { $0.localizedDescription == proxyProfileName })
        let manager = existing ?? NETransparentProxyManager()
        var resolvedMode = wholeMachine ? "whole-machine" : "per-process"
        if !explicit, let proto = existing?.protocolConfiguration as? NETunnelProviderProtocol,
           let prev = proto.providerConfiguration?["mode"] as? String, !prev.isEmpty {
            resolvedMode = prev
        }
        let prevMode: String? = (existing?.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["mode"] as? String
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extBundleID
        proto.serverAddress = "clawpatrol-gateway"
        // Preserve any wg-conf already saved on the existing profile.
        var wgConf = ""
        if let existingProto = existing?.protocolConfiguration as? NETunnelProviderProtocol,
           let prevConf = existingProto.providerConfiguration?["wg-conf"] as? String {
            wgConf = prevConf
        }
        proto.providerConfiguration = [
            "wg-conf": wgConf,
            "mode": resolvedMode,
        ]
        manager.protocolConfiguration = proto
        manager.localizedDescription = proxyProfileName
        manager.isEnabled = true
        // On-demand: NE auto-starts the proxy at boot / wake / network
        // change, so per-process flow tracking survives reboot+sleep
        // without the user re-running `Clawpatrol start`. Without this
        // the manager config persists but the tunnel sits idle until
        // explicitly restarted, leaving /tmp/clawpatrol.sock missing.
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("saveToPreferences: \(err)") }
            print("✓ proxy profile installed (\(resolvedMode))")
            // Mode change while the tunnel is already running needs an
            // explicit reload — providerConfiguration is read once at
            // startProxy time, so saveToPreferences alone leaves the
            // running ext on the old mode. Operators flipping
            // per-process ↔ whole-machine via re-running install
            // expect the new mode to apply immediately.
            let modeChanged = (prevMode ?? "") != resolvedMode
            let running = manager.connection.status == .connected
                || manager.connection.status == .connecting
            if modeChanged && running && !wgConf.isEmpty {
                reloadTunnelAndExit(manager: manager, label: resolvedMode)
            } else {
                exit(0)
            }
        }
    }
}

// reloadTunnelAndExit stops the running tunnel, waits for
// .disconnected, then starts it again. Used after a config change
// (mode flip, conf swap) that providerConfiguration alone won't
// surface to the running extension.
func reloadTunnelAndExit(manager: NETransparentProxyManager, label: String) {
    print("↻ reloading tunnel for new \(label)")
    manager.connection.stopVPNTunnel()
    var attempts = 0
    func tick() {
        let s = manager.connection.status
        if s == .disconnected || s == .invalid || attempts > 50 {
            do {
                try manager.connection.startVPNTunnel()
                print("✓ tunnel reloaded")
                exit(0)
            } catch {
                fail("startVPNTunnel: \(error)")
            }
            return
        }
        attempts += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: tick)
    }
    tick()
}

func startProxy(confPath: String) {
    guard let conf = try? String(contentsOfFile: confPath, encoding: .utf8) else {
        fail("read \(confPath)")
    }
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        guard let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName }) else {
            fail("no proxy profile — run `Clawpatrol install` first")
        }
        let prevConf: String = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["wg-conf"] as? String ?? ""
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            var cfg = proto.providerConfiguration ?? [:]
            cfg["wg-conf"] = conf
            proto.providerConfiguration = cfg
            manager.protocolConfiguration = proto
        }
        manager.isEnabled = true
        // Idempotently re-assert on-demand so existing installs
        // upgrade onto the auto-start path without re-running install.
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("save: \(err)") }
            manager.loadFromPreferences { err in
                if let err = err { fail("reload: \(err)") }
                let running = manager.connection.status == .connected
                    || manager.connection.status == .connecting
                let confChanged = prevConf != conf
                if running && confChanged {
                    // Conf swap while running — extension parses wg-conf
                    // once at startProxy. Force a stop+start so the new
                    // peer key / address takes effect.
                    reloadTunnelAndExit(manager: manager, label: "wg-conf")
                    return
                }
                if running {
                    // mitmproxy-style staleness guard: NE can report
                    // "connected" after a reboot/wake even though the
                    // sysext process hasn't actually run startProxy yet
                    // (no IPC socket, no flow handler). Ping the
                    // listener; if it doesn't respond, force a stop +
                    // start to recreate it.
                    if extSocketAlive() {
                        print("✓ proxy already up (no change)")
                        exit(0)
                    }
                    print("⟳ proxy reports connected but ext socket is dead — reloading")
                    reloadTunnelAndExit(manager: manager, label: "stale-connected")
                    return
                }
                do {
                    try manager.connection.startVPNTunnel()
                    print("✓ proxy up")
                    exit(0)
                } catch {
                    fail("startVPNTunnel: \(error)")
                }
            }
        }
    }
}

func stopProxy() {
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        guard let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName }) else {
            print("no profile to stop"); exit(0)
        }
        manager.connection.stopVPNTunnel()
        print("✓ proxy down")
        exit(0)
    }
}

// Remove every NETunnelProviderManager AND NETransparentProxyManager
// our app has registered. Used to clean up stale configs from earlier
// experiments (packet-tunnel days) when System Settings can't open
// the VPN pane to remove them by hand.
func wipeAllConfigs() {
    let group = DispatchGroup()
    var anyErr: Error?
    group.enter()
    NETunnelProviderManager.loadAllFromPreferences { managers, err in
        if let err = err { anyErr = err }
        for m in managers ?? [] {
            group.enter()
            m.removeFromPreferences { rerr in
                if let rerr = rerr { anyErr = rerr }
                group.leave()
            }
        }
        group.leave()
    }
    group.enter()
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { anyErr = err }
        for m in managers ?? [] {
            group.enter()
            m.removeFromPreferences { rerr in
                if let rerr = rerr { anyErr = rerr }
                group.leave()
            }
        }
        group.leave()
    }
    group.notify(queue: .main) {
        if let e = anyErr { fail("wipe: \(e)") }
        print("✓ all configs removed")
        exit(0)
    }
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("clawpatrol-macos: \(msg)\n".utf8))
    exit(1)
}

// extSocketAlive pings the IPC listener the extension sets up at
// startProxy. NEVPNStatus.connected is unreliable after reboot/wake —
// the manager's stored state can claim "connected" while the sysext
// process hasn't actually been spawned yet. Connecting to the unix
// socket is the ground truth.
func extSocketAlive() -> Bool {
    let path = "/tmp/clawpatrol.sock"
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return false }
    defer { close(fd) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    if pathBytes.count >= MemoryLayout.size(ofValue: addr.sun_path) { return false }
    withUnsafeMutableBytes(of: &addr.sun_path) { ptr in
        for (i, b) in pathBytes.enumerated() {
            ptr[i] = b
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    var fl = fcntl(fd, F_GETFL, 0); fl |= O_NONBLOCK
    _ = fcntl(fd, F_SETFL, fl)
    let rc = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, len)
        }
    }
    if rc == 0 { return true }
    if errno != EINPROGRESS { return false }
    var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
    let pr = poll(&pfd, 1, 500)
    if pr <= 0 { return false }
    var soerr: Int32 = 0
    var slen = socklen_t(MemoryLayout<Int32>.size)
    if getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 { return false }
    return soerr == 0
}
