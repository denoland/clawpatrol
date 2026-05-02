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
let wholeMachine = CommandLine.arguments.contains("--whole-machine")

switch cmd {
case "install": installSystemExtension(wholeMachine: wholeMachine)
case "start":
    guard CommandLine.arguments.count >= 3 else { usage() }
    startProxy(confPath: CommandLine.arguments[2])
case "stop": stopProxy()
case "wipe": wipeAllConfigs()
case "run": runWrapped()    // synchronous; calls exit() — never reaches runloop
default: usage()
}

NSApplication.shared.run()

// MARK: - run wrapper

// `Clawpatrol run -- <cmd>` forks + execs cmd. Stays foreground so
// the extension's PPID walk finds Clawpatrol's signing identifier in
// the cmd's parent chain → flows from cmd (and its descendants) get
// tunneled. Exec'ing in-place would replace our process with cmd's
// signing identity, breaking the match.
func runWrapped() {
    let argv = Array(CommandLine.arguments.dropFirst(2)).filter { $0 != "--" }
    if argv.isEmpty { usage() }
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

// MARK: - System extension activation

class ExtDelegate: NSObject, OSSystemExtensionRequestDelegate {
    let wholeMachine: Bool
    init(wholeMachine: Bool) { self.wholeMachine = wholeMachine }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("system extension: \(result.rawValue)")
        if result == .completed { saveProxyProfileAndExit(wholeMachine: wholeMachine) } else { exit(1) }
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

func installSystemExtension(wholeMachine: Bool) {
    let delegate = ExtDelegate(wholeMachine: wholeMachine)
    extDelegate = delegate
    let req = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extBundleID, queue: .main)
    req.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(req)
}

// MARK: - Transparent proxy configuration

func saveProxyProfileAndExit(wholeMachine: Bool) {
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName })
            ?? NETransparentProxyManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extBundleID
        proto.serverAddress = "clawpatrol-gateway"
        // wg-conf populated at start; mode read by the extension on
        // each new flow (per-process gates on audit-token PPID walk,
        // whole-machine returns true for everything).
        proto.providerConfiguration = [
            "wg-conf": "",
            "mode": wholeMachine ? "whole-machine" : "per-process",
        ]
        manager.protocolConfiguration = proto
        manager.localizedDescription = proxyProfileName
        manager.isEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("saveToPreferences: \(err)") }
            print("✓ proxy profile installed (\(wholeMachine ? "whole-machine" : "per-process"))")
            exit(0)
        }
    }
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
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            var cfg = proto.providerConfiguration ?? [:]
            cfg["wg-conf"] = conf
            proto.providerConfiguration = cfg
            manager.protocolConfiguration = proto
        }
        manager.isEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("save: \(err)") }
            manager.loadFromPreferences { err in
                if let err = err { fail("reload: \(err)") }
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
