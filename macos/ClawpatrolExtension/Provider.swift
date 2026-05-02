// TransparentProxyProvider — intercepts flows from clawpatrol's
// child-process tree and bridges them upstream via a userspace WG
// tunnel + gVisor netstack embedded in libwgnetstack.a (Go cgo
// archive built from ../netstack/wgnetstack.go).
//
// Why NETransparentProxy and not NEPacketTunnel:
//   Apple gates per-app NEPacketTunnel routing behind an MDM-pushed
//   com.apple.vpn.managed.appmapping payload — NETestAppMapping +
//   NEAppRule.matchTools is silently ignored on macOS without it.
//   NETransparentProxy receives flows pre-routed (TCP/UDP, with the
//   originating audit token) and we filter ourselves: walk the PPID
//   chain, match against the parent app's signing identifier, tunnel
//   matched flows, passthrough the rest.
//
// Why a Go cgo archive instead of WireGuardKit's WireGuardAdapter:
//   WireGuardAdapter is wired to NEPacketTunnelProvider.packetFlow.
//   We have no packetFlow here — we have NEAppProxyTCPFlow / UDPFlow
//   at L4. wgnetstack runs wireguard-go on a netTun whose other end
//   is a gVisor netstack stack; gonet.DialContextTCP through that
//   stack returns a connection whose IP packets are encrypted by
//   wireguard-go and emitted as UDP datagrams to the WG endpoint.
//   Each Swift-side flow gets bridged to one of these connections via
//   a unix socketpair (one fd in Go, one in Swift; goroutines pump).
//
// Provider configuration keys:
//   "wg-conf"  — wg-quick conf string (parsed in Go)
//   "mode"     — "per-process" (default) or "whole-machine"
import Darwin
import Foundation
import Network
import NetworkExtension
import os.log
import Security

private let log = OSLog(subsystem: "dev.clawpatrol.app.extension", category: "proxy")
private let parentBundleID = "dev.clawpatrol.app"

class TransparentProxyProvider: NETransparentProxyProvider {
    private var wholeMachine = false

    override func startProxy(options: [String: Any]?,
                             completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy", log: log, type: .info)
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let conf = proto.providerConfiguration?["wg-conf"] as? String, !conf.isEmpty else {
            completionHandler(NSError(domain: "clawpatrol", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing or empty wg-conf"]))
            return
        }
        if let mode = proto.providerConfiguration?["mode"] as? String {
            wholeMachine = (mode == "whole-machine")
        }

        // Spin up the userspace WG device + gVisor netstack.
        var errBuf = [CChar](repeating: 0, count: 256)
        let rc = conf.withCString { confC in
            errBuf.withUnsafeMutableBufferPointer { ebuf in
                wg_netstack_init(UnsafeMutablePointer(mutating: confC),
                                 ebuf.baseAddress, Int32(ebuf.count))
            }
        }
        if rc != 0 {
            let msg = String(cString: errBuf)
            os_log("wg_netstack_init: %{public}@", log: log, type: .error, msg)
            completionHandler(NSError(domain: "clawpatrol", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "wg-netstack: \(msg)"]))
            return
        }

        // Intercept everything outbound — filter inside handleNewFlow.
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                          localNetwork: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                          localNetwork: nil, localPrefix: 0,
                          protocol: .UDP, direction: .outbound),
        ]
        settings.excludedNetworkRules = [
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "224.0.0.0", port: "0"),
                          remotePrefix: 4, localNetwork: nil, localPrefix: 0,
                          protocol: .UDP, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "ff00::", port: "0"),
                          remotePrefix: 8, localNetwork: nil, localPrefix: 0,
                          protocol: .UDP, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "169.254.0.0", port: "0"),
                          remotePrefix: 16, localNetwork: nil, localPrefix: 0,
                          protocol: .UDP, direction: .outbound),
        ]
        setTunnelNetworkSettings(settings, completionHandler: completionHandler)
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        wg_netstack_close()
        completionHandler()
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if !shouldTunnel(flow) { return false }
        if let tcp = flow as? NEAppProxyTCPFlow {
            bridgeTCP(tcp); return true
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            bridgeUDP(udp); return true
        }
        return false
    }

    private func shouldTunnel(_ flow: NEAppProxyFlow) -> Bool {
        if wholeMachine { return true }
        guard let token = flow.metaData.sourceAppAuditToken,
              let pid = pidFromAuditToken(token) else { return false }
        return ancestorMatches(pid: pid, signingIdentifier: parentBundleID)
    }

    private func bridgeTCP(_ flow: NEAppProxyTCPFlow) {
        guard let endpoint = flow.remoteEndpoint as? NWHostEndpoint,
              let port = Int32(endpoint.port) else {
            flow.closeReadWithError(nil); flow.closeWriteWithError(nil); return
        }
        // Resolve hostname → IPv4. wgnetstack expects dotted-quad.
        // For names, we'd run DNS through the tunnel itself; for now
        // hostnames that don't parse as IPs are dropped. Curl etc.
        // typically resolve before opening the flow.
        guard let ip = resolveIPv4(endpoint.hostname) else {
            os_log("DNS unsupported for %{public}@; dropping", log: log, type: .error, endpoint.hostname)
            flow.closeReadWithError(nil); flow.closeWriteWithError(nil); return
        }

        flow.open(withLocalEndpoint: nil) { err in
            if let err = err {
                flow.closeReadWithError(err); flow.closeWriteWithError(err); return
            }
            var errBuf = [CChar](repeating: 0, count: 256)
            let fd = ip.withCString { hostC in
                errBuf.withUnsafeMutableBufferPointer { ebuf in
                    wg_netstack_dial_tcp(UnsafeMutablePointer(mutating: hostC),
                                         port, ebuf.baseAddress, Int32(ebuf.count))
                }
            }
            if fd < 0 {
                let msg = String(cString: errBuf)
                os_log("dial_tcp %{public}@:%d failed: %{public}@",
                       log: log, type: .error, ip, port, msg)
                flow.closeReadWithError(nil); flow.closeWriteWithError(nil)
                return
            }
            self.pumpTCP(flow: flow, fd: fd)
        }
    }

    private func pumpTCP(flow: NEAppProxyTCPFlow, fd: Int32) {
        // flow → fd
        func readFromFlow() {
            flow.readData { data, err in
                if let err = err { close(fd); flow.closeWriteWithError(err); return }
                guard let data = data, !data.isEmpty else {
                    shutdown(fd, SHUT_WR); return
                }
                let n = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
                if n < 0 { close(fd); flow.closeReadWithError(nil); return }
                readFromFlow()
            }
        }
        // fd → flow
        DispatchQueue.global(qos: .userInitiated).async {
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                if n <= 0 { break }
                let chunk = Data(buf.prefix(Int(n)))
                let sem = DispatchSemaphore(value: 0)
                var writeErr: Error?
                flow.write(chunk) { err in writeErr = err; sem.signal() }
                sem.wait()
                if writeErr != nil { break }
            }
            close(fd)
            flow.closeWriteWithError(nil)
        }
        readFromFlow()
    }

    private func bridgeUDP(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: NWHostEndpoint(hostname: "0.0.0.0", port: "0")) { err in
            if let err = err {
                flow.closeReadWithError(err); flow.closeWriteWithError(err); return
            }
            self.pumpUDP(flow: flow)
        }
    }

    /// Per-datagram dial. Each (datagram, endpoint) pair opens a fresh
    /// netstack UDP conn, sends, awaits one reply, closes. Fine for
    /// DNS / sparse UDP. For high-rate UDP (QUIC) a per-endpoint cache
    /// would be better — TODO when we hit that wall.
    private func pumpUDP(flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { datagrams, endpoints, err in
            if err != nil || datagrams == nil || datagrams!.isEmpty {
                flow.closeReadWithError(nil); return
            }
            for (data, ep) in zip(datagrams!, endpoints ?? []) {
                guard let host = ep as? NWHostEndpoint,
                      let port = Int32(host.port),
                      let ip = self.resolveIPv4(host.hostname) else { continue }
                var errBuf = [CChar](repeating: 0, count: 256)
                let fd = ip.withCString { hostC in
                    errBuf.withUnsafeMutableBufferPointer { ebuf in
                        wg_netstack_dial_udp(UnsafeMutablePointer(mutating: hostC),
                                             port, ebuf.baseAddress, Int32(ebuf.count))
                    }
                }
                if fd < 0 { continue }
                _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
                DispatchQueue.global(qos: .userInitiated).async {
                    var buf = [UInt8](repeating: 0, count: 65536)
                    let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                    close(fd)
                    if n > 0 {
                        flow.writeDatagrams([Data(buf.prefix(Int(n)))], sentBy: [host]) { _ in }
                    }
                }
            }
            self.pumpUDP(flow: flow)
        }
    }

    /// Resolve hostname → IPv4 via the WG tunnel (1.1.1.1:53 over
    /// netstack). Already-IP literals short-circuit on the Go side.
    /// Returns nil if lookup times out / fails.
    private func resolveIPv4(_ s: String) -> String? {
        var outBuf = [CChar](repeating: 0, count: 256)
        let rc = s.withCString { hostC in
            outBuf.withUnsafeMutableBufferPointer { ebuf in
                wg_netstack_resolve(UnsafeMutablePointer(mutating: hostC),
                                    ebuf.baseAddress, Int32(ebuf.count))
            }
        }
        if rc != 0 { return nil }
        return String(cString: outBuf)
    }
}

// MARK: - audit token / process tree

private func pidFromAuditToken(_ data: Data) -> pid_t? {
    guard data.count >= MemoryLayout<audit_token_t>.size else { return nil }
    return data.withUnsafeBytes { raw -> pid_t in
        let token = raw.load(as: audit_token_t.self)
        return audit_token_to_pid(token)
    }
}

private func ancestorMatches(pid: pid_t, signingIdentifier: String) -> Bool {
    var cur = pid
    var depth = 0
    while cur > 1 && depth < 32 {
        if processSigningIdentifier(pid: cur) == signingIdentifier { return true }
        cur = parentPid(of: cur)
        depth += 1
    }
    return false
}

private func parentPid(of pid: pid_t) -> pid_t {
    var info = proc_bsdshortinfo()
    let size = Int32(MemoryLayout<proc_bsdshortinfo>.size)
    let n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, size)
    return n == size ? pid_t(info.pbsi_ppid) : 0
}

// PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN. Hardcoded — Swift's
// Darwin module doesn't expose the macro from sys/proc_info.h.
private let MAX_PROC_PATH = 4096

private func processSigningIdentifier(pid: pid_t) -> String? {
    var path = [CChar](repeating: 0, count: MAX_PROC_PATH)
    let n = proc_pidpath(pid, &path, UInt32(MAX_PROC_PATH))
    guard n > 0, let url = URL(string: "file://" + String(cString: path)) else { return nil }
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
          let code = staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    return dict["identifier"] as? String
}
