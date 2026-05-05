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
        return ancestorMatches(pid: pid)
    }

    private func bridgeTCP(_ flow: NEAppProxyTCPFlow) {
        guard let endpoint = flow.remoteEndpoint as? NWHostEndpoint,
              let port = Int32(endpoint.port) else {
            flow.closeReadWithError(nil); flow.closeWriteWithError(nil); return
        }
        guard let ip = resolveIPv4(endpoint.hostname) else {
            os_log("DNS unsupported for %{public}@; dropping", log: log, type: .error, endpoint.hostname)
            flow.closeReadWithError(nil); flow.closeWriteWithError(nil); return
        }

        flow.open(withLocalEndpoint: nil) { err in
            if let err = err {
                flow.closeReadWithError(err); flow.closeWriteWithError(err); return
            }
            var errBuf = [CChar](repeating: 0, count: 256)
            let cid = ip.withCString { hostC in
                errBuf.withUnsafeMutableBufferPointer { ebuf in
                    wg_netstack_tcp_connect(UnsafeMutablePointer(mutating: hostC),
                                            port, ebuf.baseAddress, Int32(ebuf.count))
                }
            }
            if cid < 0 {
                let msg = String(cString: errBuf)
                os_log("tcp_connect %{public}@:%d failed: %{public}@",
                       log: log, type: .error, ip, port, msg)
                flow.closeReadWithError(nil); flow.closeWriteWithError(nil)
                return
            }
            self.pumpTCP(flow: flow, cid: cid)
        }
    }

    // pumpTCP bridges a flow's read/write to the cgo conn-handle API.
    // No fds, no socketpair — just two recursive read loops calling
    // wg_netstack_send / wg_netstack_recv with the conn ID. The Go
    // side stores one gVisor TCPConn per ID, so we trade socketpair
    // pressure (RLIMIT_NOFILE on whole-machine) for one Go goroutine
    // blocked on Read per direction. Goroutines are 8KB stack each
    // and Go schedules them onto a small worker pool.
    private func pumpTCP(flow: NEAppProxyTCPFlow, cid: Int64) {
        // Dedicated background queue per flow for the send path. Apple
        // serializes flow operations on a private per-flow queue; if
        // we'd called the (potentially-blocking) wg_netstack_send
        // directly inside the readData callback, NE couldn't invoke
        // the write-side callback for this same flow until send
        // returned — full deadlock under TCP back-pressure (gconn's
        // send buffer fills, send blocks, send-callback queue jams,
        // recv-side flow.write completion never fires, recv loop's
        // semaphore never signals → entire flow hangs until idle
        // close at the browser keep-alive limit (~30s).
        let sendQueue = DispatchQueue(label: "wgflow.send.\(cid)", qos: .userInitiated)

        // flow → cid (send)
        func readFromFlow() {
            flow.readData { data, err in
                if err != nil { wg_netstack_close_conn(cid); flow.closeWriteWithError(err); return }
                guard let data = data, !data.isEmpty else {
                    wg_netstack_close_conn(cid); return
                }
                sendQueue.async {
                    let n = data.withUnsafeBytes { ptr -> Int32 in
                        wg_netstack_send(cid,
                                         UnsafeMutablePointer(mutating: ptr.baseAddress!.assumingMemoryBound(to: CChar.self)),
                                         Int32(data.count))
                    }
                    if n < 0 {
                        wg_netstack_close_conn(cid); flow.closeReadWithError(nil); return
                    }
                    readFromFlow()
                }
            }
        }
        // cid → flow (recv)
        DispatchQueue.global(qos: .userInitiated).async {
            var buf = [CChar](repeating: 0, count: 65536)
            while true {
                let n = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
                    wg_netstack_recv(cid, ptr.baseAddress, Int32(ptr.count))
                }
                if n <= 0 { break }
                let chunk = buf.withUnsafeBufferPointer { ptr in
                    Data(bytes: ptr.baseAddress!, count: Int(n))
                }
                let sem = DispatchSemaphore(value: 0)
                var writeErr: Error?
                flow.write(chunk) { err in writeErr = err; sem.signal() }
                sem.wait()
                if writeErr != nil { break }
            }
            wg_netstack_close_conn(cid)
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
                let cid = ip.withCString { hostC in
                    errBuf.withUnsafeMutableBufferPointer { ebuf in
                        wg_netstack_udp_connect(UnsafeMutablePointer(mutating: hostC),
                                                port, ebuf.baseAddress, Int32(ebuf.count))
                    }
                }
                if cid < 0 { continue }
                _ = data.withUnsafeBytes { ptr -> Int32 in
                    wg_netstack_send(cid,
                                     UnsafeMutablePointer(mutating: ptr.baseAddress!.assumingMemoryBound(to: CChar.self)),
                                     Int32(data.count))
                }
                DispatchQueue.global(qos: .userInitiated).async {
                    var buf = [CChar](repeating: 0, count: 65536)
                    let n = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
                        wg_netstack_recv(cid, ptr.baseAddress, Int32(ptr.count))
                    }
                    wg_netstack_close_conn(cid)
                    if n > 0 {
                        let chunk = buf.withUnsafeBufferPointer { ptr in
                            Data(bytes: ptr.baseAddress!, count: Int(n))
                        }
                        flow.writeDatagrams([chunk], sentBy: [host]) { _ in }
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

private func pidFromAuditToken(_ data: Data) -> pid_t? {
    guard data.count >= MemoryLayout<audit_token_t>.size else { return nil }
    return data.withUnsafeBytes { raw -> pid_t in
        let token = raw.load(as: audit_token_t.self)
        return audit_token_to_pid(token)
    }
}

// Walk PPID chain looking for an ancestor whose executable path
// lives under /Applications/Clawpatrol.app/. SecCode-based identifier
// matching (the obvious approach) is unreliable in sysext context —
// SecCodeCopySigningInformation works inconsistently. Path matching
// is good enough: the only way an ancestor binary is at our app path
// is if it's our process.
private let parentBundlePathPrefix = "/Applications/Clawpatrol.app/"
private let MAX_PROC_PATH = 4096
private let bsdInfoSize = Int32(MemoryLayout<proc_bsdinfo>.size)

private func ancestorMatches(pid: pid_t) -> Bool {
    var cur = pid
    var visited = Set<pid_t>()
    while cur > 1 && !visited.contains(cur) {
        visited.insert(cur)
        if let path = processBinaryPath(pid: cur),
           path.hasPrefix(parentBundlePathPrefix) {
            return true
        }
        guard let ppid = parentPid(of: cur), ppid != cur else { break }
        cur = ppid
    }
    return false
}

private func parentPid(of pid: pid_t) -> pid_t? {
    var info = proc_bsdinfo()
    let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, bsdInfoSize)
    return n == bsdInfoSize ? pid_t(info.pbi_ppid) : nil
}

private func processBinaryPath(pid: pid_t) -> String? {
    var path = [CChar](repeating: 0, count: MAX_PROC_PATH)
    let n = proc_pidpath(pid, &path, UInt32(MAX_PROC_PATH))
    return n > 0 ? String(cString: path) : nil
}
