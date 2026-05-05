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

        // Block until WireGuard handshake completes. setTunnelNetwork-
        // Settings succeeding does NOT mean the WG underlay is up — it
        // only means the OS accepted the proxy rules. Without this gate
        // the first user flow's SYN races wireguard-go's handshake and
        // the visible latency is dominated by the TCP retransmit timer
        // (3s, 6s, 12s, ...). 10s budget covers a healthy handshake;
        // longer than that, network is broken and we should fail loudly
        // rather than serve a stalled tunnel.
        let hsq = DispatchQueue.global(qos: .userInitiated)
        hsq.async {
            let hrc = wg_netstack_wait_handshake(10000)
            if hrc != 0 {
                os_log("wg handshake timeout (10s)", log: log, type: .error)
                completionHandler(NSError(domain: "clawpatrol", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "wg handshake timeout — gateway unreachable?"]))
                return
            }
            os_log("wg handshake complete", log: log, type: .info)
            DispatchQueue.main.async {
                self.applyNetworkSettings(completionHandler: completionHandler)
            }
        }
    }

    private func applyNetworkSettings(completionHandler: @escaping (Error?) -> Void) {
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
        // cid → flow (recv).
        //
        // Run on a dedicated pthread, NOT GCD. wg_netstack_recv blocks
        // on gVisor TCPConn.Read — it parks indefinitely waiting for
        // bytes. GCD's global queue has a fixed worker pool (~64 on
        // macOS); under whole-machine load with hundreds of long-lived
        // keep-alive connections, every blocked recv pins one worker
        // and the pool exhausts. New flows' read closures never get
        // scheduled → the symptom is "browser tabs hang for 30s, then
        // suddenly all complete at once when something times out".
        // Foundation's Thread bypasses the pool: each flow gets its
        // own kernel thread (8KB Go-side goroutine + ~520KB darwin
        // pthread stack). Cost is real but bounded by active flows.
        let recvThread = Thread {
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
        recvThread.stackSize = 256 * 1024
        recvThread.qualityOfService = .userInitiated
        recvThread.name = "wgflow.recv.\(cid)"
        recvThread.start()
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
                // Dedicated pthread for the same GCD-pool-exhaustion
                // reason as pumpTCP. UDP path is one-reply-per-dial so
                // the thread is short-lived, but DNS amplification +
                // QUIC racing on whole-machine still hits the pool cap
                // when reads stack up.
                let udpThread = Thread {
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
                udpThread.stackSize = 256 * 1024
                udpThread.qualityOfService = .userInitiated
                udpThread.name = "wgflow.udp.\(cid)"
                udpThread.start()
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

// Walk PPID chain looking for an ancestor that's "us":
//   - path under /Applications/Clawpatrol.app/  (GUI app + sysext host)
//   - OR basename == "clawpatrol"               (standalone CLI from
//                                                 install.sh, lives at
//                                                 $HOME/.local/bin by
//                                                 default but operators
//                                                 may override via
//                                                 CLAWPATROL_PREFIX)
// SecCode-based identifier matching (the obvious approach) is
// unreliable in sysext context — SecCodeCopySigningInformation works
// inconsistently. Path + basename matching is good enough.
private let parentBundlePathPrefix = "/Applications/Clawpatrol.app/"
private let cliBinaryName = "clawpatrol"
private let MAX_PROC_PATH = 4096
private let bsdInfoSize = Int32(MemoryLayout<proc_bsdinfo>.size)

private func processIsClawpatrol(path: String) -> Bool {
    if path.hasPrefix(parentBundlePathPrefix) { return true }
    if let slash = path.lastIndex(of: "/") {
        let after = path.index(after: slash)
        if path[after...] == cliBinaryName { return true }
    } else if path == cliBinaryName {
        return true
    }
    return false
}

// Per-pid cache for ancestorMatches. proc_pidpath + proc_pidinfo are
// syscalls; on whole-machine every flow walks the chain and hammers
// these (5-10 syscalls per flow × thousands of flows/sec). Cache the
// terminal verdict (matches?) keyed by pid with a 5s TTL — pids get
// recycled fast on macOS, so don't keep stale entries.
private struct ancestorCacheEntry { let matches: Bool; let expires: Date }
private var ancestorCache: [pid_t: ancestorCacheEntry] = [:]
private let ancestorCacheLock = NSLock()
private let ancestorCacheTTL: TimeInterval = 5

private func ancestorMatches(pid: pid_t) -> Bool {
    let now = Date()
    ancestorCacheLock.lock()
    if let e = ancestorCache[pid], e.expires > now {
        ancestorCacheLock.unlock()
        return e.matches
    }
    ancestorCacheLock.unlock()

    // Start at the parent — the process itself is never "its own
    // ancestor". Without this, any process whose binary is named
    // "clawpatrol" (including the gateway) would match on the first
    // iteration and have its outbound flows tunneled back into itself.
    guard let first = parentPid(of: pid), first != pid else {
        return false
    }
    var cur = first
    var visited = Set<pid_t>()
    var matches = false
    while cur > 1 && !visited.contains(cur) {
        visited.insert(cur)
        if let path = processBinaryPath(pid: cur),
           processIsClawpatrol(path: path) {
            matches = true
            break
        }
        guard let ppid = parentPid(of: cur), ppid != cur else { break }
        cur = ppid
    }

    ancestorCacheLock.lock()
    ancestorCache[pid] = ancestorCacheEntry(matches: matches, expires: now.addingTimeInterval(ancestorCacheTTL))
    if ancestorCache.count > 4096 {
        // Cap memory: drop expired entries on overflow.
        ancestorCache = ancestorCache.filter { $0.value.expires > now }
    }
    ancestorCacheLock.unlock()
    return matches
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
