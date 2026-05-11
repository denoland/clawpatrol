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

        // IPC listener — synchronous handshake from clawpatrol
        // CLI registers its PID before exec'ing the wrapped child,
        // eliminating the start-of-flow race a file-watcher would
        // have. Idempotent if startProxy fires twice.
        startSessionListener()
        startSessionReaper()

        // Apply network settings immediately — do NOT wait for the WG
        // handshake before calling completionHandler. The old approach
        // (10s wg_netstack_wait_handshake on the critical path) caused
        // startProxy to fail whenever the gateway was temporarily
        // unreachable: laptop wake-from-sleep (WG peer needs a new
        // handshake) or airport/captive-portal WiFi (the portal blocks
        // WG's UDP before you authenticate). On failure macOS enters a
        // reasserting loop that blocks ALL traffic — including bypassUDP
        // DNS — until the proxy reconnects or the user disables it.
        //
        // Moving the handshake off the critical path means:
        //   • bypassUDP flows (system DNS, QUIC, etc.) always work.
        //   • Tunnel flows (bridgeTCP/bridgeUDP for clawpatrol children)
        //     fail fast via the cgo return code when WG is not yet up.
        //   • Once the handshake completes, tunnel flows start working
        //     without any user action.
        applyNetworkSettings(completionHandler: completionHandler)

        // Background handshake — logging only, not on the critical path.
        DispatchQueue.global(qos: .utility).async {
            let hrc = wg_netstack_wait_handshake(30000)
            if hrc != 0 {
                os_log("wg handshake did not complete in 30s — tunnel flows will fail until gateway is reachable", log: log, type: .error)
            } else {
                os_log("wg handshake complete", log: log, type: .info)
            }
        }
    }

    private func applyNetworkSettings(completionHandler: @escaping (Error?) -> Void) {
        // Claim TCP+UDP everywhere. UDP cannot return false safely
        // (radar r.98382363 race → ~30s Chrome QUIC stall), so non-
        // tunnel UDP is bypassed via a real host socket in handleNew-
        // Flow. Per-process clawpatrol children's UDP/53 is tunneled
        // through the gateway, enabling SSH endpoint VIP DNS.
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let included: [NENetworkRule] = [
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                          localNetwork: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                          localNetwork: nil, localPrefix: 0,
                          protocol: .UDP, direction: .outbound),
        ]
        // Exclude RFC1918, loopback, link-local, and multicast so captive
        // portal DNS/HTTP, local network services, and mDNS bypass the
        // extension entirely. Without RFC1918 exclusions, airport WiFi
        // captive portals break: the portal's DNS server (typically
        // 192.168.x.x or 10.x.x.x) is reachable but the portal HTTP
        // server is on the same subnet — bypassUDP handles DNS fine, but
        // excluding the subnet avoids the NE claiming the flow at all,
        // which is more robust (no DispatchSource on the real socket needed).
        let excludedHosts: [(String, Int)] = [
            ("10.0.0.0",    8),   // RFC1918
            ("172.16.0.0",  12),  // RFC1918
            ("192.168.0.0", 16),  // RFC1918
            ("127.0.0.0",   8),   // loopback
            ("169.254.0.0", 16),  // link-local / APIPA
            ("224.0.0.0",   4),   // IPv4 multicast
            ("ff00::",      8),   // IPv6 multicast
            ("::1",         128), // IPv6 loopback
            ("fe80::",      10),  // IPv6 link-local
        ]
        settings.excludedNetworkRules = excludedHosts.flatMap { (host, prefix) -> [NENetworkRule] in
            [
                NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: host, port: "0"),
                              remotePrefix: prefix, localNetwork: nil, localPrefix: 0,
                              protocol: .TCP, direction: .outbound),
                NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: host, port: "0"),
                              remotePrefix: prefix, localNetwork: nil, localPrefix: 0,
                              protocol: .UDP, direction: .outbound),
            ]
        }
        settings.includedNetworkRules = included
        setTunnelNetworkSettings(settings, completionHandler: completionHandler)
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        wg_netstack_close()
        completionHandler()
    }

    // Sleep/wake — without these overrides macOS may restart the
    // extension when the network interface comes back up after sleep,
    // causing startProxy to be called again. Setting reasserting=true
    // during sleep tells the runtime the tunnel is temporarily down;
    // clearing it on wake avoids a full stop/start cycle.
    override func sleep(completionHandler: @escaping () -> Void) {
        reasserting = true
        completionHandler()
    }

    override func wake() {
        // WireGuard auto-initiates a new handshake on the next keepalive
        // tick (≤10s, per persistent_keepalive_interval). Clear reasserting
        // immediately — bypassUDP flows don't need the WG tunnel and will
        // work right away. Tunnel-side flows (clawpatrol children) fail fast
        // via the cgo return code until the handshake completes.
        reasserting = false
        os_log("wake — wg will reconnect via keepalive", log: log, type: .info)
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let tunnel = shouldTunnel(flow)
        if let tcp = flow as? NEAppProxyTCPFlow {
            if !tunnel { return false }
            bridgeTCP(tcp); return true
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            // Claim every UDP flow. Returning false on UDP races kernel
            // detach (radar r.98382363) → ~30s Chrome QUIC stall.
            // Tunnel-side flows go through the gateway; non-tunnel
            // flows are bypassed by re-emitting datagrams via a real
            // host UDP socket (Mozilla VPN's bypassudpflow pattern).
            if !tunnel { bypassUDP(udp); return true }
            bridgeUDP(udp); return true
        }
        return false
    }

    private func bypassUDP(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: nil) { err in
            if err != nil {
                flow.closeReadWithError(err); flow.closeWriteWithError(err); return
            }
            BypassUDP(flow: flow).start()
        }
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
                    // 15s: covers one WG keepalive cycle (≤10s) + handshake
                    // (~2s). Fails fast if gateway is unreachable rather than
                    // blocking the flow indefinitely (whole-machine wake stall).
                    wg_netstack_tcp_connect(UnsafeMutablePointer(mutating: hostC),
                                            port, 15000, ebuf.baseAddress, Int32(ebuf.count))
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

// Session registry — populated synchronously by `clawpatrol run`
// (Go) or `Clawpatrol run` (Swift helper) over the unix socket at
// sessionSockPath before the wrapped child exec's. Mirrors unclaw's
// SessionRegistry, transport-agnostic so the Go CLI can speak it
// without an ObjC runtime.
//
// Wire protocol (newline-framed ASCII):
//   client → "register <pid>\n"      ext → "ok\n"
//   client → "unregister <pid>\n"    ext → "ok\n"
// Unknown verbs reply "err\n". Connection close = no-op; lingering
// PIDs are reaped via kill(pid, 0).
//
// Why /tmp: sysext sandbox allows /private/tmp (alias /tmp);
// /var/run requires root for both bind AND connect, but the CLI runs
// as user. /tmp is world-RW which is fine — registering a non-
// clawpatrol PID just means the ext might tunnel that PID's flows,
// a local authz concern only the host's user controls anyway.
let sessionSockPath = "/tmp/clawpatrol.sock"

private var sessionPidsSet: Set<pid_t> = []
private let sessionPidsLock = NSLock()

private func sessionPids() -> Set<pid_t> {
    sessionPidsLock.lock()
    defer { sessionPidsLock.unlock() }
    return sessionPidsSet
}
private func sessionRegister(_ pid: pid_t) {
    sessionPidsLock.lock()
    sessionPidsSet.insert(pid)
    sessionPidsLock.unlock()
    // Do NOT invalidate the ancestor cache here. The cache stores
    // "was this pid a descendant of any session pid I checked?". A
    // new session pid only changes the verdict for processes that
    // descend from it — and those processes don't exist yet at
    // register time (the CLI registers before exec'ing the child).
    // Dumping the cache on every register made the first 100ms
    // after `clawpatrol run` a cold-cache storm: every Chrome
    // helper, system service, and background daemon re-walked its
    // full PPID chain via proc_pidinfo, the per-flow handleNewFlow
    // latency spiked, and macOS started stalling unrelated UDP
    // sockets.
}
private func sessionUnregister(_ pid: pid_t) {
    sessionPidsLock.lock()
    sessionPidsSet.remove(pid)
    sessionPidsLock.unlock()
    // On unregister evict cache entries that pointed to this
    // session pid — their descendants are no longer tunneled. Walk
    // the cache once and drop the matches; cheaper than removeAll
    // because most entries are unrelated negatives.
    ancestorCacheLock.lock()
    if !ancestorCache.isEmpty {
        for (k, v) in ancestorCache where v.sessionPID == pid {
            ancestorCache.removeValue(forKey: k)
        }
    }
    ancestorCacheLock.unlock()
}

// Reaper: every 5s drop registered PIDs whose process is gone.
// Covers SIGKILLed CLIs that didn't get to send unregister.
private var sessionReaperTimer: DispatchSourceTimer?
private func startSessionReaper() {
    let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    t.schedule(deadline: .now() + 5, repeating: 5)
    t.setEventHandler {
        for pid in sessionPids() where kill(pid, 0) != 0 {
            sessionUnregister(pid)
        }
    }
    t.resume()
    sessionReaperTimer = t
}

private var sessionListenFD: Int32 = -1
private func startSessionListener() {
    unlink(sessionSockPath)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = sessionSockPath.utf8CString
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { p in
            for (i, b) in pathBytes.enumerated() {
                p.advanced(by: i).pointee = b
            }
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { ap -> Int32 in
        ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.bind(fd, sa, len)
        }
    }
    if rc != 0 { Darwin.close(fd); return }
    chmod(sessionSockPath, 0o666)
    if listen(fd, 16) != 0 { Darwin.close(fd); return }
    sessionListenFD = fd
    DispatchQueue.global(qos: .userInitiated).async {
        while true {
            let cfd = Darwin.accept(fd, nil, nil)
            if cfd < 0 { continue }
            DispatchQueue.global(qos: .userInitiated).async {
                serviceSessionClient(cfd)
            }
        }
    }
}

private func serviceSessionClient(_ fd: Int32) {
    defer { Darwin.close(fd) }
    var buf = [UInt8](repeating: 0, count: 256)
    var pending = ""
    while true {
        let n = buf.withUnsafeMutableBufferPointer { p -> Int in
            Darwin.read(fd, p.baseAddress, p.count)
        }
        if n <= 0 { return }
        pending += String(bytes: buf[0..<n], encoding: .utf8) ?? ""
        while let nl = pending.firstIndex(of: "\n") {
            let line = String(pending[..<nl])
            pending = String(pending[pending.index(after: nl)...])
            let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
            var reply = "err\n"
            if parts.count == 2, let pid = pid_t(parts[1]) {
                switch parts[0] {
                case "register":   sessionRegister(pid);   reply = "ok\n"
                case "unregister": sessionUnregister(pid); reply = "ok\n"
                default: break
                }
            }
            _ = reply.withCString { cs in
                Darwin.write(fd, cs, strlen(cs))
            }
        }
    }
}

// Ancestor match — walk PPID chain via proc_pidinfo only (no
// proc_pidpath; Set<pid_t> membership instead of string compares).
// Mirrors unclaw/UnclawExtension/ProcessTree.swift. The path-based
// check we used previously was the actual cause of the
// Chrome-hangs-during-clawpatrol-run symptom: proc_pidpath is
// ~50–200µs per level, and Chrome spawns many helper processes whose
// flows all hit handleNewFlow. Walking 5–10 levels × hundreds of
// concurrent flows × the path syscall = handleNewFlow returning
// slowly enough to mis-route UDP. proc_pidinfo is ~5µs and Set
// membership is nanoseconds.
private let bsdInfoSize = Int32(MemoryLayout<proc_bsdinfo>.size)

// ancestorCache memoizes the verdict for each (pid, start_time) seen
// in handleNewFlow. start_time is included in the key so the cache
// is immune to PID reuse — macOS recycles PIDs aggressively under
// fork-heavy workloads and a stale entry under bare-pid keying could
// flip a non-clawpatrol flow into "tunneled" or vice versa.
//
// Pattern matches unclaw's SessionRegistry.swift:57-61 (start-time
// validation on read) and Apple Endpoint Security guidance (audit
// tokens are the canonical anti-reuse key, but pidversion isn't
// exposed via proc_pidinfo so start_time is the next best thing).
//
// 60s TTL: long-running browser helpers (Chrome, Slack) shouldn't
// re-walk their PPID chain every few seconds. The reaper already
// drops session pids within 5s of process exit, so a stale "matched"
// verdict is at most 5s out of date.
private struct ancestorCacheKey: Hashable {
    let pid: pid_t
    let startTimeSec: UInt64
}
private struct ancestorCacheEntry { let sessionPID: pid_t; let expires: Date }
private var ancestorCache: [ancestorCacheKey: ancestorCacheEntry] = [:]
private let ancestorCacheLock = NSLock()
private let ancestorCacheTTL: TimeInterval = 60

// procStartTime returns the start_time field of proc_bsdinfo for pid.
// 0 on failure — keep the entry in cache anyway under the bare-pid
// key so a transient lookup miss doesn't disable caching.
private func procStartTime(_ pid: pid_t) -> UInt64 {
    var info = proc_bsdinfo()
    let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, bsdInfoSize)
    return n == bsdInfoSize ? UInt64(info.pbi_start_tvsec) : 0
}

private func ancestorMatches(pid: pid_t) -> Bool {
    let key = ancestorCacheKey(pid: pid, startTimeSec: procStartTime(pid))
    let now = Date()
    ancestorCacheLock.lock()
    if let e = ancestorCache[key], e.expires > now {
        let v = e.sessionPID != 0
        ancestorCacheLock.unlock()
        return v
    }
    ancestorCacheLock.unlock()

    let registered = sessionPids()
    if registered.isEmpty { return false }

    // Start at the parent — the process itself is never "its own
    // ancestor".
    guard let first = parentPid(of: pid), first != pid else { return false }
    var cur = first
    var visited = Set<pid_t>()
    var sessionPID: pid_t = 0
    while cur > 1 && !visited.contains(cur) {
        visited.insert(cur)
        if registered.contains(cur) {
            sessionPID = cur
            break
        }
        guard let ppid = parentPid(of: cur), ppid != cur else { break }
        cur = ppid
    }

    ancestorCacheLock.lock()
    ancestorCache[key] = ancestorCacheEntry(sessionPID: sessionPID, expires: now.addingTimeInterval(ancestorCacheTTL))
    if ancestorCache.count > 4096 {
        ancestorCache = ancestorCache.filter { $0.value.expires > now }
    }
    ancestorCacheLock.unlock()
    return sessionPID != 0
}

private func parentPid(of pid: pid_t) -> pid_t? {
    var info = proc_bsdinfo()
    let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, bsdInfoSize)
    return n == bsdInfoSize ? pid_t(info.pbi_ppid) : nil
}

// BypassUDP — non-tunnel UDP flows from non-clawpatrol processes.
// We claim the flow (rather than return false) to dodge the radar
// r.98382363 race, then pump datagrams between the flow and a real
// host UDP socket. Caller's UDP socket sees normal traffic; QUIC,
// mDNS, DNS, NTP, etc. all work unchanged.
final class BypassUDP {
    private static var live = Set<BypassUDP>()
    private static let liveLock = NSLock()

    private let flow: NEAppProxyUDPFlow
    private var sock: Int32 = -1
    private var recvSource: DispatchSourceRead?
    private let recvQueue = DispatchQueue(label: "bypass.udp.recv", qos: .userInitiated)

    init(flow: NEAppProxyUDPFlow) { self.flow = flow }

    func start() {
        BypassUDP.liveLock.lock()
        BypassUDP.live.insert(self)
        BypassUDP.liveLock.unlock()
        // AF_INET6 dual-stack so v4-mapped addresses route correctly.
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        if sock < 0 { closeAll(); return }
        var off: Int32 = 0
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &off, socklen_t(MemoryLayout<Int32>.size))
        // Non-blocking + close-on-exec.
        var fl = fcntl(sock, F_GETFL, 0); fl |= O_NONBLOCK; _ = fcntl(sock, F_SETFL, fl)
        _ = fcntl(sock, F_SETFD, FD_CLOEXEC)

        let src = DispatchSource.makeReadSource(fileDescriptor: sock, queue: recvQueue)
        src.setEventHandler { [weak self] in self?.recvOne() }
        src.setCancelHandler { [weak self] in
            guard let s = self, s.sock >= 0 else { return }
            close(s.sock); s.sock = -1
        }
        src.resume()
        recvSource = src
        readFromFlow()
    }

    private func readFromFlow() {
        flow.readDatagrams { [weak self] data, endpoints, err in
            guard let self = self else { return }
            if err != nil || data == nil || data!.isEmpty {
                self.closeAll(); return
            }
            for (d, ep) in zip(data!, endpoints ?? []) {
                guard let host = ep as? NWHostEndpoint else { continue }
                self.sendOne(d, to: host)
            }
            self.readFromFlow()
        }
    }

    private func sendOne(_ data: Data, to host: NWHostEndpoint) {
        var ss = sockaddr_storage()
        guard fillSockaddr(&ss, host: host.hostname, port: host.port) else { return }
        let slen = socklen_t(ss.ss_len)
        withUnsafePointer(to: &ss) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                _ = data.withUnsafeBytes { buf in
                    sendto(self.sock, buf.baseAddress, buf.count, 0, sa, slen)
                }
            }
        }
    }

    private func recvOne() {
        var buf = [UInt8](repeating: 0, count: 65535)
        var ss = sockaddr_storage()
        var slen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let n = buf.withUnsafeMutableBufferPointer { bp -> Int in
            withUnsafeMutablePointer(to: &ss) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(sock, bp.baseAddress, bp.count, 0, sa, &slen)
                }
            }
        }
        if n <= 0 { return }
        guard let src = sockaddrToHostEndpoint(&ss) else { return }
        let chunk = Data(bytes: buf, count: n)
        flow.writeDatagrams([chunk], sentBy: [src]) { _ in }
    }

    private func closeAll() {
        recvSource?.cancel()
        recvSource = nil
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        BypassUDP.liveLock.lock()
        BypassUDP.live.remove(self)
        BypassUDP.liveLock.unlock()
    }
}

extension BypassUDP: Hashable {
    static func == (lhs: BypassUDP, rhs: BypassUDP) -> Bool { lhs === rhs }
    func hash(into hasher: inout Hasher) { hasher.combine(ObjectIdentifier(self)) }
}

private func fillSockaddr(_ ss: inout sockaddr_storage, host: String, port: String) -> Bool {
    guard let p = UInt16(port) else { return false }
    // AF_INET6 + AI_V4MAPPED: IPv4 addresses are returned as IPv4-mapped
    // sockaddr_in6 (::ffff:x.x.x.x), which sendto accepts on the dual-stack
    // AF_INET6 socket. AF_UNSPEC returns sockaddr_in for IPv4, which sendto
    // rejects with EAFNOSUPPORT — silently dropped → all UDP bypasses fail.
    var hints = addrinfo(ai_flags: AI_NUMERICHOST | AI_NUMERICSERV | AI_V4MAPPED,
                         ai_family: AF_INET6, ai_socktype: SOCK_DGRAM,
                         ai_protocol: IPPROTO_UDP, ai_addrlen: 0,
                         ai_canonname: nil, ai_addr: nil, ai_next: nil)
    var res: UnsafeMutablePointer<addrinfo>?
    if getaddrinfo(host, port, &hints, &res) != 0 || res == nil { return false }
    defer { freeaddrinfo(res) }
    let info = res!.pointee
    memcpy(&ss, info.ai_addr, Int(info.ai_addrlen))
    ss.ss_len = UInt8(info.ai_addrlen)
    _ = p
    return true
}

private func sockaddrToHostEndpoint(_ ss: inout sockaddr_storage) -> NWHostEndpoint? {
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    var serv = [CChar](repeating: 0, count: Int(NI_MAXSERV))
    let slen = socklen_t(ss.ss_len)
    let rc = withUnsafePointer(to: &ss) { ptr -> Int32 in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            getnameinfo(sa, slen,
                        &host, socklen_t(host.count),
                        &serv, socklen_t(serv.count),
                        NI_NUMERICHOST | NI_NUMERICSERV)
        }
    }
    if rc != 0 { return nil }
    return NWHostEndpoint(hostname: String(cString: host), port: String(cString: serv))
}
