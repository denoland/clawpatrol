# clawpatrol macOS — `clawpatrol run` per-process tunnel

NETransparentProxyProvider system extension. Intercepts every outbound
TCP/UDP flow, walks the source process's PPID chain back to
`dev.clawpatrol.app`, tunnels matching flows through a userspace
WireGuard + gVisor netstack to the gateway. Non-matching flows
passthrough untouched. Whole-machine mode (`install --whole-machine`)
short-circuits the filter and tunnels everything.

## Layout

```
macos/
  project.yml                            # xcodegen spec
  install.sh                             # build + cp to /Applications + LS rebuild
  Clawpatrol/                            # parent app (CLI helper)
    main.swift                           # install / start / stop / wipe / run
    Info.plist                           # NSSystemExtensionUsageDescription
    Clawpatrol.entitlements
  ClawpatrolExtension/                   # the system extension
    main.swift                           # NEProvider.startSystemExtensionMode()
    Provider.swift                       # TransparentProxyProvider + flow bridge
    BridgingHeader.h                     # libwgnetstack.h + libbsm + libproc
    Info.plist                           # NEExtensionPointIdentifier=app-proxy
    ClawpatrolExtension.entitlements     # app-proxy-provider, app-groups
  netstack/                              # Go cgo c-archive
    wgnetstack.go                        # wireguard-go + gVisor netstack +
                                         # cgo bridge (dial_tcp/udp/resolve)
    go.mod / go.sum
```

The Go module embeds wireguard-go + gVisor netstack and exposes a C
ABI: `wg_netstack_init`, `wg_netstack_dial_tcp`, `wg_netstack_dial_udp`,
`wg_netstack_resolve`, `wg_netstack_close`. Each dial returns one end
of a unix socketpair; the Go side pumps bytes between the gVisor
connection and the fd. Provider.swift hands off bytes from each
intercepted `NEAppProxyTCPFlow` / `UDPFlow` to those fds.

Same wireguard-go + gvisor stack the gateway uses (`../wireguard.go`),
client side.

## Build

Pre-reqs:
- macOS 13+, Apple Silicon
- Xcode 15+
- [xcodegen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- Go 1.22+ (`brew install go`)
- Apple Development cert + manually-created (non-XcodeManaged)
  provisioning profiles `Clawpatrol App Dev` and `Clawpatrol Extension Dev`
  in your Apple Developer account, both with App Groups +
  Network Extensions capabilities

```sh
cd macos
xcodegen generate
./install.sh                 # builds, copies to /Applications, rebuilds LS
```

## Use

```sh
sudo systemextensionsctl developer on    # one-time, allows Apple Dev sysexts

/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol install
# → System Settings → Login Items & Extensions → Network Extensions
#   → toggle Clawpatrol on (one-time approval)

/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol start \
  ~/.config/clawpatrol/wg.conf

# Verify per-process scoping:
/Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol run -- curl https://api.ipify.org
# → gateway IP
curl https://api.ipify.org
# → real IP
```

Subcommands:
- `install [--whole-machine]` — submit OSSystemExtensionRequest, save
  proxy profile (default per-process, optional whole-machine)
- `start <wg-conf>` — load wg-quick conf, fire startVPNTunnel
- `stop` — stopVPNTunnel
- `run -- <cmd> [args...]` — fork+exec cmd as child of clawpatrol so
  the extension's PPID walk picks it up
- `wipe` — remove every NETunnelProviderManager + NETransparentProxyManager
  this app has registered (escape hatch when System Settings is broken)

## Why these specific choices

- **NETransparentProxyProvider, not NEPacketTunnelProvider**: per-app VPN
  via NEAppRule.matchTools requires an MDM-pushed appmapping payload on
  macOS — NETestAppMapping is silently ignored. Transparent proxy gets
  `flow.metaData.sourceAppAuditToken` for free; we filter ourselves.
- **system-extension, not app-extension**: NETransparentProxyProvider on
  macOS *must* be a sysext. App-extension form refuses to launch
  (`OSLaunchdErrorDomain Code=137`).
- **app-proxy-provider, not packet-tunnel-provider**: app-proxy is
  treated as removable-with-auth by sysextd → activates with Apple
  Development cert + dev mode. Packet-tunnel is "nonRemovable" → only
  activates with notarized Developer ID + Apple-granted entitlement.
- **PRODUCT_NAME = bundle ID for the extension target**: sysextd matches
  embedded `.systemextension` bundle basenames against the requested
  identifier. Default product name produces `ClawpatrolExtension.systemextension`
  → "Extension not found in App bundle" on activation.
- **Manual non-XcodeManaged profiles**: Xcode's auto-generated Mac Team
  Provisioning Profiles aren't trusted by sysextd's path gate.
- **App in `/Applications`, not from DerivedData**: sysextd's
  "/Applications-only" check resolves the parent bundle via
  LaunchServices. `install.sh` rebuilds the LS DB to drop the stale
  DerivedData entry.
