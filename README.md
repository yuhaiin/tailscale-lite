# tailscale-lite

**Experimental, independent Tailnet client for [Yuhaiin](https://github.com/yuhaiin/yuhaiin).**

This module embeds Tailscale control-plane coordination and the WireGuard/magicsock encrypted packet engine **without `tsnet`, `ipnlocal`, or gVisor netstack**. The caller supplies a `tun.Device` implemented by its own userspace IP stack, plus a callback that configures the addresses given by the control plane. No system TUN interface or OS route manager is created here.

> This is an initial integration. It has not yet passed the full live Tailnet/Headscale, NAT traversal, control-plane authentication, mobile reconnection, TKA and binary-size validation matrix. Do not ship it as a production replacement for Tailscale.

## Integration contract

```go
// Existing Yuhaiin code can supply its lightweight tunnel adapter, which
// satisfies tun.Device. It must handle address provisioning dynamically.
client, err := tailscalelite.New(tailscalelite.Config{
    Device: adapter,
    StatePath: "/private/path/tailnet.json",
    AuthKey: authKey,
    ControlURL: controlURL,
    Underlay: underlay,
    OnAddresses: configureLightweightStack,
})
if err != nil { return err }
defer client.Close()
if err := client.WaitReady(ctx); err != nil { return err }
// TCP/UDP sockets belong to the caller's lightweight stack, not this library.
```

The explicit `Underlay` is the fork's per-instance transport contract: control HTTP/Noise, DERP, STUN, and WireGuard discovery must use the supplied dial and UDP socket functions. No process-global dial override is installed.

### Current guarantees and restrictions

- Machine identity and node persistence use private state files (`0600`) written by atomic rename.
- A valid control NetMap configures peer routes and packet ACL filters before WireGuard is enabled.
- Longest-prefix route lookup, ambiguous-route rejection and no system-network dial fallback.
- Missing/invalid mapping, expired keys and Tailnet Lock requirements are intended to fail closed.
- All IPv4/IPv6 application sockets are handled by the host stack; this module has no DNS listener.
- Peers are initially filtered for expiration, jail and unsigned-only access; the remaining Tailscale capability/TKA semantics require further validation.
- Unimplemented: TKA verification, fully integrated MagicDNS and configuration migration from `tailscaled.state`, production interoperability testing, gVisor-free binary size comparison.

### Development

```bash
GOFLAGS='-tags=ts_omit_netstack,ts_omit_gro' go test -race ./...
GOFLAGS='-tags=ts_omit_netstack,ts_omit_gro' go list -deps ./... | grep '^gvisor.dev/gvisor' && exit 1
```

Tailscale's currently pinned fork is the same one used by Yuhaiin. Upstream code is retained through standard Go module dependencies rather than copied into this repository. Follow the BSD-3-Clause upstream license for Tailscale and relevant dependency licenses.

## Design

See [docs/architecture.md](docs/architecture.md).
