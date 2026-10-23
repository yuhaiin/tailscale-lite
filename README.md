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
    // Underlay: nil, // custom underlay currently rejected, no silent fallback
    OnAddresses: configureLightweightStack,
})
if err != nil { return err }
defer client.Close()
if err := client.WaitReady(ctx); err != nil { return err }
// TCP/UDP sockets belong to the caller's lightweight stack, not this library.
```

**Upstream-only transport limitation:** This module now uses unmodified official `tailscale.com` with **no Go module `replace`**. The old fork-specific instance-scoped `netns.Underlay` API is not upstream. To avoid breaking Yuhaiin's outbound isolation, `New` rejects non-nil `Underlay` with `ErrCustomUnderlayUnsupported` rather than silently falling back to system sockets. With `Underlay: nil`, upstream Tailscale uses its normal system-network transport. Consequently **this branch is not ready for integration into Yuhaiin's custom outbound** until independent injection hooks are implemented and exercised through end-to-end tests.

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

This module directly depends on the official stable `tailscale.com v1.104.2` release. The old Asutorufa fork and module-level `replace` are not used. Follow the BSD-3-Clause upstream license for Tailscale and relevant dependency licenses.

## Design

See [docs/architecture.md](docs/architecture.md).
