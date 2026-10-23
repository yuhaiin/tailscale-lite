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
- Unimplemented: TKA verification, fully integrated MagicDNS and production interoperability testing. Selected legacy `tailscaled.state` machine and node identities can be migrated with `MigrateLegacyState`; malformed or ambiguous profiles fail closed.

### Development

```bash
GOFLAGS='-tags=ts_omit_netstack,ts_omit_gro' go test -race ./...
GOFLAGS='-tags=ts_omit_netstack,ts_omit_gro' go list -deps ./... | grep '^gvisor.dev/gvisor' && exit 1
```

Tailscale's currently pinned fork is the same one used by Yuhaiin. Upstream code is retained through standard Go module dependencies rather than copied into this repository. Follow the BSD-3-Clause upstream license for Tailscale and relevant dependency licenses.

## Design

See [docs/architecture.md](docs/architecture.md).

### Existing tsnet identity migration

Before calling `New`, the embedding application may call `MigrateLegacyState(oldStateFile, newStateFile, controlURL)`. It reads the private `tailscaled.state` FileStore, checks the currently selected profile and control URL, and imports both machine and node keys to the private atomic `lite.json` format. The original FileStore is kept for rollback. Missing, logged-out, ambiguous, insecurely permissioned or cross-control identities are rejected rather than silently enrolling a different Tailnet node. Integration with an actual previously enrolled node still requires live validation.

### Custom underlay isolation

Production embedding in Yuhaiin must set `RequireUnderlay: true` and provide
`Underlay` with `DialContext`, `PacketListener`, and `DNSCache`.
`New` rejects missing or incomplete transports **before opening network sockets**.
The fork's per-instance underlay hooks are currently required; do not remove
the `tailscale.com` replacement unless equivalent complete transport injection
is implemented and tested. This module is not a complete replacement for tsnet yet.

### Binary size analysis

The [gsa workflow](.github/workflows/size.yml) builds the lite client and
legacy tsnet under the same Go version, then attempts to profile the current
Yuhaiin Linux binary. See [size report guide](docs/size-analysis.md). The
presence of `gvisor.dev/gvisor` in `go.mod` alone is not evidence that its
symbols were linked; consult the dependency check and gsa's linked-package
sizes. Comparisons are meaningful only within matched build flags/platforms.
