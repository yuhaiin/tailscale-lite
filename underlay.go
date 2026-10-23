package tailscalelite

import (
    "context"
    "errors"
    "net"
    "net/netip"
)

// ErrCustomUnderlayUnsupported is returned when a caller requests a custom
// underlay using the upstream Tailscale transport. Upstream Tailscale's
// controlclient, netcheck, DERP, and magicsock do not provide the same
// instance-scoped socket injection interface as Yuhaiin's prior fork.
//
// Until those transports have explicit injection hooks, silently falling
// back to system sockets would leak control and data traffic outside the
// caller's policy and cannot be allowed.
var ErrCustomUnderlayUnsupported = errors.New("tailscale-lite: custom underlay not supported with upstream tailscale.com; refusing system-network fallback")

// Underlay describes the transport that an embedding application ultimately
// needs to supply. The upstream engine cannot yet use it: New rejects any
// non-nil Underlay rather than falling back to the system network.
//
// This API is reserved for an independent transport implementation.
type Underlay struct {
    DialContext func(context.Context, string, string) (net.Conn, error)
    ListenPacket func(context.Context, string, string) (net.PacketConn, error)
    LookupIP func(context.Context, string) ([]netip.Addr, error)
}
