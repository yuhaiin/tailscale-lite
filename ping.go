package tailscalelite

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// Ping measures an ICMP echo through the already-authorized Tailnet route.
// A destination outside the current NetMap is never passed to the engine.
func (c *Client) Ping(ctx context.Context, ip netip.Addr) (time.Duration, error) {
	if _, ok := c.Route(ip); !ok {
		return 0, errors.New("tailscale-lite: no authorized route to destination")
	}
	c.mu.Lock()
	engine, closed := c.engine, c.closed
	c.mu.Unlock()
	if closed || engine == nil {
		return 0, errors.New("tailscale-lite: closed")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ch := make(chan *ipnstate.PingResult, 1)
	engine.Ping(ip, tailcfg.PingICMP, 8, func(result *ipnstate.PingResult) {
		select {
		case ch <- result:
		default:
		}
	})
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case r := <-ch:
		if r == nil {
			return 0, errors.New("tailscale-lite: empty ICMP ping result")
		}
		if r.Err != "" {
			return 0, errors.New(r.Err)
		}
		return time.Duration(r.LatencySeconds * float64(time.Second)), nil
	}
}
