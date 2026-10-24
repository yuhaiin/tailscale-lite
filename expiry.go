package tailscalelite

import (
	"tailscale.com/types/netmap"
	"time"
)

// stopExpiryTimer requires applyMu. A callback already waiting on applyMu
// cannot apply an old snapshot after logout, replacement, or Close.
func (c *Client) stopExpiryTimer() {
	c.expiryGeneration++
	if c.expiryTimer != nil {
		c.expiryTimer.Stop()
		c.expiryTimer = nil
	}
	c.latestNetMap = nil
}

// scheduleExpiry requires applyMu. Control snapshots are immutable; retain the
// last authorized snapshot so deadlines still apply while control is offline.
func (c *Client) scheduleExpiry(nm *netmap.NetworkMap) {
	c.stopExpiryTimer()
	c.latestNetMap = nm
	var next time.Time
	consider := func(expiry time.Time) {
		if !expiry.IsZero() && (next.IsZero() || expiry.Before(next)) {
			next = expiry
		}
	}
	consider(nm.SelfNode.KeyExpiry())
	c.mu.Lock()
	routes := c.routes
	c.mu.Unlock()
	for _, peer := range nm.Peers {
		if _, installed := routes.byKey[peer.Key()]; installed {
			consider(peer.KeyExpiry())
		}
	}
	if next.IsZero() {
		return
	}
	generation := c.expiryGeneration
	c.expiryTimer = time.AfterFunc(time.Until(next), func() {
		c.applyMu.Lock()
		defer c.applyMu.Unlock()
		if generation != c.expiryGeneration {
			return
		}
		// Rebuild routes, engine peers and both DNS tables at the deadline.
		// Local expiry deactivates the whole map; peer expiry removes that peer
		// and schedules the next outstanding deadline.
		err := c.applyNetMap(c.latestNetMap)
		if err != nil {
			c.mu.Lock()
			c.status.Error = err.Error()
			c.mu.Unlock()
		}
	})
}
