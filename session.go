package tailscalelite

import (
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// deactivateNetMap is called with applyMu held, never with Client.mu held.
// Packet policy is removed before peer and route ownership is discarded.
func (c *Client) deactivateNetMap() {
	c.stopExpiryTimer()
	// An old manager snapshot must not keep resolving or forwarding once
	// control revokes this node. The resolver clears its own routes first.
	if c.dns != nil {
		_ = c.dns.Set(dns.Config{})
	}
	deny := filter.NewAllowNone(c.cfg.Logf, nil)
	c.engine.SetFilter(deny)
	c.magic.SetFilter(deny)
	c.mu.Lock()
	old := c.routes
	c.routes = newRouteTable()
	c.names = newNameTable("")
	c.status.Ready = false
	c.status.Addresses = nil
	c.status.PeerCount = 0
	c.mu.Unlock()
	c.magic.SetNetworkMap(tailcfg.NodeView{}, nil)
	c.magic.SetDERPMap(nil)
	for k := range old.byKey {
		c.engine.SyncDevicePeer(k)
	}
}
