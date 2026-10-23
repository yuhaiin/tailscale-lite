package tailscalelite

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go4.org/netipx"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// applyNetMap installs a complete, validated control-plane snapshot. On error,
// the current inbound filter becomes deny-all rather than granting permissions
// based on a partly parsed NetMap. Client.applyMu serializes calls.
func (c *Client) applyNetMap(nm *netmap.NetworkMap) error {
	deny := func(err error) error {
		f := filter.NewAllowNone(c.cfg.Logf, nil)
		c.mu.Lock()
		c.routes = newRouteTable()
		c.names = newNameTable("")
		c.status.Ready = false
		c.mu.Unlock()
		c.engine.SetFilter(f)
		c.magic.SetFilter(f)
		if c.dns != nil {
			_ = c.dns.Set(dns.Config{})
		}
		return err
	}
	if nm == nil || !nm.SelfNode.Valid() {
		return deny(errors.New("tailscale-lite: no self node"))
	}
	if nm.TKAEnabled {
		return deny(errors.New("tailscale-lite: tailnet lock not yet supported; refusing unverified peers"))
	}
	if expiry := nm.SelfNode.KeyExpiry(); !expiry.IsZero() && expiry.Before(time.Now()) {
		return deny(errors.New("tailscale-lite: local node key has expired"))
	}
	addrs := nm.GetAddresses().AsSlice()
	if len(addrs) == 0 {
		return deny(errors.New("tailscale-lite: control supplied no local addresses"))
	}
	newRoutes, err := buildRoutes(nm, c.cfg.DisableSubnetRoutes)
	if err != nil {
		return deny(err)
	}
	newNames := buildNames(nm, newRoutes)
	dnsCfg, err := dnsConfigForNetMap(nm, newRoutes)
	if err != nil {
		return deny(err)
	}
	localBuilder := new(netipx.IPSetBuilder)
	for _, p := range addrs {
		if !p.IsValid() || !p.IsSingleIP() {
			return deny(fmt.Errorf("tailscale-lite: invalid local address %s", p))
		}
		localBuilder.AddPrefix(p)
	}
	localIPs, err := localBuilder.IPSet()
	if err != nil {
		return deny(fmt.Errorf("local IP set: %w", err))
	}
	// nm.PacketFilter is already parsed by controlclient. A nil filter is an
	// explicit deny-all, not a reason to fall back to local default permissions.
	f := filter.New(nm.PacketFilter, nil, localIPs, nil, nil, c.cfg.Logf)
	if c.cfg.OnAddresses != nil {
		if err := c.cfg.OnAddresses(append([]netip.Prefix(nil), addrs...)); err != nil {
			return deny(fmt.Errorf("configure host addresses: %w", err))
		}
	}
	c.engine.SetFilter(f)
	c.magic.SetFilter(f)
	c.magic.SetDERPMap(nm.DERPMap)
	filtered := make([]tailcfg.NodeView, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		if _, ok := newRoutes.byKey[p.Key()]; ok {
			filtered = append(filtered, p)
		}
	}
	c.magic.SetNetworkMap(nm.SelfNode, filtered)
	c.engine.SetSelfNode(nm.SelfNode)
	c.mu.Lock()
	old := c.routes
	c.routes = newRoutes
	c.names = newNames
	priv := c.state.Persist.PrivateNodeKey
	c.mu.Unlock()
	if priv.IsZero() {
		return deny(errors.New("tailscale-lite: no registered private node key"))
	}
	for pub := range old.byKey {
		c.engine.SyncDevicePeer(pub)
	}
	for pub := range newRoutes.byKey {
		c.engine.SyncDevicePeer(pub)
	}
	cfg := &wgcfg.Config{PrivateKey: priv, Addresses: append([]netip.Prefix(nil), addrs...)}
	if err := c.engine.Reconfig(cfg, &router.Config{LocalAddrs: append([]netip.Prefix(nil), addrs...)}, dnsCfg); err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		return deny(fmt.Errorf("reconfigure WireGuard: %w", err))
	}
	c.mu.Lock()
	c.status.Addresses = append([]netip.Prefix(nil), addrs...)
	c.status.PeerCount = len(filtered)
	c.mu.Unlock()
	return nil
}
