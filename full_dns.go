package tailscalelite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// dnsConfigForNetMap configures the actual Tailscale DNS resolver used by
// tsnet before the lite migration. No operating-system DNS is installed.
// Upstream DNS requests use the instance's injected Dialer/Underlay, and
// resolvers inside authorized Tailnet routes use the host's IP stack.
func dnsConfigForNetMap(nm *netmap.NetworkMap, routes *routeTable) (*dns.Config, error) {
	if nm == nil || !nm.SelfNode.Valid() {
		return nil, errors.New("tailscale-lite: missing DNS network map")
	}
	cfg := &dns.Config{
		AcceptDNS: true,
		Routes:    make(map[dnsname.FQDN][]*dnstype.Resolver),
		Hosts:     make(map[dnsname.FQDN][]netip.Addr),
	}
	setHost := func(name string, addrs []netip.Prefix) {
		fqdn, err := dnsname.ToFQDN(name)
		if err != nil {
			return
		}
		for _, addr := range addrs {
			if addr.IsValid() && addr.IsSingleIP() {
				cfg.Hosts[fqdn] = append(cfg.Hosts[fqdn], addr.Addr())
			}
		}
	}
	setHost(nm.SelfNode.Name(), nm.GetAddresses().AsSlice())
	for _, peer := range nm.Peers {
		if _, ok := routes.byKey[peer.Key()]; !ok {
			continue
		}
		var ips []netip.Prefix
		for _, p := range peer.Addresses().All() {
			if p.IsSingleIP() {
				owner, ok := routes.lookup(p.Addr())
				if ok && owner == peer.Key() {
					ips = append(ips, p)
				}
			}
		}
		setHost(peer.Name(), ips)
	}
	for _, rec := range nm.DNS.ExtraRecords {
		if rec.Type != "" && rec.Type != "A" && rec.Type != "AAAA" {
			continue
		}
		fqdn, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil || (rec.Type == "A" && !ip.Is4()) || (rec.Type == "AAAA" && !ip.Is6()) {
			continue
		}
		cfg.Hosts[fqdn] = append(cfg.Hosts[fqdn], ip)
	}
	for _, domain := range nm.DNS.Domains {
		if fqdn, err := dnsname.ToFQDN(domain); err == nil {
			cfg.SearchDomains = append(cfg.SearchDomains, fqdn)
		}
	}
	for suffix, resolvers := range nm.DNS.Routes {
		fqdn, err := dnsname.ToFQDN(suffix)
		if err != nil {
			return nil, fmt.Errorf("invalid Tailnet DNS route %q: %w", suffix, err)
		}
		cfg.Routes[fqdn] = append([]*dnstype.Resolver(nil), resolvers...)
	}
	cfg.DefaultResolvers = append(cfg.DefaultResolvers, nm.DNS.Resolvers...)
	if nm.DNS.Proxied {
		suffix := nm.MagicDNSSuffix()
		fqdn, err := dnsname.ToFQDN(suffix)
		if err != nil {
			return nil, fmt.Errorf("invalid MagicDNS suffix %q: %w", suffix, err)
		}
		// MagicDNS is authoritative, including nonexistent hostnames.
		cfg.Routes[fqdn] = nil
	}
	// ExtraRecords can fall outside the MagicDNS suffix and still must be
	// answered locally, unless control explicitly supplies a split route.
	for name := range cfg.Hosts {
		covered := false
		for route := range cfg.Routes {
			if route.Contains(name) {
				covered = true
				break
			}
		}
		if !covered {
			cfg.Routes[name] = nil
		}
	}
	for _, p := range nm.GetAddresses().All() {
		if p.Addr().Is6() {
			cfg.OnlyIPv6 = true
		} else if p.Addr().Is4() {
			cfg.OnlyIPv6 = false
			break
		}
	}
	return cfg, nil
}

// QueryDNS preserves Tailscale's full DNS wire protocol handling, including
// TCP/UDP, A/AAAA/PTR, Split DNS and configured upstream forwarding.
func (c *Client) QueryDNS(ctx context.Context, packet []byte, family string, from netip.AddrPort) ([]byte, error) {
	c.mu.Lock()
	ready, manager := !c.closed && c.status.Ready, c.dns
	c.mu.Unlock()
	if !ready || manager == nil {
		return nil, errors.New("tailscale-lite: DNS not ready")
	}
	if family != "tcp" && family != "udp" {
		return nil, errors.New("tailscale-lite: invalid DNS transport")
	}
	return manager.Query(ctx, packet, family, from)
}

// HandleDNSConn delegates DNS-over-TCP to the same Tailscale DNS manager.
func (c *Client) HandleDNSConn(conn net.Conn, from netip.AddrPort) error {
	c.mu.Lock()
	ready, manager := !c.closed && c.status.Ready, c.dns
	c.mu.Unlock()
	if !ready || manager == nil {
		return errors.New("tailscale-lite: DNS not ready")
	}
	manager.HandleTCPConn(conn, from)
	return nil
}

// Guard compilation against moving API types.
var _ = tailcfg.DNSConfig{}
