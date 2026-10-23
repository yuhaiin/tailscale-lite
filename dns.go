package tailscalelite

import (
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/types/netmap"
)

// nameTable is an immutable MagicDNS subset. Split-DNS forwarding is left to
// the host resolver; we never query system DNS for a Tailnet hostname.
type nameTable struct {
	suffix    string
	records   map[string][]netip.Addr
	ambiguous map[string]bool
	owners    map[string]string
}

func newNameTable(suffix string) *nameTable {
	return &nameTable{suffix: canonicalName(suffix), records: make(map[string][]netip.Addr),
		ambiguous: make(map[string]bool), owners: make(map[string]string)}
}
func canonicalName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
func (t *nameTable) add(name, owner string, addr netip.Addr) {
	name = canonicalName(name)
	if name == "" || !addr.IsValid() || t.ambiguous[name] {
		return
	}
	if prior, ok := t.owners[name]; ok && prior != owner {
		delete(t.records, name)
		t.ambiguous[name] = true
		return
	}
	t.owners[name] = owner
	if !slices.Contains(t.records[name], addr) {
		t.records[name] = append(t.records[name], addr)
	}
}
func (t *nameTable) lookup(name string) ([]netip.Addr, bool) {
	name = canonicalName(name)
	if name == "" {
		return nil, false
	}
	if t.ambiguous[name] {
		return nil, true
	}
	if ips, ok := t.records[name]; ok {
		return slices.Clone(ips), true
	}
	if t.suffix != "" && (name == t.suffix || strings.HasSuffix(name, "."+t.suffix)) {
		return nil, true // recognized tailnet name, negative response; never leak to host DNS
	}
	return nil, false // host resolver can process non-Tailnet names
}

func buildNames(nm *netmap.NetworkMap, routes *routeTable) *nameTable {
	suffix := nm.MagicDNSSuffix()
	t := newNameTable(suffix)
	if nm.DNS.Proxied {
		putPeer := func(name, owner string, addrs []netip.Prefix) {
			name = canonicalName(name)
			for _, p := range addrs {
				if !p.IsSingleIP() {
					continue
				}
				t.add(name, owner, p.Addr())
				if t.suffix != "" && strings.HasSuffix(name, "."+t.suffix) {
					t.add(strings.TrimSuffix(name, "."+t.suffix), owner, p.Addr())
				}
			}
		}
		if nm.SelfNode.Valid() {
			putPeer(nm.SelfNode.Name(), "self", nm.GetAddresses().AsSlice())
		}
		for _, peer := range nm.Peers {
			if _, ok := routes.byKey[peer.Key()]; !ok {
				continue
			}
			var addrs []netip.Prefix
			for _, p := range peer.Addresses().All() {
				owner, ok := routes.lookup(p.Addr())
				if ok && owner == peer.Key() {
					addrs = append(addrs, p)
				}
			}
			putPeer(peer.Name(), peer.Key().String(), addrs)
		}
	}
	for _, rec := range nm.DNS.ExtraRecords {
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			continue
		}
		if rec.Type != "" && !strings.EqualFold(rec.Type, "A") && !strings.EqualFold(rec.Type, "AAAA") {
			continue
		}
		if strings.EqualFold(rec.Type, "A") && !ip.Is4() || strings.EqualFold(rec.Type, "AAAA") && !ip.Is6() {
			continue
		}
		t.add(rec.Name, "control-extra", ip)
	}
	return t
}

// LookupIP returns the IPs for known Tailnet and ExtraRecord names. The bool
// indicates that the query is owned by this client, including negative
// answers. Unknown external names return (nil,false), for the host resolver.
func (c *Client) LookupIP(name string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.status.Ready || c.names == nil {
		return nil, false
	}
	return c.names.lookup(name)
}
