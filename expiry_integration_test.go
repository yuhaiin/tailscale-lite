//go:build integration

package tailscalelite

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

// This isolated review probe applies exactly one authorized map through the
// real client/engine, then sends no further control updates across expiry.
func TestKeyExpiryWithoutControlUpdate(t *testing.T) {
	for _, which := range []string{"peer", "self"} {
		t.Run(which, func(t *testing.T) {
			c, err := New(Config{
				Device: newBlockingTun(), StatePath: filepath.Join(t.TempDir(), "identity.json"),
				ControlURL: "http://127.0.0.1:1", Hostname: "review-expiry",
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			// Quiesce the real control client before injecting the only map.
			c.control.Shutdown()
			c.mu.Lock()
			c.state.Persist.PrivateNodeKey = key.NewNode()
			selfKey := c.state.Persist.PrivateNodeKey.Public()
			c.mu.Unlock()
			self := &tailcfg.Node{ID: 1, Name: "self.review.ts.net.", Key: selfKey,
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, HomeDERP: 1}
			peerIP := netip.MustParseAddr("100.64.0.2")
			peerPrefix := netip.PrefixFrom(peerIP, 32)
			peer := &tailcfg.Node{ID: 2, Name: "peer.review.ts.net.", Key: key.NewNode().Public(),
				Addresses: []netip.Prefix{peerPrefix}, AllowedIPs: []netip.Prefix{peerPrefix}}
			expires := time.Now().Add(200 * time.Millisecond)
			if which == "peer" {
				peer.KeyExpiry = expires
			} else {
				self.KeyExpiry = expires
			}
			nm := &netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{peer.View()},
				DNS: tailcfg.DNSConfig{Proxied: true}}
			c.SetControlClientStatus(nil, controlclient.Status{LoggedIn: true, NetMap: nm})
			if err := c.WaitReady(t.Context()); err != nil {
				t.Fatalf("initial map did not apply: %v", err)
			}
			if _, ok := c.Route(peerIP); !ok {
				t.Fatal("initial peer route missing")
			}
			if ips, _ := c.LookupIP(peer.Name); len(ips) == 0 {
				t.Fatal("initial peer DNS missing")
			}
			query := dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(peer.Name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
			packet, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			queryAddresses := func() (int, error) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				wire, err := c.QueryDNS(ctx, packet, "udp", netip.AddrPort{})
				if err != nil {
					return 0, err
				}
				var reply dnsmessage.Message
				if err := reply.Unpack(wire); err != nil {
					return 0, err
				}
				return len(reply.Answers), nil
			}
			if n, err := queryAddresses(); err != nil || n != 1 {
				t.Fatalf("initial full DNS response: %d %v", n, err)
			}
			<-time.After(time.Until(expires))
			// Allow the expiry callback to remove engine peers and DNS.
			deadline := time.Now().Add(2 * time.Second)
			for {
				_, authorized := c.Route(peerIP)
				ips, _ := c.LookupIP(peer.Name)
				dnsAnswers, dnsErr := queryAddresses()
				if !authorized && len(ips) == 0 && dnsAnswers == 0 && (which != "self" || dnsErr != nil) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("expired %s identity retains route=%v DNS=%v ready=%v", which, authorized, ips, c.Snapshot().Ready)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, ok := c.lookupPeerConfig(peer.Key); ok {
				t.Fatal("expired peer remains in engine configuration")
			}

			if which == "self" {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := c.WaitReady(ctx); err == nil {
					t.Error("WaitReady still succeeds after local node key expiry")
				}
			}
		})
	}
}

func TestKeyExpiryRenewalAndLogout(t *testing.T) {
	for _, action := range []string{"renew", "logout", "close"} {
		t.Run(action, func(t *testing.T) {
			c, err := New(Config{Device: newBlockingTun(), StatePath: filepath.Join(t.TempDir(), "identity.json"), ControlURL: "http://127.0.0.1:1"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			c.control.Shutdown()
			c.mu.Lock()
			c.state.Persist.PrivateNodeKey = key.NewNode()
			selfKey := c.state.Persist.PrivateNodeKey.Public()
			c.mu.Unlock()
			expires := time.Now().Add(250 * time.Millisecond)
			self := &tailcfg.Node{ID: 1, Key: selfKey, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, KeyExpiry: expires}
			ip := netip.MustParseAddr("100.64.0.2")
			peer := &tailcfg.Node{ID: 2, Key: key.NewNode().Public(), Name: "peer.test.ts.net.", Addresses: []netip.Prefix{netip.PrefixFrom(ip, 32)}, AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}
			nm := &netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{peer.View()}, DNS: tailcfg.DNSConfig{Proxied: true}}
			c.SetControlClientStatus(nil, controlclient.Status{LoggedIn: true, NetMap: nm})
			if err := c.WaitReady(t.Context()); err != nil {
				t.Fatal(err)
			}
			switch action {
			case "renew":
				next := *nm
				renewed := nm.SelfNode.AsStruct()
				renewed.KeyExpiry = time.Time{}
				next.SelfNode = renewed.View()
				c.SetControlClientStatus(nil, controlclient.Status{LoggedIn: true, NetMap: &next})
			case "logout":
				c.SetControlClientStatus(nil, controlclient.Status{})
			case "close":
				_ = c.Close()
			}
			<-time.After(time.Until(expires) + 50*time.Millisecond)
			_, route := c.Route(ip)
			if route != (action == "renew") {
				t.Fatalf("%s: route=%v", action, route)
			}
			if c.Snapshot().Ready != (action == "renew") {
				t.Fatalf("%s: invalid readiness", action)
			}
		})
	}
}
