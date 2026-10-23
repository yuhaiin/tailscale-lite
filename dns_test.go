package tailscalelite

import (
	"net/netip"
	"testing"
)

func TestNameTable(t *testing.T) {
	x := newNameTable("Example.ts.net.")
	ip := netip.MustParseAddr("100.99.0.1")
	x.add("node.example.ts.net.", "peer-a", ip)
	found, handled := x.lookup("NODE.EXAMPLE.TS.NET.")
	if !handled || len(found) != 1 || found[0] != ip {
		t.Fatalf("lookup: %v %v", found, handled)
	}
	found[0] = netip.IPv4Unspecified()
	again, _ := x.lookup("node.example.ts.net")
	if again[0] != ip {
		t.Fatal("name table leaked a mutable slice")
	}
	if ips, ok := x.lookup("missing.example.ts.net"); !ok || len(ips) != 0 {
		t.Fatal("Tailnet name leaked to system DNS")
	}
	if _, ok := x.lookup("example.org"); ok {
		t.Fatal("external name stolen")
	}
	x.add("node.example.ts.net", "peer-b", netip.MustParseAddr("100.99.0.2"))
	if ips, ok := x.lookup("node.example.ts.net"); !ok || len(ips) != 0 {
		t.Fatal("ambiguous name not blocked")
	}
}
