package tailscalelite

import(
 "net/netip"
 "testing"
 "tailscale.com/types/key"
)

func TestRouteTableLongestPrefixAndAmbiguity(t *testing.T){
 a:=key.NewNode().Public()
 b:=key.NewNode().Public()
 t1:=&routeTable{entries:[]routeEntry{
  {prefix:netip.MustParsePrefix("10.0.0.0/8"),key:a},
  {prefix:netip.MustParsePrefix("10.42.0.0/16"),key:b},
  {prefix:netip.MustParsePrefix("10.42.0.0/16"),key:a},
  {prefix:netip.MustParsePrefix("2001:db8::/32"),key:b},
 }}
 for _,tc:=range []struct{ip string;want key.NodePublic;ok bool}{
  {"10.1.2.3",a,true},
  {"10.42.1.1",key.NodePublic{},false},
  {"2001:db8::1",b,true},
  {"1.1.1.1",key.NodePublic{},false},
 }{
  got,ok:=t1.lookup(netip.MustParseAddr(tc.ip))
  if got!=tc.want||ok!=tc.ok{t.Errorf("%s = %v, %v; want %v, %v",tc.ip,got,ok,tc.want,tc.ok)}
 }
}
