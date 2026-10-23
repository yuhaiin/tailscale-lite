package tailscalelite

import (
 "net/netip"
 "sort"
 "time"

 "tailscale.com/tailcfg"
 "tailscale.com/types/key"
 "tailscale.com/types/netmap"
 "tailscale.com/wgengine"
 "tailscale.com/wgengine/wgcfg"
)

type routeEntry struct {
 prefix netip.Prefix
 key key.NodePublic
 node tailcfg.NodeView
}
type routeTable struct {
 entries []routeEntry
 byKey map[key.NodePublic]wgcfg.PeerConfig
}

// routeTable is immutable after build. The owner exchanges it under Client.mu.
func newRouteTable()*routeTable{return &routeTable{byKey:make(map[key.NodePublic]wgcfg.PeerConfig)}}

func buildRoutes(nm *netmap.NetworkMap, disableSubnets bool)(*routeTable,error){
 t:=newRouteTable()
 now:=time.Now()
 for _,p:=range nm.Peers {
  if !p.Valid() || p.Expired() || (!p.KeyExpiry().IsZero() && p.KeyExpiry().Before(now)) || p.UnsignedPeerAPIOnly() || p.IsJailed() {
   continue
  }
  key:=p.Key()
  var allowed []netip.Prefix
  for _,prefix:=range p.AllowedIPs().All(){
   if !prefix.IsValid(){continue}
   if disableSubnets && !prefix.IsSingleIP(){continue}
   allowed=append(allowed,prefix)
   t.entries=append(t.entries,routeEntry{prefix,key,p})
  }
  if len(allowed)!=0{t.byKey[key]=wgcfg.PeerConfig{AllowedIPs:allowed}}
 }
 sort.Slice(t.entries,func(i,j int)bool{
  if a,b:=t.entries[i].prefix.Bits(),t.entries[j].prefix.Bits();a!=b{return a>b}
  return t.entries[i].prefix.String()<t.entries[j].prefix.String()
 })
 return t,nil
}

// Ambiguous equal-specificity route ownership fails closed.
func(t *routeTable) find(ip netip.Addr)(routeEntry,bool){
 var best routeEntry
 found:=false
 for _,r:=range t.entries {
  if !r.prefix.Contains(ip){continue}
  if found && r.prefix.Bits()==best.prefix.Bits() && r.key!=best.key{return routeEntry{},false}
  if !found {best=r;found=true;continue}
  if r.prefix.Bits()<best.prefix.Bits(){break}
 }
 return best,found
}
func(t *routeTable) lookup(ip netip.Addr)(key.NodePublic,bool){
 r,ok:=t.find(ip)
 if !ok{return key.NodePublic{},false}
 return r.key,true
}
func(c *Client) lookupPeerKey(ip netip.Addr)(key.NodePublic,bool){
 c.mu.Lock();defer c.mu.Unlock()
 if c.closed{return key.NodePublic{},false}
 return c.routes.lookup(ip)
}
func(c *Client) lookupPeer(ip netip.Addr)(wgengine.PeerForIP,bool){
 c.mu.Lock();defer c.mu.Unlock()
 if c.closed{return wgengine.PeerForIP{},false}
 r,ok:=c.routes.find(ip)
 if !ok{return wgengine.PeerForIP{},false}
 return wgengine.PeerForIP{Node:r.node,Route:r.prefix},true
}
func(c *Client) lookupPeerConfig(pub key.NodePublic)(wgcfg.PeerConfig,bool){
 c.mu.Lock();defer c.mu.Unlock()
 if c.closed{return wgcfg.PeerConfig{},false}
 cfg,ok:=c.routes.byKey[pub]
 return cfg,ok
}
