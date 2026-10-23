//go:build integration

package tailscalelite

import (
 "context"
 "errors"
 "fmt"
 "net"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/tailscale/wireguard-go/tun"
 "tailscale.com/derp/derpserver"
 "tailscale.com/tailcfg"
 "tailscale.com/tstest/integration/testcontrol"
 "tailscale.com/types/key"
 "tailscale.com/types/logger"
)

// A real control/magicsock/WireGuard smoke test. It does not exercise
// application TCP/UDP; Yuhaiin will provide the actual lightweight stack.
func TestLocalControlRegistration(t *testing.T) {
 relayServer:=derpserver.New(key.NewNode(),logger.Discard)
 defer relayServer.Close()
 relay:=httptest.NewTLSServer(derpserver.Handler(relayServer))
 defer relay.Close()
 _,portText,err:=net.SplitHostPort(strings.TrimPrefix(relay.URL,"https://"))
 if err!=nil{t.Fatal(err)}
 port,err:=strconv.Atoi(portText)
 if err!=nil{t.Fatal(err)}
 control:=&testcontrol.Server{
  DERPMap:&tailcfg.DERPMap{Regions:map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
   1:{RegionID:1,RegionCode:"local",Nodes:[]*tailcfg.DERPNode{{
    Name:"local",RegionID:1,HostName:"127.0.0.1",IPv4:"127.0.0.1",
    IPv6:"none",DERPPort:port,STUNPort:-1,InsecureForTests:true,
   }}},
  }},
  DNSConfig:&tailcfg.DNSConfig{Proxied:true},
  MagicDNSDomain:"lite-test.ts.net",
  Logf:logger.Discard,
 }
 control.HTTPTestServer=httptest.NewServer(control)
 defer control.HTTPTestServer.Close()
 ctx,cancel:=context.WithTimeout(t.Context(),30*time.Second)
 defer cancel()
 for i:=0;i<2;i++{
  device:=newBlockingTun()
  client,err:=New(Config{
   Device:device,
   AuthKey:"local-test-key",
   Hostname:fmt.Sprintf("lite%d",i),
   ControlURL:control.HTTPTestServer.URL,
   StatePath:filepath.Join(t.TempDir(),"identity.json"),
  })
  if err!=nil{t.Fatal(err)}
  t.Cleanup(func(){_ =client.Close()})
  if err:=client.WaitReady(ctx);err!=nil{t.Fatalf("node %d: %v; status: %+v",i,err,client.Snapshot())}
  s:=client.Snapshot()
  if !s.LoggedIn || !s.Ready || len(s.Addresses)==0{t.Fatalf("node %d: invalid status %+v",i,s)}
 }
}

// Deliberately no host TCP/IP implementation. No packets are produced until
// Yuhaiin's stack attaches, and Close must unblock the engine's reader.
type blockingTun struct{
 done chan struct{}
 events chan tun.Event
 once sync.Once
}
func newBlockingTun()*blockingTun{
 d:=&blockingTun{done:make(chan struct{}),events:make(chan tun.Event,1)}
 d.events<-tun.EventUp
 return d
}
func(*blockingTun)Name()(string,error){return "tailscale-lite-test",nil}
func(*blockingTun)File()*os.File{return nil}
func(*blockingTun)MTU()(int,error){return 1280,nil}
func(*blockingTun)BatchSize()int{return 1}
func(d *blockingTun)Events()<-chan tun.Event{return d.events}
func(d *blockingTun)Read([]byte,[]tun.ReadPacket)(int,error){
 <-d.done
 return 0,net.ErrClosed
}
func(d *blockingTun)Write(buffers [][]byte,_ int)(int,error){
 select{case <-d.done:return 0,net.ErrClosed;default:}
 return len(buffers),nil
}
func(d *blockingTun)Close()error{
 d.once.Do(func(){close(d.done);close(d.events)})
 return nil
}
var _ tun.Device=(*blockingTun)(nil)
var _ =errors.Is
