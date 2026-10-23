//go:build integration

package tailscalelite

import (
 "context"
 "encoding/binary"
 "bytes"
 "errors"
 "fmt"
 "net"
 "net/netip"
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
 ctx,cancel:=context.WithTimeout(t.Context(),55*time.Second)
 defer cancel()
 var clients [2]*Client
 var devices [2]*blockingTun
 for i:=0;i<2;i++{
  device:=newBlockingTun()
  devices[i]=device
  client,err:=New(Config{
   Device:device,
   AuthKey:"local-test-key",
   Hostname:fmt.Sprintf("lite%d",i),
   ControlURL:control.HTTPTestServer.URL,
   StatePath:filepath.Join(t.TempDir(),"identity.json"),
   Logf:func(format string,args ...any){
    t.Logf("node%d: %s",i,fmt.Sprintf(format,args...))
   },
  })
  if err!=nil{t.Fatal(err)}
  clients[i]=client
  t.Cleanup(func(){_ =client.Close()})
  if err:=client.WaitReady(ctx);err!=nil{t.Fatalf("node %d: %v; status: %+v",i,err,client.Snapshot())}
  s:=client.Snapshot()
  if !s.LoggedIn || !s.Ready || len(s.Addresses)==0{t.Fatalf("node %d: invalid status %+v",i,s)}
 }
 // Poll for the second node's peer route to reach the first client.
 var from,to netip.Addr
 for _,p:=range clients[0].Snapshot().Addresses{if p.Addr().Is4(){from=p.Addr()}}
 for _,p:=range clients[1].Snapshot().Addresses{if p.Addr().Is4(){to=p.Addr()}}
 if !from.IsValid()||!to.IsValid(){t.Fatal("test control did not assign IPv4 to both nodes")}
 for {
  if _,ok:=clients[0].Route(to);ok{break}
  select{
   case <-ctx.Done():t.Fatalf("no peer route: %v / %+v",ctx.Err(),clients[0].Snapshot())
   case <-time.After(20*time.Millisecond):
  }
 }
 packet:=testICMPv4Packet(from,to)
 select {
 case devices[0].send<-packet:
 case <-ctx.Done():t.Fatal(ctx.Err())
 }
 // The receiver has no application IP stack. Receiving the raw IP packet
 // here proves that control, magicsock, DERP/UDP, WG decryption and ACL pass.
 timer:=time.NewTimer(15*time.Second)
 defer timer.Stop()
 for {
  select{
   case received:=<-devices[1].recv:
    if bytes.Equal(received,packet){return}
   case <-timer.C:
    t.Fatalf("encrypted packet not delivered (from %v to %v); client0=%+v client1=%+v",from,to,clients[0].Snapshot(),clients[1].Snapshot())
   case <-ctx.Done():t.Fatal(ctx.Err())
  }
 }
}

func testChecksum(b []byte) uint16 {
 var sum uint32
 for len(b)>1{sum+=uint32(binary.BigEndian.Uint16(b[:2]));b=b[2:]}
 if len(b)>0{sum+=uint32(b[0])<<8}
 for sum>>16!=0{sum=(sum&0xffff)+(sum>>16)}
 return ^uint16(sum)
}

func testICMPv4Packet(src,dst netip.Addr)[]byte{
 // IPv4 header + ICMP echo request with a short unique payload.
 payload:=[]byte("tailscale-lite-wireguard-integration")
 b:=make([]byte,20+8+len(payload))
 b[0]=0x45;b[8]=64;b[9]=1
 binary.BigEndian.PutUint16(b[2:4],uint16(len(b)))
 binary.BigEndian.PutUint16(b[4:6],0x3141)
 a,z:=src.As4(),dst.As4()
 copy(b[12:16],a[:]);copy(b[16:20],z[:])
 binary.BigEndian.PutUint16(b[10:12],testChecksum(b[:20]))
 icmp:=b[20:]
 icmp[0]=8
 binary.BigEndian.PutUint16(icmp[4:6],42)
 binary.BigEndian.PutUint16(icmp[6:8],7)
 copy(icmp[8:],payload)
 binary.BigEndian.PutUint16(icmp[2:4],testChecksum(icmp))
 return b
}

// Deliberately no host TCP/IP implementation. No packets are produced until
// Yuhaiin's stack attaches, and Close must unblock the engine's reader.
type blockingTun struct{
 done chan struct{}
 events chan tun.Event
 once sync.Once
 send chan []byte
 recv chan []byte
}
func newBlockingTun()*blockingTun{
 d:=&blockingTun{done:make(chan struct{}),events:make(chan tun.Event,1),send:make(chan []byte,8),recv:make(chan []byte,8)}
 d.events<-tun.EventUp
 return d
}
func(*blockingTun)Name()(string,error){return "tailscale-lite-test",nil}
func(*blockingTun)File()*os.File{return nil}
func(*blockingTun)MTU()(int,error){return 1280,nil}
func(*blockingTun)BatchSize()int{return 1}
func(d *blockingTun)Events()<-chan tun.Event{return d.events}
func(d *blockingTun)Read(slab []byte, packets []tun.ReadPacket)(int,error){
 select {
 case <-d.done:return 0,net.ErrClosed
 case packet:=<-d.send:
  offset:=tun.ReadPacketSpacing
  if len(packets)==0 || len(slab)<offset+len(packet){return 0,errors.New("test TUN receive slab too small")}
  copy(slab[offset:],packet)
  packets[0]=tun.ReadPacket{Offset:offset,Size:len(packet)}
  return 1,nil
 }
}
func(d *blockingTun)Write(buffers [][]byte,offset int)(int,error){
 count:=0
 for _,buf:=range buffers{
  if offset<0||offset>len(buf){return count,errors.New("invalid write offset")}
  packet:=append([]byte(nil),buf[offset:]...)
  select{
  case <-d.done:return count,net.ErrClosed
  case d.recv<-packet:count++
  }
 }
 return count,nil
}
func(d *blockingTun)Close()error{
 d.once.Do(func(){close(d.done);close(d.events)})
 return nil
}
var _ tun.Device=(*blockingTun)(nil)
var _ =errors.Is
