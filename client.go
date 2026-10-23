// Package tailscalelite embeds a Tailnet endpoint without tsnet, ipnlocal, an OS TUN, or gVisor.
//
// The host provides a userspace tun.Device (for example, Yuhaiin's lightweight
// TCP/IP stack adapter). The endpoint owns only Tailscale control and encrypted
// packet transport; application sockets remain with the host.
package tailscalelite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

// Config contains the minimum information for a single Tailnet endpoint.
// Device must deliver decrypted IP packets to the host's IP stack and send its
// outbound IP packets to WireGuard. No system TUN is created by this package.
type Config struct {
	Device     tun.Device
	Hostname   string
	AuthKey    string
	ControlURL string
	StatePath  string
	Underlay   *netns.Underlay
	// RequireUnderlay prohibits falling back to the host network.
	// Set this for embedded proxy use where every control/DERP/UDP socket
	// must follow the host's outbound routing policy.
	RequireUnderlay bool
	Logf            logger.Logf
	// OnAddresses configures the host IP stack with addresses assigned by control.
	// It is invoked before the first WireGuard configuration is applied.
	OnAddresses func([]netip.Prefix) error
	// DisableSubnetRoutes restricts outbound route lookup to exact peer IPs.
	DisableSubnetRoutes bool
	// TailnetDialTCP/UDP connect to peer or subnet-resolver IPs through the
	// host's userspace stack. Required for DNS resolvers inside a Tailnet.
	// They are never used for off-Tailnet upstreams, which use Underlay.
	TailnetDialTCP func(context.Context, netip.AddrPort) (net.Conn, error)
	TailnetDialUDP func(context.Context, netip.AddrPort) (net.Conn, error)
}

// Status is an immutable, non-secret snapshot. It never contains auth keys.
type Status struct {
	Ready     bool
	LoggedIn  bool
	AuthURL   string
	Error     string
	Addresses []netip.Prefix
	PeerCount int
}

// Client owns one independent control session and WireGuard engine.
type Client struct {
	mu              sync.Mutex
	applyMu         sync.Mutex
	cfg             Config
	status          Status
	routes          *routeTable
	names           *nameTable
	state           diskState
	control         *controlclient.Auto
	engine          wgengine.Engine
	magic           *magicsock.Conn
	monitor         *netmon.Monitor
	bus             *eventbus.Bus
	dialer          *tsdial.Dialer
	dns             *dns.Manager
	stateRelease    func()
	ready           chan struct{}
	readyOnce       sync.Once
	netInfoReady    chan struct{}
	netInfoReadySet bool
	closed          bool
}

// New starts an isolated Tailnet client. Call WaitReady to wait for an
// authorized NetMap. A host-supplied Device is mandatory; nil would silently
// create Tailscale's fake TUN and black-hole application packets.
func New(cfg Config) (_ *Client, err error) {
	if err := validateUnderlay(cfg); err != nil {
		return nil, err
	}
	if cfg.Device == nil {
		return nil, errors.New("tailscale-lite: Device is required")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("tailscale-lite: StatePath is required")
	}
	if cfg.ControlURL == "" {
		cfg.ControlURL = "https://controlplane.tailscale.com"
	}
	if cfg.Logf == nil {
		cfg.Logf = logger.Discard
	}
	release, err := claimStatePath(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			release()
		}
	}()
	state, err := readState(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	if state.MachineKey.IsZero() || state.BackendLogID == "" {
		if state.MachineKey.IsZero() {
			state.MachineKey = key.NewMachine()
		}
		if state.BackendLogID == "" {
			id, err := logid.NewPrivateID()
			if err != nil {
				return nil, fmt.Errorf("generate backend ID: %w", err)
			}
			state.BackendLogID = id.Public().String()
		}
		if err := writeState(cfg.StatePath, state); err != nil {
			return nil, err
		}
	}
	c := &Client{
		cfg: cfg, state: state, ready: make(chan struct{}), netInfoReady: make(chan struct{}),
		routes: newRouteTable(), names: newNameTable(""), stateRelease: release,
	}
	c.bus = eventbus.New()
	c.monitor, err = netmon.New(c.bus, cfg.Logf)
	if err != nil {
		c.bus.Close()
		return nil, fmt.Errorf("netmon: %w", err)
	}
	c.dialer = tsdial.NewDialer(c.monitor)
	c.dialer.Logf = cfg.Logf
	c.dialer.Underlay = cfg.Underlay
	c.dialer.SetBus(c.bus)
	// Routes are consulted dynamically on each lookup. In particular the
	// fixed Tailnet service ranges must *never* leak to host DNS/network
	// sockets merely because control briefly removed the peer route.
	c.dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		if tsaddr.IsTailscaleIP(ip) {
			return true
		}
		_, ok := c.Route(ip)
		return ok
	}
	c.dialer.NetstackDialTCP = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		if cfg.TailnetDialTCP == nil {
			return nil, errors.New("tailscale-lite: missing host Tailnet TCP dialer")
		}
		if _, ok := c.Route(addr.Addr()); !ok {
			return nil, errors.New("tailscale-lite: unauthorized Tailnet TCP destination")
		}
		return cfg.TailnetDialTCP(ctx, addr)
	}
	c.dialer.NetstackDialUDP = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		if cfg.TailnetDialUDP == nil {
			return nil, errors.New("tailscale-lite: missing host Tailnet UDP dialer")
		}
		if _, ok := c.Route(addr.Addr()); !ok {
			return nil, errors.New("tailscale-lite: unauthorized Tailnet UDP destination")
		}
		return cfg.TailnetDialUDP(ctx, addr)
	}
	h := health.NewTracker(c.bus)
	var wrappedTun *tstun.Wrapper
	c.engine, err = wgengine.NewUserspaceEngine(cfg.Logf, wgengine.Config{
		Tun: cfg.Device, NetMon: c.monitor, Dialer: c.dialer,
		HealthTracker: h, Metrics: &usermetric.Registry{}, EventBus: c.bus,
		DERPAppName: "yuhaiin/tailscale-lite",
		SetSubsystem: func(s any) {
			switch sub := s.(type) {
			case *magicsock.Conn:
				c.magic = sub
			case *tstun.Wrapper:
				wrappedTun = sub
			case *dns.Manager:
				c.dns = sub
			}
		},
	})
	if err != nil {
		c.monitor.Close()
		c.bus.Close()
		return nil, fmt.Errorf("wireguard engine: %w", err)
	}
	if c.magic == nil || wrappedTun == nil || c.dns == nil {
		c.engine.Close()
		c.monitor.Close()
		c.bus.Close()
		return nil, errors.New("tailscale-lite: engine did not expose magicsock, DNS, and TUN subsystems")
	}
	c.engine.SetPeerByIPPacketFunc(c.lookupPeerKey)
	c.engine.SetPeerForIPFunc(c.lookupPeer)
	c.engine.SetPeerConfigFunc(c.lookupPeerConfig)
	// Fail closed until the control plane supplies validated ACL rules.
	denyAll := filter.NewAllowNone(cfg.Logf, nil)
	c.engine.SetFilter(denyAll)
	c.magic.SetFilter(denyAll)

	c.control, err = controlclient.New(controlclient.Options{
		Persist:              state.Persist,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) { return state.MachineKey, nil },
		ServerURL:            cfg.ControlURL, AuthKey: cfg.AuthKey,
		Hostinfo:       &tailcfg.Hostinfo{Hostname: cfg.Hostname, BackendLogID: state.BackendLogID},
		DiscoPublicKey: c.magic.DiscoPublicKey(),
		Dialer:         c.dialer, Bus: c.bus, HealthTracker: h, Logf: cfg.Logf, Observer: c,
	})
	if err != nil {
		c.engine.Close()
		c.monitor.Close()
		c.bus.Close()
		return nil, fmt.Errorf("control client: %w", err)
	}
	// Relay selection, NAT probing and the home DERP ID must flow back to
	// control. Otherwise peers learn our key but have no UDP/DERP route.
	c.magic.SetNetInfoCallback(func(ni *tailcfg.NetInfo) {
		if ni == nil {
			return
		}
		c.mu.Lock()
		ctl := c.control
		closed := c.closed
		c.mu.Unlock()
		if !closed && ctl != nil {
			ctl.SetNetInfo(ni)
			c.mu.Lock()
			if !c.closed && !c.netInfoReadySet {
				c.netInfoReadySet = true
				close(c.netInfoReady)
			}
			c.mu.Unlock()
		}
	})
	c.engine.SetStatusCallback(func(s *wgengine.Status, e error) {
		if e != nil || s == nil {
			return
		}
		c.mu.Lock()
		control := c.control
		closed := c.closed
		c.mu.Unlock()
		if !closed && control != nil {
			control.UpdateEndpoints(s.LocalAddrs)
		}
	})
	// Tailscale corks all TUN queues until the caller wires up its
	// subsystems. Without Start, control login succeeds but WireGuard
	// packets never leave the host stack.
	wrappedTun.Start()
	c.control.Login(controlclient.LoginDefault)
	return c, nil
}

// SetControlClientStatus implements controlclient.Observer. Callbacks are
// serialized here so a stale NetMap cannot replace a newer applied map.
func (c *Client) SetControlClientStatus(_ controlclient.Client, s controlclient.Status) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.status.LoggedIn = s.LoggedIn
	c.status.AuthURL = s.URL
	if s.Err != nil {
		c.status.Error = s.Err.Error()
	} else {
		c.status.Error = ""
	}
	if s.Persist.Valid() {
		p := s.Persist.AsStruct()
		if p != nil && !p.PrivateNodeKey.IsZero() && !c.state.Persist.Equals(p) {
			next := c.state
			next.Persist = *p
			if err := writeState(c.cfg.StatePath, next); err != nil {
				c.status.Error = fmt.Sprintf("persist node state: %v", err)
				c.mu.Unlock()
				return
			}
			c.state = next
		}
	}
	mustApply := s.NetMap != nil && s.LoggedIn && s.Err == nil
	loggedOut := !s.LoggedIn
	c.mu.Unlock()
	if loggedOut {
		// Never retain a previously authorized route after logout,
		// revoked machine authorization, or auth state reset.
		c.deactivateNetMap()
		return
	}
	if !mustApply {
		return
	}
	err := c.applyNetMap(s.NetMap)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if err != nil {
		c.status.Error = err.Error()
		c.status.Ready = false
		return
	}
	c.status.Error = ""
	c.status.Ready = true
	c.readyOnce.Do(func() { close(c.ready) })
}

// WaitReady returns only after the client has obtained an authorized NetMap
// and successfully applied routing and WireGuard configuration.
func (c *Client) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ready:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return errors.New("tailscale-lite: closed")
		}
		if c.status.Error != "" {
			return errors.New(c.status.Error)
		}
		if !c.status.Ready {
			return errors.New("tailscale-lite: not ready")
		}
		return nil
	}
}

// WaitTransportReady waits until the initial NetMap is applied and magicsock
// has completed and reported its initial network check to control. This keeps
// callers from exposing a new peer route before control has the local DERP
// region and endpoint information needed to route the first WireGuard handshake.
func (c *Client) WaitTransportReady(ctx context.Context) error {
	if err := c.WaitReady(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("tailscale-lite: closed")
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.netInfoReady:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return errors.New("tailscale-lite: closed")
		}
		if !c.netInfoReadySet {
			return errors.New("tailscale-lite: closed")
		}
		if !c.status.Ready {
			return errors.New("tailscale-lite: not ready")
		}
		return nil
	}
}

// Snapshot returns status with its address slice owned by the caller.
func (c *Client) Snapshot() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.status
	s.Addresses = append([]netip.Prefix(nil), s.Addresses...)
	return s
}

// Route looks up a validated Tailnet route. It never dials host sockets.
func (c *Client) Route(ip netip.Addr) (key.NodePublic, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.status.Ready {
		return key.NodePublic{}, false
	}
	return c.routes.lookup(ip)
}

func (c *Client) Close() error {
	c.applyMu.Lock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		c.applyMu.Unlock()
		return nil
	}
	c.closed = true
	ctl := c.control
	engine := c.engine
	monitor := c.monitor
	bus := c.bus
	release := c.stateRelease
	c.stateRelease = nil
	c.readyOnce.Do(func() { close(c.ready) })
	if !c.netInfoReadySet {
		close(c.netInfoReady)
	}
	c.mu.Unlock()
	c.applyMu.Unlock()
	if ctl != nil {
		ctl.Shutdown()
	}
	if engine != nil {
		engine.Close()
	}
	if monitor != nil {
		monitor.Close()
	}
	if bus != nil {
		bus.Close()
	}
	if release != nil {
		release()
	}
	return nil
}

// Closing a client is final. Another instance may load the same state only
// after the prior client has shut down and released its resources.
func (c *Client) Closed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
