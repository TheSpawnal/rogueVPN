package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/control"
	"wyrm/internal/disco"
	"wyrm/internal/flow"
	"wyrm/internal/keys"
	"wyrm/internal/platform"
	"wyrm/internal/proto"
	"wyrm/internal/stun"
	"wyrm/internal/tap"
	"wyrm/internal/transport"
	"wyrm/internal/transport/wg"
	"wyrm/internal/version"
)

const (
	// DefaultMTU is the IPv6 minimum MTU. It survives every common
	// underlay (PPPoE, mobile, nested tunnels) without fragmentation.
	DefaultMTU = 1280

	keepalive   = 25 * time.Second
	maxPeers    = 10000
	oobQueue    = 512
	stunPeriod  = 25 * time.Second
	stunRetry   = 3 * time.Second
	stunTTL     = 90 * time.Second
	addrRefresh = 10 * time.Second
)

// Config configures a node engine.
type Config struct {
	StateDir   string
	Iface      string
	ListenPort uint16
	MTU        int
	// NoLAN stops the node from advertising its local interface addresses.
	// Peers on the same LAN then connect through the router instead of
	// directly, but the coordination server and peers learn nothing about
	// the local network.
	NoLAN bool
	Log   *slog.Logger
}

type oobPkt struct {
	b    []byte
	from netip.AddrPort
}

type stunReq struct {
	server netip.AddrPort
	sent   time.Time
}

// Engine is a running node.
type Engine struct {
	cfg     Config
	log     *slog.Logger
	st      *State
	ctl     *control.Client
	tr      transport.Transport
	flows   *flow.Table
	iface   string
	started time.Time

	discoPriv keys.Private
	discoPub  keys.Public
	oob       chan oobPkt
	oobDrops  atomic.Uint64
	epChanged chan struct{}

	mu          sync.Mutex
	peers       map[keys.Public]*peer // by tunnel key
	byDisco     map[keys.Public]*peer
	endpoints   []netip.AddrPort
	reflexive   map[netip.AddrPort]time.Time
	stunPending map[stun.TxID]stunReq
	stunServers []netip.AddrPort
	lastSTUN    time.Time
	lastAddrs   time.Time
	coordState  string
	coordSync   time.Time
}

// New builds the tunnel and prepares the engine. Call Run to start it.
func New(cfg Config, st *State) (*Engine, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < 1280 || cfg.MTU > 1420 {
		return nil, errors.New("engine: MTU must be between 1280 and 1420")
	}
	ctl, err := control.New(st.CoordURL, st.CoordPin, st.id)
	if err != nil {
		return nil, err
	}
	dp, err := keys.NewPrivate()
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg: cfg, log: cfg.Log, st: st, ctl: ctl,
		flows:       flow.NewTable(),
		started:     time.Now(),
		discoPriv:   dp,
		discoPub:    dp.Public(),
		oob:         make(chan oobPkt, oobQueue),
		epChanged:   make(chan struct{}, 1),
		peers:       make(map[keys.Public]*peer),
		byDisco:     make(map[keys.Public]*peer),
		reflexive:   make(map[netip.AddrPort]time.Time),
		stunPending: make(map[stun.TxID]stunReq),
		coordState:  "connecting",
	}
	e.flows.SetLocal(st.IP, st.CIDR)
	if err := loadPolicy(cfg.StateDir, e.flows); err != nil {
		return nil, err
	}
	e.flows.OnChange(func(p flow.Policy) {
		if err := savePolicy(cfg.StateDir, p); err != nil {
			e.log.Error("policy save failed", "err", err)
		}
	})

	dev, err := platform.CreateTUN(cfg.Iface, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tunnel device: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	e.iface = name
	tr, err := wg.New(wg.Config{
		TUN:        tap.New(dev, e.flows),
		PrivateKey: st.wgKey,
		ListenPort: cfg.ListenPort,
		OOBMatch:   func(b []byte) bool { return disco.LooksLike(b) || stun.IsResponse(b) },
		OOBRecv:    e.recvOOB,
		Log:        cfg.Log,
	})
	if err != nil {
		return nil, err
	}
	e.tr = tr
	addr := netip.PrefixFrom(st.IP, st.CIDR.Bits())
	if err := platform.ConfigureInterface(name, addr, cfg.MTU); err != nil {
		tr.Close()
		return nil, fmt.Errorf("configure %s: %w", name, err)
	}
	e.log.Info("tunnel up", "iface", name, "addr", addr.String(), "port", tr.LocalPort(),
		"transport", tr.Name(), "node", st.NodeID)
	return e, nil
}

// Table exposes the flow inspector.
func (e *Engine) Table() *flow.Table { return e.flows }

// Run drives the engine until ctx is cancelled, then tears the tunnel down.
func (e *Engine) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){e.discoLoop, e.updateLoop, e.pollLoop, e.flowLoop} {
		wg.Add(1)
		go func() { defer wg.Done(); fn(ctx) }()
	}
	<-ctx.Done()
	wg.Wait()
	e.tr.Close()
	e.log.Info("tunnel down", "iface", e.iface)
}

func (e *Engine) flowLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.flows.Tick()
		}
	}
}

// recvOOB runs on the transport's receive path: copy and queue, never block.
func (e *Engine) recvOOB(b []byte, from netip.AddrPort) {
	select {
	case e.oob <- oobPkt{b: append([]byte(nil), b...), from: from}:
	default:
		e.oobDrops.Add(1) // lock-free: this runs on the tunnel's receive path
	}
}

func (e *Engine) signalEndpoints() {
	select {
	case e.epChanged <- struct{}{}:
	default:
	}
}

// updateLoop publishes the discovery key and endpoints whenever they change.
func (e *Engine) updateLoop(ctx context.Context) {
	e.signalEndpoints()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.epChanged:
		}
		backoff := time.Second
		for {
			e.mu.Lock()
			req := proto.UpdateRequest{DiscoPub: e.discoPub, Endpoints: slices.Clone(e.endpoints)}
			e.mu.Unlock()
			if req.Endpoints == nil {
				req.Endpoints = []netip.AddrPort{}
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := e.ctl.Update(cctx, req)
			cancel()
			if err == nil || ctx.Err() != nil {
				break
			}
			e.log.Debug("endpoint update failed", "err", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

// pollLoop long-polls the coordination server for network maps.
func (e *Engine) pollLoop(ctx context.Context) {
	var since uint64
	backoff := time.Second
	for ctx.Err() == nil {
		nm, err := e.ctl.NetMap(ctx, since)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			state := "unreachable"
			if errors.Is(err, control.ErrUnauthorized) {
				state = "unauthorized"
				backoff = 30 * time.Second
			}
			e.mu.Lock()
			changed := e.coordState != state
			e.coordState = state
			e.mu.Unlock()
			if changed {
				e.log.Warn("coordination server "+state, "err", err)
			}
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		e.mu.Lock()
		was := e.coordState
		e.coordState, e.coordSync = "synced", time.Now()
		e.mu.Unlock()
		if nm == nil {
			continue
		}
		since = nm.Version
		e.resolveSTUN(ctx, nm.STUNPort)
		n := e.applyNetMap(nm)
		if was != "synced" {
			e.log.Info("coordination server synced", "peers", n)
		}
		if nm.Self.DiscoPub != e.discoPub {
			e.signalEndpoints() // the server lost our live state (restart)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (e *Engine) resolveSTUN(ctx context.Context, port uint16) {
	if port == 0 {
		return
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(e.ctl.Host()); err == nil {
		addrs = []netip.Addr{a}
	} else {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, _ = net.DefaultResolver.LookupNetIP(cctx, "ip", e.ctl.Host())
		cancel()
	}
	var servers []netip.AddrPort
	var have4, have6 bool
	for _, a := range addrs {
		a = a.Unmap()
		if (a.Is4() && have4) || (a.Is6() && have6) {
			continue
		}
		have4, have6 = have4 || a.Is4(), have6 || a.Is6()
		servers = append(servers, netip.AddrPortFrom(a, port))
	}
	if len(servers) == 0 {
		return
	}
	e.mu.Lock()
	if !slices.Equal(e.stunServers, servers) {
		e.stunServers = servers
		e.lastSTUN = time.Time{}
	}
	e.mu.Unlock()
}

// usableEndpoint filters addresses that must never become tunnel endpoints,
// most importantly anything inside the mesh itself (a routing loop).
func (e *Engine) usableEndpoint(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.IsValid() && ap.Port() != 0 && a.Zone() == "" && !a.IsUnspecified() &&
		!a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !e.st.CIDR.Contains(a)
}

// refreshEndpointsLocked recomputes the endpoints this node advertises.
func (e *Engine) refreshEndpointsLocked(now time.Time) {
	var eps []netip.AddrPort
	for ap, seen := range e.reflexive {
		if now.Sub(seen) > stunTTL {
			delete(e.reflexive, ap)
			continue
		}
		eps = append(eps, ap)
	}
	slices.SortFunc(eps, netip.AddrPort.Compare)
	if !e.cfg.NoLAN {
		port := e.tr.LocalPort()
		var local []netip.AddrPort
		for _, a := range platform.LocalAddrs(e.iface) {
			if ap := netip.AddrPortFrom(a, port); e.usableEndpoint(ap) && !slices.Contains(eps, ap) {
				local = append(local, ap)
			}
		}
		slices.SortFunc(local, netip.AddrPort.Compare)
		eps = append(eps, local...)
	}
	if len(eps) > proto.MaxEndpoints {
		eps = eps[:proto.MaxEndpoints]
	}
	if !slices.Equal(eps, e.endpoints) {
		e.endpoints = eps
		e.signalEndpoints()
	}
}

// Status reports the local node.
func (e *Engine) Status() api.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return api.Status{
		Version: version.Version, NodeID: e.st.NodeID, Name: e.st.Name,
		IP: e.st.IP, CIDR: e.st.CIDR, Iface: e.iface,
		ListenPort: e.tr.LocalPort(), Transport: e.tr.Name(),
		CoordURL: e.st.CoordURL, CoordState: e.coordState, CoordSync: e.coordSync,
		Endpoints: slices.Clone(e.endpoints), Shields: e.flows.Shields(),
		Started: e.started, Totals: e.flows.Totals(),
	}
}

// Peers reports every remote node and the link to it.
func (e *Engine) Peers() []api.Peer {
	stats, err := e.tr.Stats()
	if err != nil {
		e.log.Debug("transport stats failed", "err", err)
	}
	byKey := make(map[keys.Public]transport.PeerStats, len(stats))
	for _, s := range stats {
		byKey[s.PublicKey] = s
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]api.Peer, 0, len(e.peers))
	for k, p := range e.peers {
		s := byKey[k]
		ap := api.Peer{
			ID: p.node.ID, Name: p.node.Name, IP: p.node.IP, Key: k.Short(),
			Online: p.node.Online, Endpoint: s.Endpoint, Candidates: len(p.cands),
			LastHandshake: s.LastHandshake, RxBytes: s.RxBytes, TxBytes: s.TxBytes,
		}
		switch {
		case p.bestValid(now):
			ap.Path = api.PathDirect
			ap.RTTMillis = float64(p.cands[p.best].rtt) / float64(time.Millisecond)
		case !s.LastHandshake.IsZero() && now.Sub(s.LastHandshake) < 3*time.Minute:
			ap.Path = api.PathActive
		case p.node.Online:
			ap.Path = api.PathProbing
		default:
			ap.Path = api.PathOffline
		}
		out = append(out, ap)
	}
	slices.SortFunc(out, func(a, b api.Peer) int { return a.IP.Compare(b.IP) })
	return out
}
