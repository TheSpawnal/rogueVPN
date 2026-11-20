package engine

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wyrm/internal/disco"
	"wyrm/internal/flow"
	"wyrm/internal/keys"
	"wyrm/internal/proto"
	"wyrm/internal/stun"
	"wyrm/internal/transport"
)

type wire struct {
	from, to netip.AddrPort
	b        []byte
}

// fakeNet delivers datagrams between engines. Addresses are rewritten the
// way a NAT would: each engine sends from its public address.
type fakeNet struct {
	queue []wire
	nodes map[netip.AddrPort]*Engine
	seen  []wire
	drop  func(w wire) bool
}

type fakeTransport struct {
	net       *fakeNet
	public    netip.AddrPort
	endpoints map[keys.Public]netip.AddrPort
	removed   []keys.Public
}

func (f *fakeTransport) Name() string      { return "fake" }
func (f *fakeTransport) LocalPort() uint16 { return 51820 }
func (f *fakeTransport) Close() error      { return nil }
func (f *fakeTransport) UpsertPeer(p transport.PeerConfig) error {
	f.endpoints[p.PublicKey] = p.Endpoint
	return nil
}
func (f *fakeTransport) RemovePeer(k keys.Public) error {
	delete(f.endpoints, k)
	f.removed = append(f.removed, k)
	return nil
}
func (f *fakeTransport) SetEndpoint(k keys.Public, ep netip.AddrPort) error {
	f.endpoints[k] = ep
	return nil
}
func (f *fakeTransport) Stats() ([]transport.PeerStats, error) { return nil, nil }
func (f *fakeTransport) SendOOB(b []byte, to netip.AddrPort) error {
	f.net.queue = append(f.net.queue, wire{f.public, to, append([]byte(nil), b...)})
	return nil
}

func (n *fakeNet) pump(now time.Time) {
	for len(n.queue) > 0 {
		w := n.queue[0]
		n.queue = n.queue[1:]
		n.seen = append(n.seen, w)
		if n.drop != nil && n.drop(w) {
			continue
		}
		if e := n.nodes[w.to]; e != nil {
			e.handleOOB(oobPkt{b: w.b, from: w.from}, now)
		}
	}
}

var meshCIDR = netip.MustParsePrefix("10.88.0.0/16")

func testEngine(t *testing.T, n *fakeNet, ip, public string) (*Engine, *fakeTransport) {
	t.Helper()
	wk, _ := keys.NewPrivate()
	dk, _ := keys.NewPrivate()
	ft := &fakeTransport{net: n, public: netip.MustParseAddrPort(public), endpoints: map[keys.Public]netip.AddrPort{}}
	e := &Engine{
		cfg:         Config{NoLAN: true},
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:          &State{IP: netip.MustParseAddr(ip), CIDR: meshCIDR, wgKey: wk, Name: ip},
		tr:          ft,
		flows:       flow.NewTable(),
		discoPriv:   dk,
		discoPub:    dk.Public(),
		epChanged:   make(chan struct{}, 1),
		peers:       map[keys.Public]*peer{},
		byDisco:     map[keys.Public]*peer{},
		reflexive:   map[netip.AddrPort]time.Time{},
		stunPending: map[stun.TxID]stunReq{},
	}
	n.nodes[ft.public] = e
	return e, ft
}

func view(e *Engine, name string, eps ...string) proto.Node {
	n := proto.Node{ID: name, Name: name, WGPub: e.st.wgKey.Public(), DiscoPub: e.discoPub, IP: e.st.IP, Online: true}
	for _, s := range eps {
		n.Endpoints = append(n.Endpoints, netip.MustParseAddrPort(s))
	}
	return n
}

func TestPathDiscovery(t *testing.T) {
	n := &fakeNet{nodes: map[netip.AddrPort]*Engine{}}
	a, ta := testEngine(t, n, "10.88.0.1", "198.51.100.1:40001")
	b, tb := testEngine(t, n, "10.88.0.2", "203.0.113.2:40002")
	now := time.Unix(1_800_000_000, 0)

	// A only knows B's LAN address (unreachable) and its public one. B knows
	// a wrong port for A, as happens behind a NAT that remaps ports: it must
	// learn the real one from A's ping.
	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(b, "b", "192.168.2.2:51820", "203.0.113.2:40002")}})
	b.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(a, "a", "198.51.100.1:9")}})
	if got := ta.endpoints[b.st.wgKey.Public()]; got.IsValid() {
		t.Fatalf("transport given an unconfirmed endpoint: %v", got)
	}

	a.tick(now)
	b.tick(now)
	n.pump(now.Add(20 * time.Millisecond))

	wantB := netip.MustParseAddrPort("203.0.113.2:40002")
	wantA := netip.MustParseAddrPort("198.51.100.1:40001")
	if got := ta.endpoints[b.st.wgKey.Public()]; got != wantB {
		t.Fatalf("A did not move to B's working endpoint: %v", got)
	}
	if got := tb.endpoints[a.st.wgKey.Public()]; got != wantA {
		t.Fatalf("B did not learn A's mapped endpoint: %v", got)
	}
	pa := a.peers[b.st.wgKey.Public()]
	if !pa.bestValid(now.Add(time.Second)) || pa.cands[wantB].rtt != 20*time.Millisecond {
		t.Fatalf("path state: %+v", pa.cands[wantB])
	}

	// Replay: a captured ping re-sent from a spoofed address must produce
	// no reply and no new candidate.
	var ping wire
	for _, w := range n.seen {
		if w.from == wantA && w.to == wantB {
			ping = w
			break
		}
	}
	pb := b.peers[a.st.wgKey.Public()]
	before, sent := len(pb.cands), len(n.seen)
	spoof := netip.MustParseAddrPort("192.0.2.66:6666")
	b.handleOOB(oobPkt{b: ping.b, from: spoof}, now.Add(time.Second))
	n.pump(now.Add(time.Second))
	if len(pb.cands) != before || len(n.seen) != sent {
		t.Fatalf("replayed ping was processed (cands %d->%d, packets %d->%d)", before, len(pb.cands), sent, len(n.seen))
	}

	// A third party that is not in the network map is ignored entirely.
	c, _ := testEngine(t, n, "10.88.0.3", "192.0.2.3:40003")
	shared, _ := disco.Shared(c.discoPriv, b.discoPub)
	tx, _ := disco.NewTxID()
	forged, _ := disco.Seal(c.discoPub, shared, disco.Ping(tx))
	b.handleOOB(oobPkt{b: forged, from: netip.MustParseAddrPort("192.0.2.3:40003")}, now.Add(time.Second))
	// ...and so is one that claims A's disco key without owning it.
	forged, _ = disco.Seal(a.discoPub, shared, disco.Ping(tx))
	b.handleOOB(oobPkt{b: forged, from: netip.MustParseAddrPort("192.0.2.3:40003")}, now.Add(time.Second))
	if len(n.queue) != 0 || len(pb.cands) != before {
		t.Fatal("unauthenticated ping was answered")
	}

	// Path loss: when pongs stop, the path is dropped and probing resumes.
	n.drop = func(wire) bool { return true }
	later := now
	for i := 0; i < 20; i++ {
		later = later.Add(time.Second)
		a.tick(later)
		n.pump(later)
	}
	if pa.best.IsValid() {
		t.Fatal("dead path kept")
	}
	n.drop = nil
	later = later.Add(3 * time.Second)
	a.tick(later)
	n.pump(later)
	if pa.best != wantB {
		t.Fatalf("path not recovered: %v", pa.best)
	}

	// Removal from the network map removes the tunnel peer.
	a.applyNetMap(&proto.NetMap{})
	if len(a.peers) != 0 || len(a.byDisco) != 0 || len(ta.removed) != 1 {
		t.Fatal("peer not removed")
	}
}

func TestKeyChangeIsReported(t *testing.T) {
	n := &fakeNet{nodes: map[netip.AddrPort]*Engine{}}
	a, ta := testEngine(t, n, "10.88.0.1", "198.51.100.1:40001")
	b, _ := testEngine(t, n, "10.88.0.2", "203.0.113.2:40002")
	var logs bytes.Buffer
	a.log = slog.New(slog.NewTextHandler(&logs, nil))

	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(b, "b", "203.0.113.2:40002")}})
	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(b, "b", "203.0.113.2:40003")}})
	if strings.Contains(logs.String(), "key behind a mesh address changed") {
		t.Fatal("warned without a key change")
	}
	// Same node, same address, different tunnel key.
	swapped := view(b, "b", "203.0.113.2:40002")
	other, _ := keys.NewPrivate()
	swapped.WGPub = other.Public()
	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{swapped}})
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "key behind a mesh address changed") {
		t.Fatalf("key substitution not reported: %s", logs.String())
	}
	if len(a.peers) != 1 || a.peers[other.Public()] == nil || len(ta.removed) != 1 {
		t.Fatal("old key not replaced")
	}
}

func TestPathPreference(t *testing.T) {
	n := &fakeNet{nodes: map[netip.AddrPort]*Engine{}}
	a, ta := testEngine(t, n, "10.88.0.1", "198.51.100.1:40001")
	b, _ := testEngine(t, n, "10.88.0.2", "203.0.113.2:40002")
	lan := netip.MustParseAddrPort("192.168.1.20:51820")
	wan := netip.MustParseAddrPort("203.0.113.2:40002")
	n.nodes[lan] = b // B is reachable on both
	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(b, "b", wan.String(), lan.String())}})
	b.applyNetMap(&proto.NetMap{Peers: []proto.Node{view(a, "a", "198.51.100.1:40001")}})
	p := a.peers[b.st.wgKey.Public()]
	now := time.Unix(1_800_000_000, 0)

	pong := func(ap netip.AddrPort, rtt time.Duration, at time.Time) {
		c := p.cands[ap]
		c.lastPong, c.rtt = at, rtt
		a.mu.Lock()
		a.selectPathLocked(p, at)
		a.mu.Unlock()
	}
	pong(wan, 30*time.Millisecond, now)
	if ta.endpoints[b.st.wgKey.Public()] != wan {
		t.Fatal("first confirmed path not used")
	}
	pong(lan, 25*time.Millisecond, now) // better, but not clearly: stay
	if p.best != wan {
		t.Fatal("flapped to a marginally faster path")
	}
	pong(lan, time.Millisecond, now) // clearly better: move
	if p.best != lan || ta.endpoints[b.st.wgKey.Public()] != lan {
		t.Fatal("did not move to the clearly faster path")
	}
}

func TestNetMapValidation(t *testing.T) {
	n := &fakeNet{nodes: map[netip.AddrPort]*Engine{}}
	a, _ := testEngine(t, n, "10.88.0.1", "198.51.100.1:40001")
	b, _ := testEngine(t, n, "10.88.0.2", "203.0.113.2:40002")
	c, _ := testEngine(t, n, "10.88.0.3", "192.0.2.3:40003")

	self := view(a, "self", "192.0.2.9:1")
	outside := view(b, "outside", "192.0.2.9:1")
	outside.IP = netip.MustParseAddr("192.168.0.1") // would hijack a LAN address
	dupIP := view(c, "dup", "192.0.2.9:1")
	dupIP.IP = b.st.IP
	// Endpoints inside the mesh or otherwise unusable must never reach the tunnel.
	good := view(b, "b", "10.88.0.7:51820", "127.0.0.1:51820", "[fe80::1]:51820", "0.0.0.0:1", "192.0.2.50:51820")

	a.applyNetMap(&proto.NetMap{Peers: []proto.Node{self, outside, good, dupIP}})
	if len(a.peers) != 1 {
		t.Fatalf("accepted %d peers, want 1", len(a.peers))
	}
	p := a.peers[b.st.wgKey.Public()]
	if p == nil || len(p.cands) != 1 || p.cands[netip.MustParseAddrPort("192.0.2.50:51820")] == nil {
		t.Fatalf("candidates not filtered: %v", p.cands)
	}

	// STUN: only a reply from the server we asked, to a request we made.
	srv := netip.MustParseAddrPort("192.0.2.200:3478")
	a.stunServers = []netip.AddrPort{srv}
	now := time.Unix(1_800_000_000, 0)
	a.tick(now)
	var tx stun.TxID
	for _, w := range n.queue {
		if w.to == srv {
			tx, _ = stun.ParseRequest(w.b)
		}
	}
	n.queue = nil
	mapped := netip.MustParseAddrPort("198.51.100.1:40001")
	other, _, _ := stun.NewRequest()
	a.handleOOB(oobPkt{b: stun.Response(other, mapped), from: srv}, now)
	a.handleOOB(oobPkt{b: stun.Response(tx, mapped), from: netip.MustParseAddrPort("192.0.2.66:3478")}, now)
	a.handleOOB(oobPkt{b: stun.Response(tx, netip.MustParseAddrPort("10.88.0.9:1")), from: srv}, now)
	if len(a.endpoints) != 0 {
		t.Fatalf("spoofed STUN reply accepted: %v", a.endpoints)
	}
	a.stunPending[tx] = stunReq{server: srv, sent: now}
	a.handleOOB(oobPkt{b: stun.Response(tx, mapped), from: srv}, now)
	if len(a.endpoints) != 1 || a.endpoints[0] != mapped {
		t.Fatalf("STUN reply not used: %v", a.endpoints)
	}
}
