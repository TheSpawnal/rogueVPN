package flow

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxFlows = 65536
	ringSize        = 2048
	maxSubs         = 4

	idleTCP       = 30 * time.Minute
	idleTCPClosed = 10 * time.Second
	idleUDP       = 2 * time.Minute
	idleOther     = 30 * time.Second
)

// Key identifies a flow from this host's point of view.
type Key struct {
	Proto      uint8
	Local      netip.Addr
	Remote     netip.Addr
	LocalPort  uint16
	RemotePort uint16
}

type pairKey struct {
	proto         uint8
	local, remote netip.Addr
}

type entry struct {
	key       Key
	initiator Dir
	first     int64
	last      int64
	txPkts    uint64
	rxPkts    uint64
	txBytes   uint64
	rxBytes   uint64
	dropped   uint64
	flagsOut  uint8
	flagsIn   uint8
	prevTx    uint64
	prevRx    uint64
	txRate    float64
	rxRate    float64
}

func (e *entry) closed() bool {
	return (e.flagsIn|e.flagsOut)&TCPRst != 0 || (e.flagsIn&TCPFin != 0 && e.flagsOut&TCPFin != 0)
}

func (e *entry) idleLimit() time.Duration {
	switch e.key.Proto {
	case ProtoTCP:
		if e.closed() {
			return idleTCPClosed
		}
		return idleTCP
	case ProtoUDP:
		return idleUDP
	}
	return idleOther
}

func (e *entry) state() string {
	if e.key.Proto != ProtoTCP {
		return "-"
	}
	all := e.flagsIn | e.flagsOut
	switch {
	case all&TCPRst != 0:
		return "rst"
	case e.flagsIn&TCPFin != 0 && e.flagsOut&TCPFin != 0:
		return "closed"
	case all&TCPFin != 0:
		return "closing"
	case e.flagsIn&TCPAck != 0 && e.flagsOut&TCPAck != 0:
		return "est"
	}
	return "syn"
}

// FlowInfo is the exported view of one flow.
type FlowInfo struct {
	Proto     uint8          `json:"proto"`
	Local     netip.AddrPort `json:"local"`
	Remote    netip.AddrPort `json:"remote"`
	Initiator string         `json:"initiator"`
	State     string         `json:"state"`
	First     time.Time      `json:"first"`
	Last      time.Time      `json:"last"`
	TxPkts    uint64         `json:"tx_pkts"`
	RxPkts    uint64         `json:"rx_pkts"`
	TxBytes   uint64         `json:"tx_bytes"`
	RxBytes   uint64         `json:"rx_bytes"`
	TxRate    float64        `json:"tx_rate"`
	RxRate    float64        `json:"rx_rate"`
	Dropped   uint64         `json:"dropped"`
}

// PacketInfo is one entry of the recent-packet ring.
type PacketInfo struct {
	Seq       uint64         `json:"seq"`
	Time      time.Time      `json:"time"`
	Dir       string         `json:"dir"`
	Verdict   string         `json:"verdict"`
	Proto     uint8          `json:"proto"`
	Src       netip.AddrPort `json:"src"`
	Dst       netip.AddrPort `json:"dst"`
	Len       int            `json:"len"`
	TCPFlags  uint8          `json:"tcp_flags,omitempty"`
	ICMPType  uint8          `json:"icmp_type,omitempty"`
	ICMPCode  uint8          `json:"icmp_code,omitempty"`
	Frag      bool           `json:"frag,omitempty"`
	Malformed bool           `json:"malformed,omitempty"`
}

type pktRec struct {
	seq       uint64
	ts        int64
	p         Packet
	dir       Dir
	drop      bool
	malformed bool
}

// Totals are interface-wide counters.
type Totals struct {
	TxPkts    uint64  `json:"tx_pkts"`
	RxPkts    uint64  `json:"rx_pkts"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxRate    float64 `json:"tx_rate"`
	RxRate    float64 `json:"rx_rate"`
	DropOut   uint64  `json:"drop_out"`
	DropIn    uint64  `json:"drop_in"`
	Malformed uint64  `json:"malformed"`
	// ForeignOut and ForeignIn count packets that are not traffic between
	// this node's mesh address and another mesh address. Outbound ones are
	// ordinary host noise on the interface; inbound ones mean a peer sent
	// something it should not have.
	ForeignOut uint64 `json:"foreign_out"`
	ForeignIn  uint64 `json:"foreign_in"`
	Flows      int    `json:"flows"`
}

type localAddrs struct {
	self netip.Addr
	mesh netip.Prefix
}

// CapPacket is one captured packet delivered to a subscriber.
type CapPacket struct {
	Time time.Time
	Orig int
	Data []byte
}

// Sub is a live capture subscription.
type Sub struct {
	C       chan CapPacket
	snaplen int
	dropped atomic.Uint64
}

// Dropped returns how many packets were skipped because the subscriber was slow.
func (s *Sub) Dropped() uint64 { return s.dropped.Load() }

// Table tracks flows and applies the filter policy. All methods are safe for
// concurrent use.
type Table struct {
	mu    sync.Mutex
	flows map[Key]*entry
	pairs map[pairKey]int // out-initiated flows per address pair
	max   int
	ring  [ringSize]pktRec
	seq   uint64

	lastTick int64

	rules   atomic.Pointer[ruleset]
	shields atomic.Bool
	local   atomic.Pointer[localAddrs]
	subs    atomic.Pointer[[]*Sub]

	pmu      sync.Mutex // serializes policy and subscription changes
	nextID   uint32
	onChange func(Policy)

	txPkts, rxPkts, txBytes, rxBytes atomic.Uint64
	dropOut, dropIn, malformed       atomic.Uint64
	foreignOut, foreignIn            atomic.Uint64

	rateMu         sync.Mutex
	prevTx, prevRx uint64
	prevAt         int64
	txRate, rxRate float64
}

// NewTable returns an empty table with an allow-all policy.
func NewTable() *Table {
	t := &Table{
		flows:  make(map[Key]*entry),
		pairs:  make(map[pairKey]int),
		max:    defaultMaxFlows,
		nextID: 1,
	}
	t.rules.Store(&ruleset{})
	return t
}

// SetLocal confines the tunnel to mesh traffic of this node: outbound
// packets must go from self to a mesh address, inbound packets from a mesh
// address to self. Everything else is dropped before any rule is consulted.
// Without this, a peer could aim packets at other networks this host is
// attached to and have the host's kernel forward them.
func (t *Table) SetLocal(self netip.Addr, mesh netip.Prefix) {
	t.local.Store(&localAddrs{self: self, mesh: mesh.Masked()})
}

// Process accounts for one packet and returns whether it may pass.
func (t *Table) Process(dir Dir, b []byte) bool {
	now := time.Now().UnixNano()
	p, ok := Decode(b)
	if !ok {
		t.malformed.Add(1)
		t.countDrop(dir)
		t.mu.Lock()
		t.record(now, dir, &Packet{Len: len(b)}, true, true)
		t.mu.Unlock()
		t.capture(now, b)
		return false
	}

	if l := t.local.Load(); l != nil {
		if dir == Out && (p.Src != l.self || !l.mesh.Contains(p.Dst)) {
			t.foreignOut.Add(1)
			return false
		}
		if dir == In && (p.Dst != l.self || !l.mesh.Contains(p.Src)) {
			t.foreignIn.Add(1)
			t.mu.Lock()
			t.record(now, dir, &p, true, false)
			t.mu.Unlock()
			t.capture(now, b)
			return false
		}
	}

	var key Key
	key.Proto = p.Proto
	if dir == Out {
		key.Local, key.Remote = p.Src, p.Dst
		key.LocalPort, key.RemotePort = p.SrcPort, p.DstPort
	} else {
		key.Local, key.Remote = p.Dst, p.Src
		key.LocalPort, key.RemotePort = p.DstPort, p.SrcPort
	}

	v := t.rules.Load().eval(dir, &p, key.Remote)

	t.mu.Lock()
	e := t.flows[key]
	if v == vNone {
		v = vAllow
		if dir == In && t.shields.Load() && !t.related(e, &p, &key) {
			v = vDrop
		}
	}
	if v == vAllow {
		if e == nil {
			e = t.insert(key, dir, now)
		}
		if e != nil {
			e.last = now
			if dir == Out {
				e.txPkts++
				e.txBytes += uint64(p.Len)
				e.flagsOut |= p.TCPFlags
			} else {
				e.rxPkts++
				e.rxBytes += uint64(p.Len)
				e.flagsIn |= p.TCPFlags
			}
		}
	} else if e != nil {
		e.dropped++
	}
	t.record(now, dir, &p, v == vDrop, false)
	t.mu.Unlock()

	if v == vAllow {
		if dir == Out {
			t.txPkts.Add(1)
			t.txBytes.Add(uint64(p.Len))
		} else {
			t.rxPkts.Add(1)
			t.rxBytes.Add(uint64(p.Len))
		}
	} else {
		t.countDrop(dir)
	}
	t.capture(now, b)
	return v == vAllow
}

// related decides whether an inbound packet may pass in shields mode: it
// must belong to a flow this host opened, be a trailing fragment between a
// pair of addresses with such a flow, or be an ICMP error.
func (t *Table) related(e *entry, p *Packet, k *Key) bool {
	if e != nil && e.initiator == Out {
		return true
	}
	if p.Frag {
		return t.pairs[pairKey{k.Proto, k.Local, k.Remote}] > 0
	}
	return p.icmpError()
}

func (t *Table) insert(k Key, dir Dir, now int64) *entry {
	if len(t.flows) >= t.max {
		if dir == In {
			return nil // never let remote traffic evict local state
		}
		t.evictOne()
	}
	e := &entry{key: k, initiator: dir, first: now, last: now}
	t.flows[k] = e
	if dir == Out {
		t.pairs[pairKey{k.Proto, k.Local, k.Remote}]++
	}
	return e
}

func (t *Table) remove(e *entry) {
	delete(t.flows, e.key)
	if e.initiator == Out {
		pk := pairKey{e.key.Proto, e.key.Local, e.key.Remote}
		if n := t.pairs[pk]; n <= 1 {
			delete(t.pairs, pk)
		} else {
			t.pairs[pk] = n - 1
		}
	}
}

// evictOne drops the least recently active of a small random sample,
// preferring flows opened by the remote side.
func (t *Table) evictOne() {
	var victim *entry
	n := 0
	for _, e := range t.flows {
		if victim == nil ||
			(e.initiator == In && victim.initiator == Out) ||
			(e.initiator == victim.initiator && e.last < victim.last) {
			victim = e
		}
		if n++; n >= 16 {
			break
		}
	}
	if victim != nil {
		t.remove(victim)
	}
}

func (t *Table) record(now int64, dir Dir, p *Packet, drop, malformed bool) {
	t.seq++
	t.ring[t.seq%ringSize] = pktRec{seq: t.seq, ts: now, p: *p, dir: dir, drop: drop, malformed: malformed}
}

func (t *Table) countDrop(dir Dir) {
	if dir == Out {
		t.dropOut.Add(1)
	} else {
		t.dropIn.Add(1)
	}
}

func (t *Table) capture(now int64, b []byte) {
	subs := t.subs.Load()
	if subs == nil {
		return
	}
	for _, s := range *subs {
		n := min(len(b), s.snaplen)
		cp := CapPacket{Time: time.Unix(0, now), Orig: len(b), Data: append([]byte(nil), b[:n]...)}
		select {
		case s.C <- cp:
		default:
			s.dropped.Add(1)
		}
	}
}

// Tick expires idle flows and refreshes rates. Call it about once a second.
func (t *Table) Tick() {
	now := time.Now().UnixNano()
	t.mu.Lock()
	dt := float64(now-t.lastTick) / 1e9
	for _, e := range t.flows {
		if time.Duration(now-e.last) > e.idleLimit() {
			t.remove(e)
			continue
		}
		if t.lastTick != 0 && dt > 0 {
			e.txRate, e.rxRate = float64(e.txBytes-e.prevTx)/dt, float64(e.rxBytes-e.prevRx)/dt
		}
		e.prevTx, e.prevRx = e.txBytes, e.rxBytes
	}
	t.lastTick = now
	t.mu.Unlock()

	t.rateMu.Lock()
	tx, rx := t.txBytes.Load(), t.rxBytes.Load()
	if dt := float64(now-t.prevAt) / 1e9; t.prevAt != 0 && dt > 0 {
		t.txRate, t.rxRate = float64(tx-t.prevTx)/dt, float64(rx-t.prevRx)/dt
	}
	t.prevTx, t.prevRx, t.prevAt = tx, rx, now
	t.rateMu.Unlock()
}

// Totals returns interface-wide counters.
func (t *Table) Totals() Totals {
	t.rateMu.Lock()
	txr, rxr := t.txRate, t.rxRate
	t.rateMu.Unlock()
	t.mu.Lock()
	n := len(t.flows)
	t.mu.Unlock()
	return Totals{
		TxPkts: t.txPkts.Load(), RxPkts: t.rxPkts.Load(),
		TxBytes: t.txBytes.Load(), RxBytes: t.rxBytes.Load(),
		TxRate: txr, RxRate: rxr,
		DropOut: t.dropOut.Load(), DropIn: t.dropIn.Load(),
		Malformed: t.malformed.Load(), Flows: n,
		ForeignOut: t.foreignOut.Load(), ForeignIn: t.foreignIn.Load(),
	}
}

// Flows returns up to limit flows, most recently active first.
func (t *Table) Flows(limit int) []FlowInfo {
	t.mu.Lock()
	out := make([]FlowInfo, 0, len(t.flows))
	for _, e := range t.flows {
		init := "out"
		if e.initiator == In {
			init = "in"
		}
		out = append(out, FlowInfo{
			Proto:     e.key.Proto,
			Local:     netip.AddrPortFrom(e.key.Local, e.key.LocalPort),
			Remote:    netip.AddrPortFrom(e.key.Remote, e.key.RemotePort),
			Initiator: init,
			State:     e.state(),
			First:     time.Unix(0, e.first),
			Last:      time.Unix(0, e.last),
			TxPkts:    e.txPkts, RxPkts: e.rxPkts,
			TxBytes: e.txBytes, RxBytes: e.rxBytes,
			TxRate: e.txRate, RxRate: e.rxRate,
			Dropped: e.dropped,
		})
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Remote.Compare(out[j].Remote) < 0
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Packets returns ring entries with a sequence number above after, oldest
// first, capped at limit.
func (t *Table) Packets(after uint64, limit int) []PacketInfo {
	if limit <= 0 || limit > ringSize {
		limit = ringSize
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if after > t.seq {
		after = 0 // the daemon restarted under a long-lived client
	}
	start := after + 1
	if t.seq >= ringSize && start < t.seq-ringSize+1 {
		start = t.seq - ringSize + 1
	}
	if start == 0 {
		start = 1
	}
	if t.seq >= start && t.seq-start+1 > uint64(limit) {
		start = t.seq - uint64(limit) + 1
	}
	out := make([]PacketInfo, 0, limit)
	for s := start; s <= t.seq; s++ {
		r := &t.ring[s%ringSize]
		pi := PacketInfo{
			Seq: r.seq, Time: time.Unix(0, r.ts), Dir: r.dir.String(), Verdict: "allow",
			Proto: r.p.Proto, Len: r.p.Len, TCPFlags: r.p.TCPFlags,
			ICMPType: r.p.ICMPType, ICMPCode: r.p.ICMPCode, Frag: r.p.Frag, Malformed: r.malformed,
		}
		if r.drop {
			pi.Verdict = "drop"
		}
		if r.p.Src.IsValid() {
			pi.Src = netip.AddrPortFrom(r.p.Src, r.p.SrcPort)
			pi.Dst = netip.AddrPortFrom(r.p.Dst, r.p.DstPort)
		}
		out = append(out, pi)
	}
	return out
}

// Subscribe starts a live capture. snaplen bounds the bytes copied per packet.
func (t *Table) Subscribe(snaplen, buffer int) (*Sub, error) {
	if snaplen <= 0 || snaplen > 65535 {
		snaplen = 65535
	}
	if buffer <= 0 {
		buffer = 1024
	}
	t.pmu.Lock()
	defer t.pmu.Unlock()
	var cur []*Sub
	if p := t.subs.Load(); p != nil {
		cur = *p
	}
	if len(cur) >= maxSubs {
		return nil, errors.New("too many capture sessions")
	}
	s := &Sub{C: make(chan CapPacket, buffer), snaplen: snaplen}
	next := append(append([]*Sub(nil), cur...), s)
	t.subs.Store(&next)
	return s, nil
}

// Unsubscribe stops a live capture.
func (t *Table) Unsubscribe(s *Sub) {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	p := t.subs.Load()
	if p == nil {
		return
	}
	var next []*Sub
	for _, x := range *p {
		if x != s {
			next = append(next, x)
		}
	}
	if len(next) == 0 {
		t.subs.Store(nil)
		return
	}
	t.subs.Store(&next)
}

// OnChange registers a callback invoked with the new policy after every
// policy change. It is called with the policy lock held, so changes are
// delivered in order; the callback must not call back into the Table.
func (t *Table) OnChange(fn func(Policy)) {
	t.pmu.Lock()
	t.onChange = fn
	t.pmu.Unlock()
}

func (t *Table) policyLocked() Policy {
	rs := t.rules.Load()
	p := Policy{Shields: t.shields.Load(), Rules: make([]Rule, 0, len(rs.rules))}
	for _, c := range rs.rules {
		r := c.rule
		r.Hits = c.hits.Load()
		p.Rules = append(p.Rules, r)
	}
	return p
}

func (t *Table) changedLocked() {
	if t.onChange != nil {
		t.onChange(t.policyLocked())
	}
}

// Policy returns the current filter state.
func (t *Table) Policy() Policy {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	return t.policyLocked()
}

// LoadPolicy replaces the filter state, for example from disk at startup.
// It does not invoke the OnChange callback.
func (t *Table) LoadPolicy(p Policy) error {
	if len(p.Rules) > MaxRules {
		return errors.New("too many rules")
	}
	rs := &ruleset{}
	seen := make(map[uint32]bool)
	var maxID uint32
	for _, r := range p.Rules {
		if r.ID == 0 || seen[r.ID] {
			return errors.New("policy: missing or duplicate rule id")
		}
		seen[r.ID] = true
		c, err := compile(r)
		if err != nil {
			return err
		}
		maxID = max(maxID, r.ID)
		rs.rules = append(rs.rules, c)
	}
	t.pmu.Lock()
	defer t.pmu.Unlock()
	t.rules.Store(rs)
	t.shields.Store(p.Shields)
	t.nextID = maxID + 1
	return nil
}

// AddRule appends a rule and returns it with its assigned ID.
func (t *Table) AddRule(r Rule) (Rule, error) {
	r.ID, r.Hits = 0, 0
	c, err := compile(r)
	if err != nil {
		return r, err
	}
	t.pmu.Lock()
	defer t.pmu.Unlock()
	cur := t.rules.Load()
	if len(cur.rules) >= MaxRules {
		return r, errors.New("rule table full")
	}
	for _, x := range cur.rules {
		a, b := x.rule, c.rule
		a.ID, a.Hits = 0, 0
		if a == b {
			return x.rule, nil // idempotent
		}
	}
	c.rule.ID = t.nextID
	t.nextID++
	next := &ruleset{rules: append(append([]*crule(nil), cur.rules...), c)}
	t.rules.Store(next)
	t.changedLocked()
	return c.rule, nil
}

// DelRule removes a rule by ID.
func (t *Table) DelRule(id uint32) bool {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	cur := t.rules.Load()
	next := &ruleset{}
	found := false
	for _, c := range cur.rules {
		if c.rule.ID == id {
			found = true
			continue
		}
		next.rules = append(next.rules, c)
	}
	if !found {
		return false
	}
	t.rules.Store(next)
	t.changedLocked()
	return true
}

// SetShields switches default-deny for unsolicited inbound traffic.
func (t *Table) SetShields(on bool) {
	t.pmu.Lock()
	defer t.pmu.Unlock()
	if t.shields.Swap(on) != on {
		t.changedLocked()
	}
}

// Shields reports whether shields mode is on.
func (t *Table) Shields() bool { return t.shields.Load() }
