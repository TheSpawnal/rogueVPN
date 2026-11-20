package tui

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/flow"
)

// Views.
const (
	viewPeers = iota
	viewFlows
	viewPackets
	viewRules
	numViews
)

var viewNames = [numViews]string{"Peers", "Flows", "Packets", "Rules"}

// ViewIndex maps a view name to its index.
func ViewIndex(name string) (int, bool) {
	for i, n := range viewNames {
		if strings.EqualFold(n, name) {
			return i, true
		}
	}
	return 0, false
}

type style uint8

const (
	stNormal style = iota
	stTitle
	stHeader
	stSelected
	stDim
	stWarn
	stBad
	stKeys
)

type line struct {
	text string
	st   style
}

var sortNames = []string{"rate", "bytes", "recent"}

const maxPackets = 2000

type peerSample struct {
	rx, tx uint64
	at     time.Time
}

type peerRate struct{ rx, tx float64 }

type model struct {
	snap     api.Snapshot
	have     bool
	err      error
	pkts     []flow.PacketInfo
	pktSeq   uint64
	view     int
	sel      [numViews]int
	top      [numViews]int
	follow   bool
	sortMode int
	paused   bool
	msg      string
	msgAt    time.Time

	prev  map[string]peerSample
	rates map[string]peerRate
	names map[netip.Addr]string
}

func newModel() *model {
	return &model{follow: true, prev: map[string]peerSample{}, rates: map[string]peerRate{}, names: map[netip.Addr]string{}}
}

func (m *model) setSnapshot(s api.Snapshot, now time.Time) {
	m.snap, m.have, m.err = s, true, nil
	m.names = map[netip.Addr]string{s.Status.IP: api.Printable(s.Status.Name)}
	seen := map[string]bool{}
	for _, p := range s.Peers {
		m.names[p.IP] = api.Printable(p.Name)
		seen[p.ID] = true
		if old, ok := m.prev[p.ID]; ok {
			if dt := now.Sub(old.at).Seconds(); dt > 0 && p.RxBytes >= old.rx && p.TxBytes >= old.tx {
				m.rates[p.ID] = peerRate{float64(p.RxBytes-old.rx) / dt, float64(p.TxBytes-old.tx) / dt}
			}
		}
		m.prev[p.ID] = peerSample{p.RxBytes, p.TxBytes, now}
	}
	for id := range m.prev {
		if !seen[id] {
			delete(m.prev, id)
			delete(m.rates, id)
		}
	}
	m.sortFlows()
}

func (m *model) addPackets(p []flow.PacketInfo) {
	if len(p) == 0 {
		return
	}
	if p[0].Seq <= m.pktSeq {
		m.pkts = m.pkts[:0] // the daemon restarted; sequence numbers start over
	}
	m.pkts = append(m.pkts, p...)
	if n := len(m.pkts) - maxPackets; n > 0 {
		m.pkts = append(m.pkts[:0], m.pkts[n:]...)
		m.sel[viewPackets] = max(0, m.sel[viewPackets]-n)
	}
	m.pktSeq = p[len(p)-1].Seq
}

func (m *model) sortFlows() {
	f := m.snap.Flows
	sort.SliceStable(f, func(i, j int) bool {
		switch m.sortMode {
		case 0:
			ri, rj := f[i].RxRate+f[i].TxRate, f[j].RxRate+f[j].TxRate
			if ri != rj {
				return ri > rj
			}
			fallthrough
		case 1:
			bi, bj := f[i].RxBytes+f[i].TxBytes, f[j].RxBytes+f[j].TxBytes
			if bi != bj {
				return bi > bj
			}
		}
		return f[i].Last.After(f[j].Last)
	})
}

func (m *model) rowCount() int {
	switch m.view {
	case viewPeers:
		return len(m.snap.Peers)
	case viewFlows:
		return len(m.snap.Flows)
	case viewPackets:
		return len(m.pkts)
	}
	return len(m.snap.Rules)
}

func (m *model) say(format string, a ...any) {
	m.msg, m.msgAt = api.Printable(fmt.Sprintf(format, a...)), time.Now()
}

// peerBlocked reports whether a blanket drop rule exists for the peer.
func (m *model) peerBlocked(ip netip.Addr) (uint32, bool) {
	want := netip.PrefixFrom(ip, ip.BitLen())
	for _, r := range m.snap.Rules {
		if r.Action == "drop" && r.Dir == "any" && r.Proto == "any" && r.Port == 0 && r.Remote == want {
			return r.ID, true
		}
	}
	return 0, false
}

func (m *model) peerName(a netip.Addr) string {
	if n, ok := m.names[a]; ok {
		return n
	}
	return "-"
}

var (
	peerCols   = []int{16, 15, 8, 26, -8, -9, -8, -8, -9, -9}
	flowCols   = []int{5, 24, 24, 14, 4, 7, -9, -9, -8, -8, -6, -5, -6}
	packetCols = []int{12, 3, 5, 5, 24, 24, -5, 0}
	ruleCols   = []int{-4, 6, 4, 5, 20, -6, -12}
)

func (m *model) header() string {
	switch m.view {
	case viewPeers:
		return cols(peerCols, "NAME", "MESH-IP", "PATH", "ENDPOINT", "RTT", "HANDSHAKE", "RX", "TX", "RX/s", "TX/s")
	case viewFlows:
		return cols(flowCols, "PROTO", "LOCAL", "REMOTE", "PEER", "INIT", "STATE", "RX/s", "TX/s", "RX", "TX", "AGE", "IDLE", "DROP")
	case viewPackets:
		return cols(packetCols, "TIME", "DIR", "VERD", "PROTO", "SOURCE", "DESTINATION", "LEN", "INFO")
	}
	return cols(ruleCols, "ID", "ACTION", "DIR", "PROTO", "REMOTE", "PORT", "HITS")
}

func (m *model) row(i int, now time.Time) line {
	switch m.view {
	case viewPeers:
		p := m.snap.Peers[i]
		path, st := api.Printable(p.Path), stNormal
		switch p.Path {
		case api.PathOffline:
			st = stDim
		case api.PathProbing:
			st = stWarn
		}
		if _, blocked := m.peerBlocked(p.IP); blocked {
			path, st = "blocked", stBad
		}
		ep, rtt := "-", "-"
		if p.Endpoint.IsValid() {
			ep = p.Endpoint.String()
		}
		if p.Path == api.PathDirect {
			rtt = strconv.FormatFloat(p.RTTMillis, 'f', 1, 64) + "ms"
		}
		r := m.rates[p.ID]
		return line{cols(peerCols, api.Printable(p.Name), p.IP.String(), path, ep, rtt,
			since(p.LastHandshake, now), humanBytes(p.RxBytes), humanBytes(p.TxBytes),
			humanRate(r.rx), humanRate(r.tx)), st}
	case viewFlows:
		f := m.snap.Flows[i]
		st := stNormal
		if f.Dropped > 0 {
			st = stWarn
		}
		return line{cols(flowCols, protoName(f.Proto), addrPort(f.Local, f.Proto), addrPort(f.Remote, f.Proto),
			m.peerName(f.Remote.Addr()), api.Printable(f.Initiator), api.Printable(f.State),
			humanRate(f.RxRate), humanRate(f.TxRate), humanBytes(f.RxBytes), humanBytes(f.TxBytes),
			since(f.First, now), since(f.Last, now), strconv.FormatUint(f.Dropped, 10)), st}
	case viewPackets:
		p := m.pkts[i]
		st := stNormal
		info := ""
		switch {
		case p.Malformed:
			info = "malformed"
		case p.Frag:
			info = "fragment"
		case p.Proto == flow.ProtoTCP:
			info = "[" + tcpFlags(p.TCPFlags) + "]"
		case p.Proto == flow.ProtoICMP || p.Proto == flow.ProtoICMPv6:
			info = fmt.Sprintf("type %d code %d", p.ICMPType, p.ICMPCode)
		}
		if p.Verdict == "drop" {
			st = stBad
		}
		return line{cols(packetCols, p.Time.Format("15:04:05.000"), api.Printable(p.Dir), api.Printable(p.Verdict),
			protoName(p.Proto), addrPort(p.Src, p.Proto), addrPort(p.Dst, p.Proto),
			strconv.Itoa(p.Len), info), st}
	}
	r := m.snap.Rules[i]
	remote, port := "any", "any"
	if r.Remote.IsValid() {
		remote = r.Remote.String()
	}
	if r.Port != 0 {
		port = strconv.Itoa(int(r.Port))
	}
	st := stNormal
	if r.Action == "drop" {
		st = stBad
	}
	return line{cols(ruleCols, strconv.FormatUint(uint64(r.ID), 10), api.Printable(r.Action), api.Printable(r.Dir),
		api.Printable(r.Proto), remote, port, strconv.FormatUint(r.Hits, 10)), st}
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "off"
}

// frame renders the whole screen as h lines.
func (m *model) frame(w, h int, now time.Time) []line {
	out := make([]line, 0, h)
	s := m.snap.Status
	if !m.have {
		msg := "connecting to daemon..."
		if m.err != nil {
			msg = api.Printable(m.err.Error())
		}
		out = append(out, line{" wyrm", stTitle}, line{" " + msg, stWarn})
	} else {
		direct := 0
		for _, p := range m.snap.Peers {
			if p.Path == api.PathDirect || p.Path == api.PathActive {
				direct++
			}
		}
		eps := make([]string, len(s.Endpoints))
		for i, e := range s.Endpoints {
			eps[i] = e.String()
		}
		if len(eps) == 0 {
			eps = []string{"none yet"}
		}
		t := s.Totals
		out = append(out,
			line{fmt.Sprintf(" wyrm %s | %s %s | %s/%d on %s:%d (%s) | coord %s | shields %s",
				api.Printable(s.Version), api.Printable(s.Name), api.Printable(s.NodeID), s.IP, s.CIDR.Bits(),
				api.Printable(s.Iface), s.ListenPort, api.Printable(s.Transport),
				api.Printable(s.CoordState), onOff(s.Shields)), stTitle},
			line{fmt.Sprintf(" peers %d/%d up | flows %d | rx %s tx %s | total rx %s tx %s | dropped in %d out %d bad %d foreign %d | up %s",
				direct, len(m.snap.Peers), t.Flows, humanRate(t.RxRate), humanRate(t.TxRate),
				humanBytes(t.RxBytes), humanBytes(t.TxBytes), t.DropIn, t.DropOut, t.Malformed, t.ForeignIn,
				since(s.Started, now)), stNormal},
			line{" endpoints " + strings.Join(eps, " "), stDim},
		)
		if m.err != nil {
			out[len(out)-1] = line{" " + api.Printable(m.err.Error()), stBad}
		}
	}

	var tabs strings.Builder
	for i, n := range viewNames {
		if i == m.view {
			fmt.Fprintf(&tabs, " [%d %s]", i+1, n)
		} else {
			fmt.Fprintf(&tabs, "  %d %s ", i+1, n)
		}
	}
	switch {
	case m.view == viewFlows:
		fmt.Fprintf(&tabs, "   sort: %s", sortNames[m.sortMode])
	case m.view == viewPackets && m.follow:
		tabs.WriteString("   following")
	}
	if m.paused {
		tabs.WriteString("   PAUSED")
	}
	out = append(out, line{tabs.String(), stNormal}, line{m.header(), stHeader})

	rows := h - len(out) - 2
	if rows < 1 {
		rows = 1
	}
	n := m.rowCount()
	sel := &m.sel[m.view]
	top := &m.top[m.view]
	if m.view == viewPackets && m.follow {
		*sel = n - 1
	}
	*sel = max(0, min(*sel, n-1))
	if *sel < *top {
		*top = *sel
	}
	if *sel >= *top+rows {
		*top = *sel - rows + 1
	}
	*top = max(0, min(*top, max(0, n-rows)))
	for i := *top; i < n && i < *top+rows; i++ {
		l := m.row(i, now)
		if i == *sel {
			l.st = stSelected
		}
		out = append(out, l)
	}
	for len(out) < h-2 {
		out = append(out, line{})
	}
	msg := ""
	if now.Sub(m.msgAt) < 5*time.Second {
		msg = " " + m.msg
	}
	keys := " 1-4 view  Up/Dn select  s sort  b block  u unblock  d delete rule  S shields  p pause  q quit"
	out = append(out, line{msg, stWarn}, line{keys, stKeys})
	return out
}
