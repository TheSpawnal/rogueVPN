package tui

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/flow"
)

func TestParseKeys(t *testing.T) {
	got := parseKeys([]byte("\x1b[A\x1b[B\x1b[5~\x1b[6~\x1b[H\x1b[F\x1b[3~\tq2\x03\x1b[99;5u\x1b"))
	want := []key{keyUp, keyDown, keyPgUp, keyPgDn, keyHome, keyEnd, keyDelete, keyTab, keyChar + 'q', keyChar + '2', keyQuit}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d: %v want %v", i, got[i], want[i])
		}
	}
	if k := parseKeys([]byte("\x1b[")); len(k) != 0 {
		t.Fatalf("truncated sequence produced keys: %v", k)
	}
}

func sample() api.Snapshot {
	ip := netip.MustParseAddr
	return api.Snapshot{
		Status: api.Status{Version: "t", Name: "alpha", NodeID: "n1", IP: ip("10.88.0.1"),
			CIDR: netip.MustParsePrefix("10.88.0.0/16"), Iface: "wyrm0", ListenPort: 51820,
			Transport: "wireguard", CoordState: "synced", Started: time.Now().Add(-time.Hour)},
		Peers: []api.Peer{
			{ID: "n2", Name: "beta\x1b[2J\x07", IP: ip("10.88.0.2"), Path: api.PathDirect, RTTMillis: 1.5,
				Endpoint: netip.MustParseAddrPort("203.0.113.2:40002"), RxBytes: 5 << 20, TxBytes: 1 << 10},
			{ID: "n3", Name: "gamma", IP: ip("10.88.0.3"), Path: api.PathOffline},
		},
		Flows: []flow.FlowInfo{
			{Proto: 6, Local: netip.MustParseAddrPort("10.88.0.1:40000"), Remote: netip.MustParseAddrPort("10.88.0.2:443"),
				Initiator: "out", State: "est", RxBytes: 100, TxBytes: 50, RxRate: 10},
			{Proto: 17, Local: netip.MustParseAddrPort("10.88.0.1:53"), Remote: netip.MustParseAddrPort("10.88.0.3:5353"),
				Initiator: "in", State: "-", RxBytes: 9000, TxBytes: 9000, RxRate: 900},
		},
		Rules: []flow.Rule{{ID: 7, Action: "drop", Dir: "any", Proto: "any", Remote: netip.MustParsePrefix("10.88.0.3/32")}},
	}
}

func TestFrame(t *testing.T) {
	m := newModel()
	now := time.Now()
	m.setSnapshot(sample(), now)
	m.addPackets([]flow.PacketInfo{{Seq: 1, Time: now, Dir: "in", Verdict: "drop", Proto: 6,
		Src: netip.MustParseAddrPort("10.88.0.2:5"), Dst: netip.MustParseAddrPort("10.88.0.1:22"), Len: 60, TCPFlags: flow.TCPSyn}})
	for v := 0; v < numViews; v++ {
		m.view = v
		for _, size := range [][2]int{{160, 40}, {20, 8}, {1, 1}} {
			lines := m.frame(size[0], size[1], now)
			var buf bytes.Buffer
			paint(&buf, lines, size[0], true)
			for _, l := range lines {
				for i := 0; i < len(l.text); i++ {
					if c := l.text[i]; c < 0x20 || c > 0x7e {
						t.Fatalf("view %d: control byte %#x reached the screen: %q", v, c, l.text)
					}
				}
			}
		}
	}
	m.view = viewPeers
	text := ""
	for _, l := range m.frame(160, 30, now) {
		text += l.text + "\n"
	}
	for _, want := range []string{"beta?[2J?", "direct", "1.5ms", "blocked", "5.0M", "shields off", "coord synced"} {
		if !strings.Contains(text, want) {
			t.Errorf("peers view lacks %q:\n%s", want, text)
		}
	}
	// Flows sort by rate first.
	if m.snap.Flows[0].Proto != 17 {
		t.Error("flows not sorted by rate")
	}
}

func TestBlockRule(t *testing.T) {
	m := newModel()
	m.setSnapshot(sample(), time.Now())
	m.view = viewPeers
	r, ok := m.blockRule()
	if !ok || r.Remote.String() != "10.88.0.2/32" || r.Dir != "any" || r.Proto != "any" || r.Port != 0 {
		t.Fatalf("peer rule: %+v", r)
	}
	m.view = viewFlows // sorted: udp inbound flow first
	r, ok = m.blockRule()
	if !ok || r.Dir != "in" || r.Proto != "udp" || r.Port != 53 || r.Remote.String() != "10.88.0.3/32" {
		t.Fatalf("inbound flow rule: %+v", r)
	}
	m.sel[viewFlows] = 1
	r, _ = m.blockRule()
	if r.Dir != "out" || r.Proto != "tcp" || r.Port != 443 {
		t.Fatalf("outbound flow rule: %+v", r)
	}
	if _, err := flow.NewTable().AddRule(r); err != nil {
		t.Fatalf("generated rule rejected: %v", err)
	}
	if id, ok := m.peerBlocked(netip.MustParseAddr("10.88.0.3")); !ok || id != 7 {
		t.Fatal("blocked peer not recognised")
	}
}

func TestFormat(t *testing.T) {
	for in, want := range map[uint64]string{0: "0B", 1023: "1023B", 1024: "1.0K", 1536: "1.5K", 150 << 20: "150M", 3 << 30: "3.0G"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := cols([]int{4, -4, 0}, "abcdefgh", "12345", "tail"); got != "abc~ 123~ tail" {
		t.Errorf("cols: %q", got)
	}
}
