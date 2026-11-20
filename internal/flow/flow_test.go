package flow

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	local  = netip.MustParseAddr("10.88.0.1")
	remote = netip.MustParseAddr("10.88.0.2")
)

func ipv4(proto uint8, src, dst netip.Addr, fragField uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:], fragField)
	b[8], b[9] = 64, proto
	copy(b[12:], src.AsSlice())
	copy(b[16:], dst.AsSlice())
	copy(b[20:], payload)
	return b
}

func tcp(sport, dport uint16, flags uint8) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12], b[13] = 5<<4, flags
	return b
}

func udp(sport, dport uint16, n int) []byte {
	b := make([]byte, 8+n)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	return b
}

func TestDecode(t *testing.T) {
	p, ok := Decode(ipv4(ProtoTCP, local, remote, 0, tcp(40000, 22, TCPSyn)))
	if !ok || p.Proto != ProtoTCP || p.Src != local || p.Dst != remote || p.SrcPort != 40000 || p.DstPort != 22 || p.TCPFlags != TCPSyn || p.Len != 40 {
		t.Fatalf("tcp: %+v %v", p, ok)
	}
	p, ok = Decode(ipv4(ProtoUDP, local, remote, 0, udp(5000, 53, 4)))
	if !ok || p.SrcPort != 5000 || p.DstPort != 53 {
		t.Fatalf("udp: %+v", p)
	}
	p, ok = Decode(ipv4(ProtoICMP, local, remote, 0, []byte{8, 0, 0, 0, 0, 0, 0, 0}))
	if !ok || p.ICMPType != 8 {
		t.Fatalf("icmp: %+v", p)
	}
	// Non-first fragment: accepted, no ports.
	p, ok = Decode(ipv4(ProtoUDP, local, remote, 185, []byte{1, 2, 3}))
	if !ok || !p.Frag || p.DstPort != 0 {
		t.Fatalf("fragment: %+v %v", p, ok)
	}
	// First fragment too short for its TCP header: rejected (tiny-fragment evasion).
	if _, ok := Decode(ipv4(ProtoTCP, local, remote, 0x2000, tcp(1, 22, TCPSyn)[:8])); ok {
		t.Fatal("tiny first fragment accepted")
	}
	for name, b := range map[string][]byte{
		"empty":       nil,
		"version":     {0x15, 0, 0, 0},
		"short v4":    ipv4(ProtoTCP, local, remote, 0, tcp(1, 2, 0))[:19],
		"bad ihl":     append([]byte{0x44}, make([]byte, 30)...),
		"len > buf":   func() []byte { b := ipv4(ProtoUDP, local, remote, 0, udp(1, 2, 0)); b[3] = 200; return b }(),
		"short udp":   ipv4(ProtoUDP, local, remote, 0, []byte{1, 2, 3}),
		"short v6":    append([]byte{0x60}, make([]byte, 38)...),
		"v6 len":      func() []byte { b := make([]byte, 40); b[0] = 0x60; b[5] = 9; b[6] = 17; return b }(),
		"v6 ext loop": v6ExtChain(9),
	} {
		if _, ok := Decode(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func ipv6(nh uint8, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6], b[7] = nh, 64
	b[23], b[39] = 1, 2
	copy(b[40:], payload)
	return b
}

func v6ExtChain(n int) []byte {
	var p []byte
	for i := 0; i < n; i++ {
		p = append(p, 60, 0, 0, 0, 0, 0, 0, 0)
	}
	return ipv6(60, append(p, udp(1, 2, 0)...))
}

func TestDecodeV6(t *testing.T) {
	p, ok := Decode(ipv6(ProtoTCP, tcp(1234, 443, TCPSyn|TCPAck)))
	if !ok || p.Proto != ProtoTCP || p.DstPort != 443 || !p.Src.Is6() {
		t.Fatalf("v6 tcp: %+v %v", p, ok)
	}
	// Destination-options header before UDP.
	ext := append([]byte{ProtoUDP, 0, 0, 0, 0, 0, 0, 0}, udp(7, 53, 0)...)
	p, ok = Decode(ipv6(60, ext))
	if !ok || p.Proto != ProtoUDP || p.DstPort != 53 {
		t.Fatalf("v6 ext: %+v %v", p, ok)
	}
	// Fragment header with non-zero offset.
	frag := []byte{ProtoUDP, 0, 0, 8, 0, 0, 0, 1, 9, 9}
	p, ok = Decode(ipv6(44, frag))
	if !ok || !p.Frag || p.Proto != ProtoUDP {
		t.Fatalf("v6 frag: %+v %v", p, ok)
	}
	p, ok = Decode(ipv6(ProtoICMPv6, []byte{128, 0, 0, 0}))
	if !ok || p.ICMPType != 128 {
		t.Fatalf("icmp6: %+v", p)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(ipv4(ProtoTCP, local, remote, 0, tcp(1, 2, TCPSyn)))
	f.Add(ipv6(60, append([]byte{ProtoUDP, 0, 0, 0, 0, 0, 0, 0}, udp(7, 53, 0)...)))
	f.Add(ipv6(44, []byte{ProtoUDP, 0, 0, 8, 0, 0, 0, 1, 9, 9}))
	tb := NewTable()
	tb.SetShields(true)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, ok := Decode(b)
		if ok && (p.Len > len(b) || !p.Src.IsValid() || !p.Dst.IsValid()) {
			t.Fatalf("inconsistent decode: %+v", p)
		}
		tb.Process(In, b)
		tb.Process(Out, b)
	})
}

func mustRule(t *testing.T, tb *Table, f ...string) Rule {
	t.Helper()
	r, err := ParseRule(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err = tb.AddRule(r)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRules(t *testing.T) {
	tb := NewTable()
	inSSH := ipv4(ProtoTCP, remote, local, 0, tcp(50000, 22, TCPSyn))
	inWeb := ipv4(ProtoTCP, remote, local, 0, tcp(50001, 80, TCPSyn))
	outSSH := ipv4(ProtoTCP, local, remote, 0, tcp(50002, 22, TCPSyn))
	if !tb.Process(In, inSSH) {
		t.Fatal("default policy must allow")
	}
	r := mustRule(t, tb, "drop", "in", "tcp", "10.88.0.2", "22")
	if tb.Process(In, inSSH) {
		t.Fatal("drop rule ignored")
	}
	if !tb.Process(In, inWeb) || !tb.Process(Out, outSSH) {
		t.Fatal("rule matched too much")
	}
	// Adding the same rule twice is idempotent.
	if again := mustRule(t, tb, "drop", "in", "tcp", "10.88.0.2/32", "22"); again.ID != r.ID {
		t.Fatalf("duplicate rule created: %d vs %d", again.ID, r.ID)
	}
	if got := tb.Policy().Rules; len(got) != 1 || got[0].Hits != 1 {
		t.Fatalf("policy: %+v", got)
	}
	// First match wins: an earlier allow shadows a later drop.
	tb2 := NewTable()
	mustRule(t, tb2, "allow", "in", "tcp", "any", "22")
	mustRule(t, tb2, "drop", "any", "any", "10.88.0.2", "any")
	if !tb2.Process(In, inSSH) || tb2.Process(In, inWeb) || tb2.Process(Out, outSSH) {
		t.Fatal("rule order not respected")
	}
	if !tb.DelRule(r.ID) || tb.DelRule(r.ID) || !tb.Process(In, inSSH) {
		t.Fatal("delete")
	}
	for _, bad := range [][]string{
		{"deny", "in", "tcp", "any", "22"},
		{"drop", "in", "icmp", "any", "22"},
		{"drop", "in", "tcp", "nope", "22"},
		{"drop", "in", "tcp", "any", "0"},
		{"drop", "in", "tcp", "any", "70000"},
		{"drop", "in", "tcp", "any"},
	} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestShields(t *testing.T) {
	tb := NewTable()
	tb.SetShields(true)
	syn := ipv4(ProtoTCP, remote, local, 0, tcp(50000, 22, TCPSyn))
	if tb.Process(In, syn) {
		t.Fatal("unsolicited inbound passed shields")
	}
	// A flow opened locally lets its replies in, and only those.
	if !tb.Process(Out, ipv4(ProtoTCP, local, remote, 0, tcp(40000, 443, TCPSyn))) {
		t.Fatal("outbound blocked")
	}
	if !tb.Process(In, ipv4(ProtoTCP, remote, local, 0, tcp(443, 40000, TCPSyn|TCPAck))) {
		t.Fatal("reply blocked")
	}
	if tb.Process(In, ipv4(ProtoTCP, remote, local, 0, tcp(443, 40001, TCPSyn|TCPAck))) {
		t.Fatal("reply to a port we never used passed")
	}
	other := netip.MustParseAddr("10.88.0.3")
	if tb.Process(In, ipv4(ProtoTCP, other, local, 0, tcp(443, 40000, TCPSyn|TCPAck))) {
		t.Fatal("reply from a host we never contacted passed")
	}
	// Trailing fragments only between hosts with a locally opened flow.
	if !tb.Process(In, ipv4(ProtoTCP, remote, local, 100, []byte{1, 2, 3})) {
		t.Fatal("related fragment blocked")
	}
	if tb.Process(In, ipv4(ProtoTCP, other, local, 100, []byte{1, 2, 3})) {
		t.Fatal("unrelated fragment passed")
	}
	// ICMP errors pass, echo requests do not.
	if !tb.Process(In, ipv4(ProtoICMP, other, local, 0, []byte{3, 1, 0, 0})) {
		t.Fatal("icmp error blocked")
	}
	if tb.Process(In, ipv4(ProtoICMP, other, local, 0, []byte{8, 0, 0, 0})) {
		t.Fatal("echo request passed")
	}
	// An explicit allow rule opens a port through shields.
	mustRule(t, tb, "allow", "in", "tcp", "any", "22")
	if !tb.Process(In, syn) {
		t.Fatal("allow rule did not open the port")
	}
	tot := tb.Totals()
	if tot.DropIn != 5 || tot.DropOut != 0 {
		t.Fatalf("drop counters: %+v", tot)
	}
}

func TestTableBookkeeping(t *testing.T) {
	tb := NewTable()
	tb.max = 4
	for i := 0; i < 20; i++ {
		tb.Process(Out, ipv4(ProtoUDP, local, remote, 0, udp(uint16(1000+i), 53, 0)))
	}
	if n := tb.Totals().Flows; n != 4 {
		t.Fatalf("flow cap not enforced: %d", n)
	}
	// Remote traffic must not evict local state when the table is full.
	before := tb.Flows(0)
	for i := 0; i < 20; i++ {
		tb.Process(In, ipv4(ProtoUDP, remote, local, 0, udp(uint16(2000+i), 9999, 0)))
	}
	after := tb.Flows(0)
	if len(after) != 4 {
		t.Fatalf("flows: %d", len(after))
	}
	for _, f := range after {
		if f.Initiator != "out" {
			t.Fatalf("inbound flow evicted a local one: %+v (before %d)", f, len(before))
		}
	}
	if len(tb.pairs) != 1 || tb.pairs[pairKey{ProtoUDP, local, remote}] != 4 {
		t.Fatalf("pair refcount: %v", tb.pairs)
	}
	// Ring: sequence numbers are contiguous and resumable.
	all := tb.Packets(0, 0)
	if len(all) != 40 || all[0].Seq != 1 || all[39].Seq != 40 {
		t.Fatalf("ring: %d", len(all))
	}
	if tail := tb.Packets(38, 0); len(tail) != 2 || tail[0].Seq != 39 {
		t.Fatalf("ring resume: %+v", tail)
	}
	if got := tb.Packets(1<<40, 5); len(got) != 5 || got[4].Seq != 40 {
		t.Fatalf("ring resync after restart: %+v", got)
	}
	for i := 0; i < ringSize+10; i++ {
		tb.Process(Out, ipv4(ProtoUDP, local, remote, 0, udp(1000, 53, 0)))
	}
	if all = tb.Packets(0, 0); len(all) != ringSize || all[len(all)-1].Seq != uint64(40+ringSize+10) {
		t.Fatalf("ring wrap: %d", len(all))
	}
}

func TestPolicyPersistence(t *testing.T) {
	tb := NewTable()
	var saved Policy
	tb.OnChange(func(p Policy) { saved = p })
	mustRule(t, tb, "drop", "in", "udp", "10.88.0.0/24", "53")
	tb.SetShields(true)
	if !saved.Shields || len(saved.Rules) != 1 {
		t.Fatalf("callback: %+v", saved)
	}
	tb2 := NewTable()
	if err := tb2.LoadPolicy(saved); err != nil {
		t.Fatal(err)
	}
	if !tb2.Shields() || tb2.Process(In, ipv4(ProtoUDP, netip.MustParseAddr("10.88.0.9"), local, 0, udp(1, 53, 0))) {
		t.Fatal("policy not restored")
	}
	if r := mustRule(t, tb2, "drop", "out", "tcp", "any", "25"); r.ID != 2 {
		t.Fatalf("rule id reused: %d", r.ID)
	}
	if err := tb2.LoadPolicy(Policy{Rules: []Rule{{ID: 1, Action: "drop"}, {ID: 1, Action: "drop"}}}); err == nil {
		t.Fatal("duplicate ids accepted")
	}
}

func TestCapture(t *testing.T) {
	tb := NewTable()
	sub, err := tb.Subscribe(24, 2)
	if err != nil {
		t.Fatal(err)
	}
	pkt := ipv4(ProtoUDP, local, remote, 0, udp(1, 2, 100))
	for i := 0; i < 3; i++ {
		tb.Process(Out, pkt)
	}
	if sub.Dropped() != 1 {
		t.Fatalf("slow subscriber accounting: %d", sub.Dropped())
	}
	got := <-sub.C
	if len(got.Data) != 24 || got.Orig != len(pkt) || !bytes.Equal(got.Data, pkt[:24]) {
		t.Fatalf("snaplen: %d/%d", len(got.Data), got.Orig)
	}
	var buf bytes.Buffer
	if err := WritePcapHeader(&buf, 24); err != nil {
		t.Fatal(err)
	}
	if err := WritePcapRecord(&buf, got); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) != 24+16+24 || binary.LittleEndian.Uint32(b) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(b[20:]) != 101 ||
		binary.LittleEndian.Uint32(b[32:]) != 24 || binary.LittleEndian.Uint32(b[36:]) != uint32(len(pkt)) {
		t.Fatalf("pcap framing: % x", b[:40])
	}
	tb.Unsubscribe(sub)
	for i := 0; i < maxSubs; i++ {
		if _, err := tb.Subscribe(0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tb.Subscribe(0, 0); err == nil {
		t.Fatal("subscriber cap not enforced")
	}
}

func TestMeshOnly(t *testing.T) {
	tb := NewTable()
	tb.SetLocal(local, netip.MustParsePrefix("10.88.0.0/16"))
	lan := netip.MustParseAddr("192.168.1.10")
	if !tb.Process(In, ipv4(ProtoUDP, remote, local, 0, udp(1, 2, 0))) ||
		!tb.Process(Out, ipv4(ProtoUDP, local, remote, 0, udp(2, 1, 0))) {
		t.Fatal("mesh traffic blocked")
	}
	for name, c := range map[string]struct {
		dir Dir
		pkt []byte
	}{
		"peer aims at this host's LAN":   {In, ipv4(ProtoUDP, remote, lan, 0, udp(1, 2, 0))},
		"peer aims at another mesh node": {In, ipv4(ProtoUDP, remote, netip.MustParseAddr("10.88.0.9"), 0, udp(1, 2, 0))},
		"inbound source outside mesh":    {In, ipv4(ProtoUDP, lan, local, 0, udp(1, 2, 0))},
		"host routes LAN source out":     {Out, ipv4(ProtoUDP, lan, remote, 0, udp(1, 2, 0))},
		"host sends to non-mesh address": {Out, ipv4(ProtoUDP, local, lan, 0, udp(1, 2, 0))},
		"host IPv6 autoconfiguration":    {Out, ipv6(ProtoICMPv6, []byte{133, 0, 0, 0})},
	} {
		if tb.Process(c.dir, c.pkt) {
			t.Errorf("%s: passed", name)
		}
	}
	// An allow rule must not reopen what the confinement closed.
	mustRule(t, tb, "allow", "any", "any", "any", "any")
	if tb.Process(In, ipv4(ProtoUDP, remote, lan, 0, udp(1, 2, 0))) {
		t.Fatal("allow rule overrode mesh confinement")
	}
	tot := tb.Totals()
	if tot.ForeignIn != 4 || tot.ForeignOut != 3 || tot.Flows != 1 || tot.DropIn != 0 {
		t.Fatalf("totals: %+v", tot)
	}
	if n := len(tb.Packets(0, 0)); n != 6 {
		t.Fatalf("ring holds %d entries, want 2 mesh + 4 foreign inbound", n)
	}
}
