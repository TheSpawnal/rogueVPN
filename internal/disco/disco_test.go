package disco

import (
	"net/netip"
	"testing"

	"wyrm/internal/keys"
)

func pair(t *testing.T) (keys.Private, keys.Private) {
	a, err := keys.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := keys.NewPrivate()
	return a, b
}

func TestPingPong(t *testing.T) {
	a, b := pair(t)
	ab, err := Shared(a, b.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, _ := Shared(b, a.Public())
	if *ab != *ba {
		t.Fatal("shared keys differ")
	}
	tx, _ := NewTxID()
	pkt, err := Seal(a.Public(), ab, Ping(tx))
	if err != nil {
		t.Fatal(err)
	}
	if !LooksLike(pkt) || Sender(pkt) != a.Public() {
		t.Fatal("framing")
	}
	payload, ok := Open(pkt, a.Public(), ba)
	typ, gtx, _, pok := Parse(payload)
	if !ok || !pok || typ != TypePing || gtx != tx {
		t.Fatal("ping did not survive")
	}
	src := netip.MustParseAddrPort("198.51.100.9:4242")
	pkt, _ = Seal(b.Public(), ba, Pong(tx, src))
	payload, ok = Open(pkt, b.Public(), ab)
	typ, gtx, gsrc, pok := Parse(payload)
	if !ok || !pok || typ != TypePong || gtx != tx || gsrc != src {
		t.Fatalf("pong did not survive: %v", gsrc)
	}
}

func TestRejects(t *testing.T) {
	a, b := pair(t)
	c, _ := keys.NewPrivate()
	ab, _ := Shared(a, b.Public())
	cb, _ := Shared(c, b.Public())
	tx, _ := NewTxID()
	pkt, _ := Seal(a.Public(), ab, Ping(tx))

	if _, ok := Open(pkt, a.Public(), cb); ok {
		t.Error("opened with the wrong key")
	}
	// Reflection: A's own packet returned to A, relabelled as coming from B.
	// The shared secret is the same in both directions, so only the sender
	// key inside the box stops this.
	refl := append([]byte(nil), pkt...)
	bp := b.Public()
	copy(refl[6:], bp[:])
	if _, ok := Open(refl, b.Public(), ab); ok {
		t.Error("reflected packet accepted")
	}
	for i := range pkt {
		bad := append([]byte(nil), pkt...)
		bad[i] ^= 1
		if _, ok := Open(bad, a.Public(), ab); ok {
			t.Errorf("tampered byte %d accepted", i)
		}
	}
	// Forged sender: C claims to be A.
	forged, _ := Seal(a.Public(), cb, Ping(tx))
	if _, ok := Open(forged, a.Public(), ab); ok {
		t.Error("forged sender accepted")
	}
	// No WireGuard message type can look like disco.
	for typ := byte(1); typ <= 4; typ++ {
		wg := make([]byte, 148)
		wg[0] = typ
		if LooksLike(wg) {
			t.Errorf("wireguard type %d classified as disco", typ)
		}
	}
	if _, err := Shared(a, keys.Public{}); err == nil {
		t.Error("low-order peer key accepted")
	}
	if _, _, _, ok := Parse([]byte{TypePing, 9, 0}); ok {
		t.Error("short payload accepted")
	}
}

func FuzzOpen(f *testing.F) {
	a, _ := keys.NewPrivate()
	b, _ := keys.NewPrivate()
	ab, _ := Shared(a, b.Public())
	tx, _ := NewTxID()
	pkt, _ := Seal(a.Public(), ab, Ping(tx))
	f.Add(pkt)
	f.Fuzz(func(t *testing.T, in []byte) {
		if LooksLike(in) {
			Sender(in)
		}
		if p, ok := Open(in, a.Public(), ab); ok {
			Parse(p)
		}
		Parse(in)
	})
}
