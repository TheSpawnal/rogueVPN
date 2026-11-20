package stun

import (
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.7:40112", "[2001:db8::1]:51820"} {
		want := netip.MustParseAddrPort(s)
		tx, req, err := NewRequest()
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ParseRequest(req)
		if !ok || got != tx {
			t.Fatalf("request not parsed")
		}
		resp := Response(tx, want)
		if !IsResponse(resp) || IsResponse(req) {
			t.Fatalf("classification wrong")
		}
		rtx, addr, err := ParseResponse(resp)
		if err != nil || rtx != tx || addr != want {
			t.Fatalf("got %v %v, want %v", addr, err, want)
		}
	}
}

func TestRejects(t *testing.T) {
	tx, req, _ := NewRequest()
	resp := Response(tx, netip.MustParseAddrPort("192.0.2.1:1"))
	// WireGuard handshake initiation: type 1, three reserved zero bytes.
	wgInit := make([]byte, 148)
	wgInit[0] = 1
	copy(wgInit[4:], []byte{0x21, 0x12, 0xA4, 0x42}) // sender index equal to the STUN cookie
	for name, b := range map[string][]byte{
		"empty":     nil,
		"short":     resp[:19],
		"truncated": resp[:len(resp)-1],
		"wireguard": wgInit,
		"request":   req,
	} {
		if IsResponse(b) {
			t.Errorf("%s accepted as response", name)
		}
	}
	bad := append([]byte(nil), resp...)
	bad[23] = 200 // attribute length beyond packet
	if _, _, err := ParseResponse(bad); err == nil {
		t.Error("oversized attribute accepted")
	}
}

func FuzzParseResponse(f *testing.F) {
	tx, _, _ := NewRequest()
	f.Add(Response(tx, netip.MustParseAddrPort("192.0.2.1:1")))
	f.Add(Response(tx, netip.MustParseAddrPort("[2001:db8::1]:2")))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseResponse(b)
		ParseRequest(b)
	})
}
