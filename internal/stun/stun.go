// Package stun implements the minimal subset of RFC 8489 needed to learn a
// socket's server-reflexive address: Binding requests without attributes and
// Binding success responses carrying XOR-MAPPED-ADDRESS.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	headerLen      = 20
	magicCookie    = 0x2112A442
	bindingRequest = 0x0001
	bindingSuccess = 0x0101
	attrXorMapped  = 0x0020
	maxPacket      = 576
)

// TxID is a STUN transaction identifier.
type TxID [12]byte

var (
	errShort  = errors.New("stun: malformed packet")
	errNoAddr = errors.New("stun: no XOR-MAPPED-ADDRESS")
)

// NewRequest builds a Binding request with a random transaction ID.
func NewRequest() (TxID, []byte, error) {
	var tx TxID
	if _, err := rand.Read(tx[:]); err != nil {
		return tx, nil, err
	}
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:], bindingRequest)
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tx[:])
	return tx, b, nil
}

func header(b []byte, typ uint16) (TxID, bool) {
	var tx TxID
	if len(b) < headerLen || len(b) > maxPacket {
		return tx, false
	}
	if binary.BigEndian.Uint16(b[0:]) != typ || binary.BigEndian.Uint32(b[4:]) != magicCookie {
		return tx, false
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n != len(b)-headerLen || n%4 != 0 {
		return tx, false
	}
	copy(tx[:], b[8:20])
	return tx, true
}

// IsResponse reports whether b is a well-framed Binding success response.
// It is used to demultiplex STUN from WireGuard on a shared socket; a
// WireGuard message can never match because its second byte is always zero.
func IsResponse(b []byte) bool {
	_, ok := header(b, bindingSuccess)
	return ok
}

// ParseRequest validates a Binding request and returns its transaction ID.
func ParseRequest(b []byte) (TxID, bool) {
	return header(b, bindingRequest)
}

// Response builds a Binding success response reporting addr.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	alen := 4
	fam := byte(0x01)
	if ip.Is6() {
		alen = 16
		fam = 0x02
	}
	b := make([]byte, headerLen+4+4+alen)
	binary.BigEndian.PutUint16(b[0:], bindingSuccess)
	binary.BigEndian.PutUint16(b[2:], uint16(4+4+alen))
	binary.BigEndian.PutUint32(b[4:], magicCookie)
	copy(b[8:], tx[:])
	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:], attrXorMapped)
	binary.BigEndian.PutUint16(a[2:], uint16(4+alen))
	a[5] = fam
	binary.BigEndian.PutUint16(a[6:], addr.Port()^uint16(magicCookie>>16))
	raw := ip.AsSlice()
	for i := range raw {
		a[8+i] = raw[i] ^ b[4+i] // cookie followed by transaction ID
	}
	return b
}

// ParseResponse extracts the reflexive address from a Binding success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	tx, ok := header(b, bindingSuccess)
	if !ok {
		return tx, netip.AddrPort{}, errShort
	}
	attrs := b[headerLen:]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		n := int(binary.BigEndian.Uint16(attrs[2:]))
		padded := (n + 3) &^ 3
		if padded > len(attrs)-4 {
			return tx, netip.AddrPort{}, errShort
		}
		v := attrs[4 : 4+n]
		attrs = attrs[4+padded:]
		if typ != attrXorMapped {
			continue
		}
		if len(v) < 4 {
			return tx, netip.AddrPort{}, errShort
		}
		port := binary.BigEndian.Uint16(v[2:]) ^ uint16(magicCookie>>16)
		var alen int
		switch v[1] {
		case 0x01:
			alen = 4
		case 0x02:
			alen = 16
		default:
			return tx, netip.AddrPort{}, errShort
		}
		if len(v) != 4+alen {
			return tx, netip.AddrPort{}, errShort
		}
		raw := make([]byte, alen)
		for i := range raw {
			raw[i] = v[4+i] ^ b[4+i]
		}
		ip, _ := netip.AddrFromSlice(raw)
		return tx, netip.AddrPortFrom(ip, port), nil
	}
	return tx, netip.AddrPort{}, errNoAddr
}
