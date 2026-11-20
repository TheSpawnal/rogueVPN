// Package disco implements the authenticated path-discovery messages that
// share the WireGuard UDP socket. Two nodes use them to punch through NATs
// and to measure which candidate endpoint works best.
//
// Wire format:
//
//	magic[6] | sender disco public key[32] | nonce[24] | NaCl box(sender key[32] | payload)
//
// The box is sealed with the X25519 shared secret of the two nodes' disco
// keys, so only a node whose disco key was distributed by the coordination
// server can produce a packet that opens. The shared secret is symmetric,
// so the sender key is repeated inside the box: a packet reflected back to
// its author, or relabelled with another sender, does not authenticate.
package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"wyrm/internal/keys"
)

const (
	magicLen  = 6
	nonceLen  = 24
	headerLen = magicLen + keys.Size + nonceLen

	// MaxPacket bounds what the receiver will even look at.
	MaxPacket = 256

	version = 1

	// Message types.
	TypePing = 1
	TypePong = 2

	pingLen = 2 + 12
	pongLen = 2 + 12 + 18
)

var magic = [magicLen]byte{'W', 'Y', 'R', 'M', 0xD1, 0x5C}

// TxID correlates a pong with its ping.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() (TxID, error) {
	var t TxID
	_, err := rand.Read(t[:])
	return t, err
}

// LooksLike reports whether b carries the disco magic. The first magic byte
// is outside the WireGuard message-type range, so the two never collide.
func LooksLike(b []byte) bool {
	return len(b) >= headerLen+box.Overhead+keys.Size+pingLen && len(b) <= MaxPacket &&
		[magicLen]byte(b[:magicLen]) == magic
}

// Sender returns the claimed sender key. The claim is only proven once Open
// succeeds with the shared secret derived from that key.
func Sender(b []byte) keys.Public {
	return keys.Public(b[magicLen : magicLen+keys.Size])
}

// Shared derives the precomputed box key between a local disco private key
// and a peer disco public key. Low-order peer keys are rejected.
func Shared(priv keys.Private, peer keys.Public) (*[32]byte, error) {
	if _, err := curve25519.X25519(priv[:], peer[:]); err != nil {
		return nil, errors.New("disco: invalid peer key")
	}
	var out [32]byte
	p, k := [32]byte(peer), [32]byte(priv)
	box.Precompute(&out, &p, &k)
	return &out, nil
}

// Seal builds a disco packet around payload.
func Seal(self keys.Public, shared *[32]byte, payload []byte) ([]byte, error) {
	payload = append(self[:], payload...)
	out := make([]byte, headerLen, headerLen+len(payload)+box.Overhead)
	copy(out, magic[:])
	copy(out[magicLen:], self[:])
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(out[magicLen+keys.Size:], nonce[:])
	return box.SealAfterPrecomputation(out, payload, &nonce, shared), nil
}

// Open authenticates and decrypts a disco packet that must come from peer,
// using the shared secret derived from peer's key.
func Open(b []byte, peer keys.Public, shared *[32]byte) ([]byte, bool) {
	if !LooksLike(b) || Sender(b) != peer {
		return nil, false
	}
	nonce := [nonceLen]byte(b[magicLen+keys.Size : headerLen])
	plain, ok := box.OpenAfterPrecomputation(nil, b[headerLen:], &nonce, shared)
	if !ok || len(plain) < keys.Size || keys.Public(plain[:keys.Size]) != peer {
		return nil, false
	}
	return plain[keys.Size:], true
}

// Ping builds a ping payload.
func Ping(tx TxID) []byte {
	p := make([]byte, pingLen)
	p[0], p[1] = TypePing, version
	copy(p[2:], tx[:])
	return p
}

// Pong builds a pong payload echoing tx and reporting the address the ping
// arrived from.
func Pong(tx TxID, src netip.AddrPort) []byte {
	p := make([]byte, pongLen)
	p[0], p[1] = TypePong, version
	copy(p[2:], tx[:])
	a := src.Addr().As16()
	copy(p[14:], a[:])
	binary.BigEndian.PutUint16(p[30:], src.Port())
	return p
}

// Parse decodes a payload returned by Open.
func Parse(p []byte) (typ byte, tx TxID, src netip.AddrPort, ok bool) {
	if len(p) < pingLen || p[1] != version {
		return 0, tx, src, false
	}
	copy(tx[:], p[2:14])
	switch p[0] {
	case TypePing:
		return TypePing, tx, src, len(p) == pingLen
	case TypePong:
		if len(p) != pongLen {
			return 0, tx, src, false
		}
		ip := netip.AddrFrom16([16]byte(p[14:30])).Unmap()
		return TypePong, tx, netip.AddrPortFrom(ip, binary.BigEndian.Uint16(p[30:])), true
	}
	return 0, tx, src, false
}
