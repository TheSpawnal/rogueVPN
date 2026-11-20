// Package flow is the traffic inspection and control layer. It sits between
// the TUN device and the tunnel transport, where every packet is plaintext
// IP, and provides flow accounting, a recent-packet ring, live capture and a
// small stateful packet filter.
package flow

import (
	"encoding/binary"
	"net/netip"
)

// Dir is the direction of a packet relative to this host.
type Dir uint8

const (
	// Out is host to mesh.
	Out Dir = iota
	// In is mesh to host.
	In
)

func (d Dir) String() string {
	if d == Out {
		return "out"
	}
	return "in"
}

// IP protocol numbers the decoder understands.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// TCP flag bits.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPAck = 0x10
)

// Packet is the decoded summary of one IP packet.
type Packet struct {
	Proto    uint8
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	ICMPType uint8
	ICMPCode uint8
	Len      int
	// Frag marks a non-first fragment, which carries no transport header.
	Frag bool
}

// Decode parses the IP and transport headers of b. It returns false for
// anything that is not a well-formed IPv4 or IPv6 packet, including first
// fragments too short to hold their transport header; such packets are
// dropped by the filter.
func Decode(b []byte) (Packet, bool) {
	if len(b) == 0 {
		return Packet{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return decode4(b)
	case 6:
		return decode6(b)
	}
	return Packet{}, false
}

func decode4(b []byte) (Packet, bool) {
	var p Packet
	if len(b) < 20 {
		return p, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || total < ihl || total > len(b) {
		return p, false
	}
	p.Len = total
	p.Proto = b[9]
	p.Src = netip.AddrFrom4([4]byte(b[12:16]))
	p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
	if binary.BigEndian.Uint16(b[6:])&0x1fff != 0 {
		p.Frag = true
		return p, true
	}
	return p, decodeL4(&p, b[ihl:total], false)
}

func decode6(b []byte) (Packet, bool) {
	var p Packet
	if len(b) < 40 {
		return p, false
	}
	total := 40 + int(binary.BigEndian.Uint16(b[4:]))
	if total > len(b) {
		return p, false
	}
	p.Len = total
	p.Src = netip.AddrFrom16([16]byte(b[8:24]))
	p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
	nh := b[6]
	off := 40
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if off+8 > total {
				return p, false
			}
			n := (int(b[off+1]) + 1) * 8
			if off+n > total {
				return p, false
			}
			nh = b[off]
			off += n
		case 51: // authentication header
			if off+8 > total {
				return p, false
			}
			n := (int(b[off+1]) + 2) * 4
			if off+n > total {
				return p, false
			}
			nh = b[off]
			off += n
		case 44: // fragment
			if off+8 > total {
				return p, false
			}
			fragOff := binary.BigEndian.Uint16(b[off+2:]) >> 3
			nh = b[off]
			off += 8
			if fragOff != 0 {
				p.Proto = nh
				p.Frag = true
				return p, true
			}
		default:
			p.Proto = nh
			return p, decodeL4(&p, b[off:total], true)
		}
	}
	return p, false
}

func decodeL4(p *Packet, l4 []byte, v6 bool) bool {
	switch {
	case p.Proto == ProtoTCP:
		if len(l4) < 20 || int(l4[12]>>4)*4 < 20 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:])
		p.DstPort = binary.BigEndian.Uint16(l4[2:])
		p.TCPFlags = l4[13]
	case p.Proto == ProtoUDP:
		if len(l4) < 8 {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:])
		p.DstPort = binary.BigEndian.Uint16(l4[2:])
	case p.Proto == ProtoICMP && !v6, p.Proto == ProtoICMPv6 && v6:
		if len(l4) < 4 {
			return false
		}
		p.ICMPType = l4[0]
		p.ICMPCode = l4[1]
	}
	return true
}

// icmpError reports whether p is an ICMP error message (as opposed to an
// informational one such as echo).
func (p *Packet) icmpError() bool {
	switch p.Proto {
	case ProtoICMP:
		return p.ICMPType == 3 || p.ICMPType == 11 || p.ICMPType == 12
	case ProtoICMPv6:
		return p.ICMPType >= 1 && p.ICMPType <= 4
	}
	return false
}
