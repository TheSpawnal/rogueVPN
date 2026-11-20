package flow

import (
	"encoding/binary"
	"io"
)

// linkTypeRaw is LINKTYPE_RAW: packets begin with an IPv4 or IPv6 header.
const linkTypeRaw = 101

// WritePcapHeader writes a classic pcap file header.
func WritePcapHeader(w io.Writer, snaplen int) error {
	var h [24]byte
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], uint32(snaplen))
	binary.LittleEndian.PutUint32(h[20:], linkTypeRaw)
	_, err := w.Write(h[:])
	return err
}

// WritePcapRecord writes one packet record.
func WritePcapRecord(w io.Writer, p CapPacket) error {
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(p.Time.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(p.Time.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(p.Data)))
	binary.LittleEndian.PutUint32(h[12:], uint32(p.Orig))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p.Data)
	return err
}
