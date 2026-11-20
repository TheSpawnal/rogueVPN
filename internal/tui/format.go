// Package tui is the terminal dashboard. It is a plain client of the local
// API: everything it shows or changes goes through the same calls a
// graphical front end would use.
package tui

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wyrm/internal/flow"
)

func humanBytes(n uint64) string {
	const units = "KMGTPE"
	if n < 1024 {
		return strconv.FormatUint(n, 10) + "B"
	}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if f >= 100 {
		return fmt.Sprintf("%.0f%c", f, units[i])
	}
	return fmt.Sprintf("%.1f%c", f, units[i])
}

func humanRate(bps float64) string {
	if bps < 1 {
		return "0"
	}
	return humanBytes(uint64(bps)) + "/s"
}

func humanDur(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

func since(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDur(now.Sub(t))
}

func protoName(p uint8) string {
	switch p {
	case flow.ProtoICMP:
		return "icmp"
	case flow.ProtoTCP:
		return "tcp"
	case flow.ProtoUDP:
		return "udp"
	case flow.ProtoICMPv6:
		return "icmp6"
	case 0:
		return "-"
	}
	return strconv.Itoa(int(p))
}

func hasPorts(p uint8) bool { return p == flow.ProtoTCP || p == flow.ProtoUDP }

func addrPort(ap netip.AddrPort, proto uint8) string {
	if !ap.IsValid() {
		return "-"
	}
	if !hasPorts(proto) {
		return ap.Addr().String()
	}
	return ap.String()
}

func tcpFlags(f uint8) string {
	var b strings.Builder
	for _, x := range []struct {
		bit  uint8
		name byte
	}{{flow.TCPSyn, 'S'}, {flow.TCPAck, 'A'}, {flow.TCPFin, 'F'}, {flow.TCPRst, 'R'}, {0x08, 'P'}} {
		if f&x.bit != 0 {
			b.WriteByte(x.name)
		}
	}
	return b.String()
}

// cols lays values out in fixed-width columns. A negative width
// right-aligns; a zero width takes the value as is (last column).
func cols(widths []int, vals ...string) string {
	var b strings.Builder
	for i, v := range vals {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		right := w < 0
		if right {
			w = -w
		}
		if w > 0 && len(v) > w {
			v = v[:w-1] + "~"
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		switch {
		case w == 0:
			b.WriteString(v)
		case right:
			b.WriteString(strings.Repeat(" ", w-len(v)))
			b.WriteString(v)
		default:
			b.WriteString(v)
			b.WriteString(strings.Repeat(" ", w-len(v)))
		}
	}
	return b.String()
}
