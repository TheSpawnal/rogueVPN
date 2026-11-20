// Package tap splices the flow inspector into the TUN device, the one point
// where every tunnel packet is visible as plaintext IP regardless of which
// transport carries it.
package tap

import (
	"golang.zx2c4.com/wireguard/tun"

	"wyrm/internal/flow"
)

// Tap wraps a TUN device so every packet crossing it is passed through a
// Table. Dropped packets never reach the tunnel (outbound) or the host
// (inbound).
type Tap struct {
	tun.Device
	t *flow.Table
}

// New wraps dev.
func New(dev tun.Device, t *flow.Table) *Tap {
	return &Tap{Device: dev, t: t}
}

// Read receives host-to-mesh packets. A dropped packet is reported with a
// zero size, which the WireGuard device skips.
func (d *Tap) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] <= 0 {
			continue
		}
		if !d.t.Process(flow.Out, bufs[i][offset:offset+sizes[i]]) {
			sizes[i] = 0
		}
	}
	return n, err
}

// Write delivers mesh-to-host packets, omitting dropped ones. The caller's
// slice is never modified.
func (d *Tap) Write(bufs [][]byte, offset int) (int, error) {
	var kept [][]byte
	filtered := false
	for i, b := range bufs {
		ok := len(b) > offset && d.t.Process(flow.In, b[offset:])
		switch {
		case ok && filtered:
			kept = append(kept, b)
		case !ok && !filtered:
			filtered = true
			kept = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if !filtered {
		return d.Device.Write(bufs, offset)
	}
	if len(kept) > 0 {
		if _, err := d.Device.Write(kept, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
