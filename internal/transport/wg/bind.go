// Package wg is the WireGuard data plane, built on the reference userspace
// implementation (wireguard-go).
package wg

import (
	"errors"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"wyrm/internal/transport"
)

// muxBind wraps the platform's UDP bind and diverts out-of-band datagrams
// (path discovery, STUN) away from the WireGuard receive path. Both kinds of
// traffic must share one socket: a NAT mapping opened by a discovery packet
// is then the mapping WireGuard itself uses.
type muxBind struct {
	inner conn.Bind
	match func([]byte) bool
	recv  transport.OOBHandler

	mu   sync.RWMutex
	open bool
	port uint16
}

var errBindClosed = errors.New("wg: socket not open")

func (m *muxBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fns, actual, err := m.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if actual == 0 {
		// On hosts without IPv6 the reference bind reports port 0 even
		// though the IPv4 socket is bound to the requested port.
		actual = port
	}
	m.open, m.port = true, actual
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = m.wrap(fn)
	}
	return out, actual, nil
}

func (m *muxBind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || !m.match(packets[i][:sizes[i]]) {
				continue
			}
			if from, perr := netip.ParseAddrPort(eps[i].DstToString()); perr == nil {
				from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
				m.recv(packets[i][:sizes[i]], from)
			}
			// A zero size tells the WireGuard receive loop to skip the slot.
			sizes[i] = 0
		}
		return n, err
	}
}

func (m *muxBind) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.open = false
	return m.inner.Close()
}

func (m *muxBind) SetMark(mark uint32) error { return m.inner.SetMark(mark) }

func (m *muxBind) Send(bufs [][]byte, ep conn.Endpoint) error { return m.inner.Send(bufs, ep) }

func (m *muxBind) ParseEndpoint(s string) (conn.Endpoint, error) { return m.inner.ParseEndpoint(s) }

func (m *muxBind) BatchSize() int { return m.inner.BatchSize() }

func (m *muxBind) localPort() uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.port
}

func (m *muxBind) sendOOB(b []byte, to netip.AddrPort) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.open {
		return errBindClosed
	}
	ep, err := m.inner.ParseEndpoint(to.String())
	if err != nil {
		return err
	}
	return m.inner.Send([][]byte{b}, ep)
}
