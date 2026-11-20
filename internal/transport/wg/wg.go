package wg

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"wyrm/internal/keys"
	"wyrm/internal/transport"
)

// Config configures the WireGuard backend.
type Config struct {
	TUN        tun.Device
	PrivateKey keys.Private
	ListenPort uint16
	// OOBMatch classifies a received datagram as out-of-band. It must never
	// match a WireGuard message.
	OOBMatch func([]byte) bool
	OOBRecv  transport.OOBHandler
	Log      *slog.Logger
}

// Backend implements transport.Transport.
type Backend struct {
	dev  *device.Device
	bind *muxBind

	mu        sync.Mutex
	keepalive map[keys.Public]time.Duration // wanted, applied once an endpoint is known
}

var _ transport.Transport = (*Backend)(nil)

// New creates the WireGuard device on top of cfg.TUN and brings it up.
// On failure the TUN device is closed.
func New(cfg Config) (*Backend, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	if cfg.ListenPort == 0 {
		// Choose the port here rather than letting the bind do it: the
		// engine must know the real port to advertise endpoints.
		p, err := freeUDPPort()
		if err != nil {
			cfg.TUN.Close()
			return nil, fmt.Errorf("wg: pick port: %w", err)
		}
		cfg.ListenPort = p
	}
	bind := &muxBind{inner: conn.NewDefaultBind(), match: cfg.OOBMatch, recv: cfg.OOBRecv}
	dev := device.NewDevice(cfg.TUN, bind, &device.Logger{
		Verbosef: func(f string, a ...any) { log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { log.Error("wireguard: " + fmt.Sprintf(f, a...)) },
	})
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", cfg.PrivateKey.Hex(), cfg.ListenPort)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: configure: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: up: %w", err)
	}
	return &Backend{dev: dev, bind: bind, keepalive: make(map[keys.Public]time.Duration)}, nil
}

func freeUDPPort() (uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// Name implements transport.Transport.
func (b *Backend) Name() string { return "wireguard" }

// LocalPort implements transport.Transport.
func (b *Backend) LocalPort() uint16 { return b.bind.localPort() }

// UpsertPeer implements transport.Transport.
func (b *Backend) UpsertPeer(p transport.PeerConfig) error {
	var s strings.Builder
	fmt.Fprintf(&s, "public_key=%s\nreplace_allowed_ips=true\n", p.PublicKey.Hex())
	for _, a := range p.AllowedIPs {
		fmt.Fprintf(&s, "allowed_ip=%s\n", a)
	}
	// Keepalives start a handshake at once, which can only fail while the
	// peer has no endpoint; they are switched on together with the first
	// endpoint instead.
	b.mu.Lock()
	b.keepalive[p.PublicKey] = p.Keepalive
	b.mu.Unlock()
	if p.Endpoint.IsValid() {
		fmt.Fprintf(&s, "endpoint=%s\npersistent_keepalive_interval=%d\n", p.Endpoint, int(p.Keepalive/time.Second))
	}
	return b.dev.IpcSet(s.String())
}

// RemovePeer implements transport.Transport.
func (b *Backend) RemovePeer(k keys.Public) error {
	b.mu.Lock()
	delete(b.keepalive, k)
	b.mu.Unlock()
	return b.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", k.Hex()))
}

// SetEndpoint implements transport.Transport.
func (b *Backend) SetEndpoint(k keys.Public, ep netip.AddrPort) error {
	b.mu.Lock()
	ka := b.keepalive[k]
	b.mu.Unlock()
	return b.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\npersistent_keepalive_interval=%d\n",
		k.Hex(), ep, int(ka/time.Second)))
}

// Stats implements transport.Transport.
func (b *Backend) Stats() ([]transport.PeerStats, error) {
	raw, err := b.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	var out []transport.PeerStats
	var cur *transport.PeerStats
	var sec, nsec int64
	flush := func() {
		if cur != nil {
			if sec != 0 || nsec != 0 {
				cur.LastHandshake = time.Unix(sec, nsec)
			}
			out = append(out, *cur)
		}
		cur, sec, nsec = nil, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			flush()
			pk, err := keys.ParsePublicHex(v)
			if err != nil {
				return nil, err
			}
			cur = &transport.PeerStats{PublicKey: pk}
			continue
		}
		if cur == nil {
			continue
		}
		switch k {
		case "endpoint":
			if ap, err := netip.ParseAddrPort(v); err == nil {
				cur.Endpoint = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out, nil
}

// SendOOB implements transport.Transport.
func (b *Backend) SendOOB(p []byte, to netip.AddrPort) error {
	return b.bind.sendOOB(p, to)
}

// Close implements transport.Transport.
func (b *Backend) Close() error {
	b.dev.Close()
	return nil
}
