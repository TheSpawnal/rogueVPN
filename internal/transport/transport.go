// Package transport defines the data-plane contract. The engine only talks
// to this interface, so the tunnel protocol can be replaced or extended
// (obfuscation, relays, post-quantum key mixing) without touching the
// control plane, NAT traversal, flow inspector or user interfaces.
package transport

import (
	"net/netip"
	"time"

	"wyrm/internal/keys"
)

// PeerConfig describes one remote node.
type PeerConfig struct {
	PublicKey  keys.Public
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort // zero if not yet known
	Keepalive  time.Duration
}

// PeerStats is the live state of one remote node.
type PeerStats struct {
	PublicKey     keys.Public
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// OOBHandler receives datagrams that arrived on the transport's UDP socket
// but are not tunnel traffic. b is only valid during the call.
type OOBHandler func(b []byte, from netip.AddrPort)

// Transport is an encrypted packet tunnel bound to one UDP port.
type Transport interface {
	// Name identifies the protocol for display.
	Name() string
	// LocalPort is the bound UDP port.
	LocalPort() uint16
	// UpsertPeer adds a peer or replaces its configuration.
	UpsertPeer(PeerConfig) error
	// RemovePeer deletes a peer and its session keys.
	RemovePeer(keys.Public) error
	// SetEndpoint points an existing peer at a new UDP address.
	SetEndpoint(keys.Public, netip.AddrPort) error
	// Stats reports all peers.
	Stats() ([]PeerStats, error)
	// SendOOB transmits a non-tunnel datagram from the tunnel's own socket,
	// so NAT mappings created by it are valid for tunnel traffic.
	SendOOB(b []byte, to netip.AddrPort) error
	// Close tears the tunnel down, including its TUN device.
	Close() error
}
