// Package api defines the local control API of the node daemon. The CLI and
// the terminal UI are ordinary clients of it; a graphical front end plugs
// in at exactly the same seam.
package api

import (
	"net/netip"
	"time"

	"wyrm/internal/flow"
)

// HTTP paths served on the daemon's local socket.
const (
	PathStatus   = "/v1/status"
	PathPeers    = "/v1/peers"
	PathFlows    = "/v1/flows"
	PathPackets  = "/v1/packets"
	PathRules    = "/v1/rules"
	PathShields  = "/v1/shields"
	PathSnapshot = "/v1/snapshot"
	PathCapture  = "/v1/capture"
)

// Status describes the local node.
type Status struct {
	Version    string           `json:"version"`
	NodeID     string           `json:"node_id"`
	Name       string           `json:"name"`
	IP         netip.Addr       `json:"ip"`
	CIDR       netip.Prefix     `json:"cidr"`
	Iface      string           `json:"iface"`
	ListenPort uint16           `json:"listen_port"`
	Transport  string           `json:"transport"`
	CoordURL   string           `json:"coord_url"`
	CoordState string           `json:"coord_state"`
	CoordSync  time.Time        `json:"coord_sync"`
	Endpoints  []netip.AddrPort `json:"endpoints"`
	Shields    bool             `json:"shields"`
	Started    time.Time        `json:"started"`
	Totals     flow.Totals      `json:"totals"`
}

// Peer path states.
const (
	PathDirect  = "direct"  // a discovery-confirmed UDP path is in use
	PathActive  = "active"  // tunnel handshake is fresh, path not re-confirmed
	PathProbing = "probing" // peer is online, still searching for a path
	PathOffline = "offline" // peer is not connected to the coordination server
)

// Peer describes one remote node and the link to it.
type Peer struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	IP            netip.Addr     `json:"ip"`
	Key           string         `json:"key"`
	Online        bool           `json:"online"`
	Path          string         `json:"path"`
	Endpoint      netip.AddrPort `json:"endpoint"`
	RTTMillis     float64        `json:"rtt_ms"`
	Candidates    int            `json:"candidates"`
	LastHandshake time.Time      `json:"last_handshake"`
	RxBytes       uint64         `json:"rx_bytes"`
	TxBytes       uint64         `json:"tx_bytes"`
}

// Snapshot is everything a dashboard needs in one round trip.
type Snapshot struct {
	Status Status          `json:"status"`
	Peers  []Peer          `json:"peers"`
	Flows  []flow.FlowInfo `json:"flows"`
	Rules  []flow.Rule     `json:"rules"`
}

// ShieldsRequest switches default-deny for unsolicited inbound traffic.
type ShieldsRequest struct {
	On bool `json:"on"`
}

// Error is the JSON body of every non-2xx response.
type Error struct {
	Error string `json:"error"`
}
