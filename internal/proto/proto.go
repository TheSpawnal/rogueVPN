// Package proto defines the control-plane wire types exchanged between a
// node and the coordination server. Everything here travels as JSON inside
// a pinned, mutually authenticated TLS 1.3 connection.
package proto

import (
	"net/netip"
	"time"

	"wyrm/internal/keys"
)

// HTTP paths of the control API.
const (
	PathEnroll = "/v1/enroll"
	PathUpdate = "/v1/update"
	PathNetMap = "/v1/netmap"
)

// Limits enforced by both sides.
const (
	MaxEndpoints = 16
	MaxNameLen   = 63
	MaxBody      = 64 << 10
)

// EnrollRequest registers the TLS client identity as a mesh node.
type EnrollRequest struct {
	AuthKey string      `json:"auth_key"`
	Name    string      `json:"name"`
	WGPub   keys.Public `json:"wg_pub"`
}

// EnrollResponse returns the node's place in the mesh.
type EnrollResponse struct {
	NodeID string       `json:"node_id"`
	Name   string       `json:"name"`
	IP     netip.Addr   `json:"ip"`
	CIDR   netip.Prefix `json:"cidr"`
}

// UpdateRequest publishes the node's ephemeral NAT-traversal key and the
// UDP endpoints on which it may be reachable.
type UpdateRequest struct {
	DiscoPub  keys.Public      `json:"disco_pub"`
	Endpoints []netip.AddrPort `json:"endpoints"`
}

// Node is one mesh member as seen by its peers.
type Node struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	WGPub     keys.Public      `json:"wg_pub"`
	DiscoPub  keys.Public      `json:"disco_pub"`
	IP        netip.Addr       `json:"ip"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
	Online    bool             `json:"online"`
	LastSeen  time.Time        `json:"last_seen"`
}

// NetMap is the full view a node needs to build its tunnels.
type NetMap struct {
	Version  uint64       `json:"version"`
	CIDR     netip.Prefix `json:"cidr"`
	STUNPort uint16       `json:"stun_port"`
	Self     Node         `json:"self"`
	Peers    []Node       `json:"peers"`
}

// Error is the JSON body of every non-2xx control response.
type Error struct {
	Error string `json:"error"`
}
