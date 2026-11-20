# Architecture

## Planes

    +------------------------- node -------------------------+
    |  wyrm top / CLI / future GUI                            |
    |        |  HTTP+JSON over unix socket (internal/api)     |
    |  apiserver                                              |
    |        |                                                |
    |  engine ---- control client ====TLS 1.3 (pinned)====> coordination server
    |    |  \                                                 |   (keys, endpoints,
    |    |   path discovery (disco + STUN)                    |    STUN responder)
    |    |        |  shares the UDP socket                    |
    |  transport (WireGuard) <======== UDP ========> other nodes
    |    |
    |  tap -> flow table (rules, shields, ring, capture)
    |    |
    |  TUN device (wyrm0) <-> kernel IP stack
    +---------------------------------------------------------+

Control plane: who is in the mesh, which keys, where they might be reachable.
Data plane: WireGuard, node to node, never through the coordination server.
Inspection plane: the tap, where every tunnel packet is plaintext IP.

## Packet path

Outbound: kernel -> TUN -> `tap.Read` -> `flow.Table.Process(Out)` ->
WireGuard encrypts -> UDP.
Inbound: UDP -> mux bind (diverts discovery and STUN packets to the engine)
-> WireGuard decrypts and checks the source address against the peer's
allowed IP -> `tap.Write` -> `flow.Table.Process(In)` -> TUN -> kernel.

`Process` does, in order: decode (malformed packets are dropped), mesh
confinement, rule list, shields, flow accounting, ring entry, capture.

## Identities and keys

| Key | Type | Lifetime | Known to |
|---|---|---|---|
| Node identity | Ed25519 | permanent, on disk | node; public half to the server |
| Tunnel key | Curve25519 | permanent, on disk | node; public half to server and peers |
| Discovery key | Curve25519 | one daemon run, memory only | node; public half to server and peers |
| Server identity | Ed25519 | permanent, on disk | server; nodes pin its public key |
| Enrollment key | 256-bit random | minutes to days | admin and the enrolling node; server stores a SHA-256 |

## Control protocol

HTTPS/1.1 over TLS 1.3 only. Trust does not come from certificate chains:

- The node pins the server's public key (`sha256:` over the
  SubjectPublicKeyInfo) and refuses anything else.
- The server requires a client certificate and identifies the node by the
  key that certificate proves possession of. A TLS session without a client
  certificate never reaches the HTTP layer.

With the Go toolchain used here the handshake negotiates the hybrid
post-quantum key exchange X25519MLKEM768 (asserted by a test).

Endpoints:

- `POST /v1/enroll` {auth key, name, tunnel public key} -> {node id, mesh IP, CIDR}
- `POST /v1/update` {discovery public key, endpoints}
- `GET /v1/netmap?since=V` long-poll; returns when the map version differs
  from V, or 204 after 25 s.

The node trusts the network map for membership and for peer keys (see the
threat model for what that implies) but validates its consistency:
peers must have distinct keys and distinct addresses inside the mesh range,
and candidate endpoints inside the mesh range, loopback, link-local or
unspecified are discarded.

## Path discovery

Discovery packets and STUN share the WireGuard UDP socket (`wg.muxBind`), so
a NAT mapping opened by a probe is the mapping WireGuard then uses. The
demultiplexer cannot misfile a WireGuard message: discovery packets start
with a magic whose first byte is outside the WireGuard type range, and a
STUN response has a non-zero second byte where WireGuard always has zero.

Discovery packet:

    magic[6] | sender disco key[32] | nonce[24] | box(sender disco key[32] | payload)

The box is NaCl box (X25519, XSalsa20-Poly1305) under the two nodes'
discovery keys. The sender key is repeated inside the box because the box
key is symmetric: without it a packet could be reflected to its author or
relabelled. Pings carry a random transaction ID; the receiver keeps a
256-entry replay window per peer.

Procedure per peer:

1. Candidates = endpoints the peer advertised + any address an authenticated
   ping arrived from.
2. Ping every candidate (every 2 s while searching).
3. A pong must echo a pending transaction ID and come from the address that
   was pinged. It yields a round-trip time.
4. The tunnel endpoint is set only to a candidate confirmed this way. A
   confirmed path is replaced only by one at least 30 % faster.
5. The path in use is re-probed every 5 s, alternatives every 30 s. No pong
   for 15 s drops the path and resumes searching.

A node's own endpoints are its local interface addresses (unless `--no-lan`)
plus what the coordination server's STUN responder observed. A STUN reply
counts only if it answers a pending request and comes from the server asked.

## Filter semantics

- Ordered rules, first match wins: action, direction, protocol, remote
  prefix, destination port.
- Shields: with no matching rule, an inbound packet passes only if it
  belongs to a flow this host opened, is a trailing fragment between two
  addresses that have such a flow, or is an ICMP error.
- Mesh confinement, before everything else and not overridable by rules:
  outbound source must be this node's mesh address and destination a mesh
  address; inbound the reverse.
- Fragments: a first fragment too short to hold its transport header is
  dropped. Port rules match first fragments; a datagram whose first fragment
  is dropped cannot be reassembled.
- Flow table: 65536 entries. When full, remote-initiated flows are not
  tracked and never evict local ones.

## Seams

| Seam | Where | What plugs in |
|---|---|---|
| Data plane | `transport.Transport` | obfuscated or relayed transports, a kernel WireGuard backend |
| OS | `internal/platform` | Windows/macOS interface configuration, routes, firewall, DNS |
| UI | `internal/api` (HTTP+JSON on a local socket) | GUI, exporters, scripts |
| Inspection | `flow.Table` subscriptions | telemetry with user consent, IDS hooks |

The engine never imports the WireGuard package directly except to
construct the backend, and no UI code imports the engine.

## Porting to Windows

Already portable: everything except `internal/platform`. wireguard-go's
`tun` package provides the Wintun device and its `conn` package the Windows
UDP bind; the mux bind wraps whichever is the platform default.

To do:

1. `platform.ConfigureInterface` for Windows (address, MTU via the IP
   Helper API / winipcfg).
2. Access control for the local API socket (directory ACL or a named pipe).
3. Service wrapper (run under the Service Control Manager).
4. Ship `wintun.dll` next to the binary.

## Roadmap

Each item names the seam it uses.

1. Relay fallback for pairs that cannot hole-punch (symmetric NAT, UDP
   blocked): a relay candidate type in path discovery, carried by the mux
   bind.
2. Exit nodes, the "classic VPN" mode: default route through a chosen peer,
   policy routing with a firewall mark, kill switch, DNS handling
   (`platform`), and a relaxation of mesh confinement for that peer only.
3. Post-quantum data plane: per-pair ML-KEM-768 secret mixed into WireGuard
   as a preshared key (`transport.PeerConfig`).
4. Mesh lock: node keys signed by a trust root the coordination server does
   not hold, so a compromised server cannot add nodes or substitute keys.
5. Access policy distributed by the coordination server and compiled into
   each node's rule table.
6. IPv6 mesh addresses.
7. Opt-in usage statistics: an exporter on the local API, off by default.
8. Windows platform layer and a GUI on the local API.
