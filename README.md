# wyrm

A WireGuard-based mesh VPN in Go. One static binary holds the node daemon,
the coordination server, the command-line client and a terminal dashboard.

Status: milestone 1. Linux is implemented and tested end to end. The code
compiles for Windows; the Windows platform layer is a stub (see
`docs/ARCHITECTURE.md`, "Porting to Windows").

## What it does

- Nodes enroll with a coordination server and get a mesh address
  (default range `10.88.0.0/16`).
- Every pair of nodes builds a direct, end-to-end encrypted WireGuard tunnel.
  NAT traversal uses STUN plus authenticated UDP hole punching on the
  WireGuard socket itself.
- The coordination server only distributes public keys and candidate
  endpoints. It never holds a private key and never carries tunnel traffic.
  It is still the trust anchor for who is in the mesh: a compromised server
  can add nodes or swap peer keys. See `docs/THREAT_MODEL.md`.
- A flow inspector sits on the tunnel device: live flow table, recent-packet
  ring, pcap capture for Wireshark, and a small stateful filter (ordered
  allow/drop rules plus a "shields" mode that drops unsolicited inbound
  traffic).
- `wyrm top` is an htop-style dashboard over all of it.
- Everything the CLI and dashboard do goes through a local HTTP API on a
  unix socket. A GUI plugs into that same API.

## Build

Needs Go 1.26 or newer.

    make build        # bin/wyrm
    make test         # vet + unit tests
    sudo make e2e     # NAT lab in network namespaces (root, nft, python3, bc)

## Quick start

On a host every node can reach (the coordination server):

    wyrm coord serve --dir /var/lib/wyrm-coord --listen :8443 --stun :3478
    wyrm coord pin                       # sha256:... give this to every node
    wyrm coord authkey > node.key        # one-time enrollment key, 1h lifetime

Open TCP 8443 and UDP 3478 on that host.

On each node, as root (first start enrolls; later starts need no flags):

    wyrm up --coord https://COORD_HOST:8443 --pin sha256:... --authkey-file node.key
    shred -u node.key

Then, from any shell on the node:

    wyrm status
    wyrm peers
    wyrm top

The enrollment key is read from a file or from `WYRM_AUTHKEY`, never from a
command-line argument, so it does not show up in `ps`.

## Commands

    wyrm up                 node daemon
    wyrm status | peers | flows | packets | rules     (add --json for scripts)
    wyrm rule add <allow|drop> <in|out|any> <any|tcp|udp|icmp> <cidr|ip|any> <port|any>
    wyrm rule del <id>
    wyrm shields <on|off>
    wyrm capture [-s snaplen] [-o file]
    wyrm top [--view peers|flows|packets|rules] [--once]

    wyrm coord serve | pin | authkey | keys | revoke <id> | nodes | rm <node>

Flags go before positional arguments. Client commands find the daemon at
`--sock`, `$WYRM_SOCK` or `/run/wyrm/wyrmd.sock`.

### Traffic control

Rules are evaluated in order; the first match decides. The port is the
packet's destination port.

    wyrm rule add drop in tcp 10.88.0.7 22     # that peer may not reach my sshd
    wyrm rule add drop any any 10.88.0.9 any   # cut one peer off entirely
    wyrm shields on                            # default-deny unsolicited inbound
    wyrm rule add allow in tcp any 443         # ...except this service

Rules and the shields setting persist across restarts.

Independently of any rule, the tunnel only carries packets between this
node's mesh address and other mesh addresses. A peer cannot use the tunnel
to reach other networks the host is attached to.

### Capture

    wyrm capture | wireshark -k -i -
    wyrm capture -s 96 -o trace.pcap

The capture is taken inside the tunnel, so it is plaintext. Output files are
created with mode 0600.

### Dashboard keys

    1-4 or Tab   switch view (Peers, Flows, Packets, Rules)
    Up/Down, j/k, PgUp/PgDn, Home/End    move
    s            cycle flow sort (rate, bytes, recent)
    b            block the selected peer, or the selected flow's service
    u            unblock the selected peer
    d            delete the selected rule
    S            toggle shields
    p            pause refresh
    q            quit

### Privacy switch

`wyrm up --no-lan` stops the node from advertising its local interface
addresses. The coordination server and peers then learn only the address
STUN observed. The cost: two nodes on the same LAN connect through their
router instead of directly.

## Who can use the local API

The daemon socket is owner-only (0600) by default. `wyrm up --group NAME`
also admits members of one group. Anyone who can connect can read tunnel
traffic and change filter rules, so treat that group like `wireshark` or
`docker`.

## What has been verified

On Linux 6.18 (amd64), in this repository's own tests:

- 27 unit tests in 7 packages, clean under the race detector.
- Three fuzzers (packet decoder and filter, discovery packets, STUN) with no
  findings.
- `test/mesh.sh`, 43 checks: three nodes, two behind separate NAT routers
  with a default-drop firewall. Covers enrollment, hole punching, a 30 MB
  transfer with digest check, a sniff of the WAN side for plaintext, rules,
  shields, capture, node restart, coordination server outage and restart,
  node removal, wrong pin, forged key, file permissions. Its last check
  drives the dashboard through a pseudo-terminal (`test/tui_drive.py`,
  10 steps).

Not verified here: anything on Windows beyond compiling; IPv6 underlays (the
test kernel had no IPv6); the systemd units in `dist/`; pairs of nodes that
are both behind symmetric NAT (they need the relay planned for milestone 2).
There has been no independent security review.

## Layout

    cmd/wyrm              CLI entry point
    internal/engine       node core: control loops, path discovery
    internal/transport    data-plane interface; wg/ is the WireGuard backend
    internal/flow         packet decoder, flow table, rules, ring, pcap
    internal/tap          splices the flow inspector into the TUN device
    internal/disco        authenticated path-discovery packets
    internal/stun         minimal STUN client/server codec
    internal/coord        coordination server
    internal/control      node side of the coordination protocol
    internal/ident        Ed25519 identities and key pinning
    internal/api          local API types and client (the GUI seam)
    internal/apiserver    local API server
    internal/tui          terminal dashboard
    internal/platform     OS-specific code (Linux implemented, others stubbed)
    test/                 NAT lab, end-to-end test, dashboard driver
    dist/                 systemd units
    docs/                 architecture and threat model
