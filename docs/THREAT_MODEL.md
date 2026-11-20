# Threat model

Milestone 1. This document states what the design defends against, what it
does not, and where the known gaps are. It has not been reviewed by anyone
other than its author.

## Assets

1. Content of traffic between nodes.
2. Membership: only enrolled nodes may join.
3. Each node's exposure: what other mesh members can reach on it.
4. Node private keys.
5. Metadata: who talks to whom, from which addresses.

## Adversaries

### Passive network observer

Sees: WireGuard packets between node endpoints, TLS 1.3 to the coordination
server, STUN requests, discovery packets.

Cannot: read tunnel traffic (WireGuard: Noise IK, ChaCha20-Poly1305), read
control traffic, learn node identities (client certificates are encrypted in
TLS 1.3), read discovery payloads.

Can: tell that this is WireGuard, see endpoint addresses, traffic volume and
timing. There is no obfuscation or padding.

### Active on-path attacker

Cannot: impersonate the coordination server (pinned key), impersonate a node
(tunnel and discovery packets are authenticated), inject a tunnel endpoint
(endpoints are only adopted after an authenticated ping/pong), reuse a
captured discovery ping (replay window), poison the reflexive address
(STUN reply must match a pending transaction and come from the server asked;
a wrong address would in any case only yield a candidate that fails to
confirm).

Can: drop or delay packets, including selectively blocking UDP so that no
direct path forms. Can relay packets unmodified, which changes the path but
not what is readable.

### Coordination server, compromised or malicious

This is the trust anchor for membership, and the largest gap. Nodes learn
each other's public keys from it and have no second source for them.

Cannot: decrypt tunnel traffic by observing it (it holds no private key),
make a node adopt an endpoint the key holder does not answer on, assign a
peer an address outside the mesh range.

Can, by acting: add a node of its own to the mesh; hand a node a substituted
public key for one of its peers and so impersonate that peer, or sit between
two nodes by doing it to both. Can remove nodes, hide nodes from each other,
and observe every node's public endpoint, its LAN addresses (unless
`--no-lan`) and when it is online.

Detection today: a node logs a warning when the tunnel key behind a mesh
address changes, which also happens on a legitimate re-enrollment. Nothing
detects a substituted key that was there from the first map.
Mitigation today: protect the server like a certificate authority; shields
and rules on each node limit what an added node can reach. Planned: mesh
lock, where node keys are signed by a root the server does not hold.

### Malicious enrolled peer

Cannot: send from an address other than its own (WireGuard allowed IPs),
reach networks behind another node or addresses other than that node's mesh
address (mesh confinement), bypass rules with fragments (tiny first
fragments are dropped), exhaust another node's flow table with inbound
traffic (remote-initiated flows never evict local ones), flood the
coordination server with endpoint updates (token bucket per node), inject
terminal escape sequences through its name (sanitised by the server and
again at display).

Can: reach every service on other nodes that their rules and shields allow.
With shields off and no rules that is everything bound to the mesh address
or to all addresses. Can send ICMP errors, which pass shields.

### Holder of a leaked enrollment key

Can enroll one node (or several, if the key is reusable) until the key
expires or is revoked. Keys are single-use and expire after an hour by
default; the server stores only their hash; failed attempts are throttled
per address. Remove unwanted nodes with `wyrm coord rm`.

### Unprivileged local user on a node

Cannot: read keys or policy (0600 in a 0700 directory), talk to the daemon
(socket 0600 unless a group is configured), read a capture file (0600).

If admitted through `--group`: can read plaintext tunnel traffic and change
filter rules.

### Future quantum adversary recording traffic today

Control channel: protected (hybrid X25519MLKEM768 key exchange).
Data plane: not protected. WireGuard's handshake is classical. A per-pair
post-quantum preshared key is on the roadmap.

## Known gaps

- No relay: two nodes that are both behind symmetric NAT, or on networks
  that block UDP, cannot connect.
- The coordination server can add nodes and substitute peer keys (see above).
- Data plane is not post-quantum.
- The node daemon runs as root. `dist/wyrmd.service` confines it to
  CAP_NET_ADMIN but has not been tested.
- Private keys are stored unencrypted, protected by file permissions only.
- WireGuard traffic is recognisable and can be blocked by a censor.
- The STUN responder answers anyone; the reply is 12 to 24 bytes larger than
  the 20-byte request, a small but non-zero amplification.
- The coordination server caps connections per address at 64, which also
  limits how many nodes can sit behind one public address.
- A coordination server outage stops enrollment and endpoint updates;
  existing tunnels keep working but cannot re-discover a path after a
  network change until it returns.
- Filter state is per packet and stateless for fragments; there is no
  reassembly.
- IPv6 underlays are implemented but untested; mesh addresses are IPv4 only.
- `staticcheck` and `govulncheck` have not been run on this tree.
- No independent audit.
