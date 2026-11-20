package engine

import (
	"context"
	"net/netip"
	"time"

	"wyrm/internal/disco"
	"wyrm/internal/keys"
	"wyrm/internal/proto"
	"wyrm/internal/stun"
	"wyrm/internal/transport"
)

const (
	maxCands     = 32
	maxPending   = 64
	pingTimeout  = 5 * time.Second
	pathTimeout  = 15 * time.Second
	candTTL      = 60 * time.Second
	pingBest     = 5 * time.Second
	pingAlt      = 30 * time.Second
	pingSearch   = 2 * time.Second
	pingOffline  = 15 * time.Second
	pingBackGap  = time.Second
	replayWindow = 256
	rttMargin    = time.Millisecond
)

type cand struct {
	advertised bool
	added      time.Time
	lastPing   time.Time
	lastPong   time.Time
	rtt        time.Duration
}

type pendingPing struct {
	to   netip.AddrPort
	sent time.Time
}

// peer is the engine's view of one remote node.
type peer struct {
	node    proto.Node
	shared  *[32]byte // disco box key; nil until the peer publishes one
	cands   map[netip.AddrPort]*cand
	pending map[disco.TxID]pendingPing
	best    netip.AddrPort

	// Replay window: transaction IDs of recently accepted pings.
	seen     map[disco.TxID]struct{}
	seenRing [replayWindow]disco.TxID
	seenPos  int
}

// replayed reports whether a ping with this transaction ID was already
// accepted, and records it otherwise. Without this, a captured ping could be
// replayed from spoofed addresses to make the node emit replies to them.
func (p *peer) replayed(tx disco.TxID) bool {
	if _, ok := p.seen[tx]; ok {
		return true
	}
	if len(p.seen) >= replayWindow {
		delete(p.seen, p.seenRing[p.seenPos])
	}
	p.seen[tx] = struct{}{}
	p.seenRing[p.seenPos] = tx
	p.seenPos = (p.seenPos + 1) % replayWindow
	return false
}

func (p *peer) bestValid(now time.Time) bool {
	c := p.cands[p.best]
	return c != nil && now.Sub(c.lastPong) < pathTimeout
}

// applyNetMap reconciles the tunnel with a network map and returns the
// number of peers. The map comes from the coordination server, which is
// trusted for membership but still validated for self-consistency.
func (e *Engine) applyNetMap(nm *proto.NetMap) int {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := make(map[keys.Public]bool, len(nm.Peers))
	ips := make(map[netip.Addr]bool, len(nm.Peers))
	prevKey := make(map[netip.Addr]keys.Public, len(e.peers))
	for k, p := range e.peers {
		prevKey[p.node.IP] = k
	}
	for _, n := range nm.Peers {
		if n.WGPub.IsZero() || n.WGPub == e.st.wgKey.Public() || n.IP == e.st.IP ||
			!e.st.CIDR.Contains(n.IP) || ips[n.IP] || seen[n.WGPub] || len(seen) >= maxPeers {
			e.log.Warn("ignoring inconsistent peer in network map", "id", n.ID)
			continue
		}
		seen[n.WGPub], ips[n.IP] = true, true

		p := e.peers[n.WGPub]
		isNew := p == nil
		if isNew {
			p = &peer{
				cands:   make(map[netip.AddrPort]*cand),
				pending: make(map[disco.TxID]pendingPing),
				seen:    make(map[disco.TxID]struct{}),
			}
			e.peers[n.WGPub] = p
		}
		for _, c := range p.cands {
			c.advertised = false
		}
		for i, ap := range n.Endpoints {
			if i >= proto.MaxEndpoints {
				break
			}
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if !e.usableEndpoint(ap) {
				continue
			}
			if c := p.cands[ap]; c != nil {
				c.advertised = true
			} else if len(p.cands) < maxCands {
				p.cands[ap] = &cand{advertised: true, added: now}
			}
		}
		if isNew || p.node.IP != n.IP {
			// No endpoint yet: the transport only ever gets endpoints that
			// path discovery has confirmed in both directions.
			err := e.tr.UpsertPeer(transport.PeerConfig{
				PublicKey:  n.WGPub,
				AllowedIPs: []netip.Prefix{netip.PrefixFrom(n.IP, n.IP.BitLen())},
				Keepalive:  keepalive,
			})
			if err != nil {
				e.log.Error("peer configuration failed", "peer", n.Name, "err", err)
			} else if isNew {
				e.log.Info("peer added", "peer", n.Name, "ip", n.IP.String())
			}
			// Keys come from the coordination server alone. A change is
			// normal after a re-enrollment and is also what a key
			// substitution by a compromised server looks like.
			if old, ok := prevKey[n.IP]; ok && old != n.WGPub {
				e.log.Warn("tunnel key behind a mesh address changed", "peer", n.Name,
					"ip", n.IP.String(), "old", old.Short(), "new", n.WGPub.Short())
			}
		}
		if n.DiscoPub != p.node.DiscoPub {
			if e.byDisco[p.node.DiscoPub] == p {
				delete(e.byDisco, p.node.DiscoPub)
			}
			p.shared = nil
			clear(p.pending)
			p.best = netip.AddrPort{}
			for _, c := range p.cands {
				c.lastPing, c.lastPong = time.Time{}, time.Time{}
			}
			if !n.DiscoPub.IsZero() && e.byDisco[n.DiscoPub] == nil {
				if sh, err := disco.Shared(e.discoPriv, n.DiscoPub); err == nil {
					p.shared = sh
					e.byDisco[n.DiscoPub] = p
				}
			}
		}
		p.node = n
		// Probe new candidates now rather than at the next tick.
		e.probeLocked(p, now)
	}
	for k, p := range e.peers {
		if seen[k] {
			continue
		}
		if err := e.tr.RemovePeer(k); err != nil {
			e.log.Error("peer removal failed", "peer", p.node.Name, "err", err)
		}
		if e.byDisco[p.node.DiscoPub] == p {
			delete(e.byDisco, p.node.DiscoPub)
		}
		delete(e.peers, k)
		e.log.Info("peer removed", "peer", p.node.Name)
	}
	return len(e.peers)
}

// discoLoop owns path discovery: it answers and evaluates discovery
// packets and schedules probes.
func (e *Engine) discoLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	e.tick(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-e.oob:
			e.handleOOB(pkt, time.Now())
		case now := <-t.C:
			e.tick(now)
		}
	}
}

func (e *Engine) tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for tx, r := range e.stunPending {
		if now.Sub(r.sent) > pingTimeout {
			delete(e.stunPending, tx)
		}
	}
	period := stunPeriod
	if len(e.reflexive) == 0 {
		period = stunRetry
	}
	if now.Sub(e.lastSTUN) >= period && len(e.stunServers) > 0 {
		e.lastSTUN = now
		for _, srv := range e.stunServers {
			tx, req, err := stun.NewRequest()
			if err != nil {
				continue
			}
			if len(e.stunPending) < maxPending {
				e.stunPending[tx] = stunReq{server: srv, sent: now}
				e.tr.SendOOB(req, srv)
			}
		}
	}
	if now.Sub(e.lastAddrs) >= addrRefresh {
		e.lastAddrs = now
		e.refreshEndpointsLocked(now)
	}

	for _, p := range e.peers {
		e.probeLocked(p, now)
	}
}

// probeLocked sends whatever pings are due for one peer.
func (e *Engine) probeLocked(p *peer, now time.Time) {
	for tx, pd := range p.pending {
		if now.Sub(pd.sent) > pingTimeout {
			delete(p.pending, tx)
		}
	}
	if p.shared == nil {
		return
	}
	valid := p.bestValid(now)
	if p.best.IsValid() && !valid {
		e.log.Info("path lost", "peer", p.node.Name, "endpoint", p.best.String())
		p.best = netip.AddrPort{}
	}
	for ap, c := range p.cands {
		if !c.advertised && ap != p.best && now.Sub(c.lastPong) > candTTL && now.Sub(c.added) > candTTL {
			delete(p.cands, ap)
			continue
		}
		every := pingOffline
		switch {
		case valid && ap == p.best:
			every = pingBest
		case valid:
			every = pingAlt
		case p.node.Online:
			every = pingSearch
		}
		if now.Sub(c.lastPing) >= every {
			e.pingLocked(p, ap, c, now)
		}
	}
}

func (e *Engine) pingLocked(p *peer, ap netip.AddrPort, c *cand, now time.Time) {
	if len(p.pending) >= maxPending {
		return
	}
	tx, err := disco.NewTxID()
	if err != nil {
		return
	}
	pkt, err := disco.Seal(e.discoPub, p.shared, disco.Ping(tx))
	if err != nil {
		return
	}
	c.lastPing = now
	p.pending[tx] = pendingPing{to: ap, sent: now}
	e.tr.SendOOB(pkt, ap)
}

func (e *Engine) handleOOB(pkt oobPkt, now time.Time) {
	if stun.IsResponse(pkt.b) {
		tx, addr, err := stun.ParseResponse(pkt.b)
		if err != nil {
			return
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		e.mu.Lock()
		defer e.mu.Unlock()
		// Only a reply to our own request, from the server we asked, counts.
		if r, ok := e.stunPending[tx]; ok && r.server == pkt.from && e.usableEndpoint(addr) {
			delete(e.stunPending, tx)
			_, known := e.reflexive[addr]
			e.reflexive[addr] = now
			if !known {
				e.refreshEndpointsLocked(now)
			}
		}
		return
	}
	if !disco.LooksLike(pkt.b) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.byDisco[disco.Sender(pkt.b)]
	if p == nil || p.shared == nil {
		return
	}
	payload, ok := disco.Open(pkt.b, p.node.DiscoPub, p.shared)
	if !ok {
		return
	}
	typ, tx, _, ok := disco.Parse(payload)
	if !ok {
		return
	}
	switch typ {
	case disco.TypePing:
		if p.replayed(tx) {
			return
		}
		if reply, err := disco.Seal(e.discoPub, p.shared, disco.Pong(tx, pkt.from)); err == nil {
			e.tr.SendOOB(reply, pkt.from)
		}
		// The peer can reach us from this address, so it is worth probing
		// even if it was never advertised (it is how NAT-mapped ports are
		// learned).
		c := p.cands[pkt.from]
		if c == nil && len(p.cands) < maxCands && e.usableEndpoint(pkt.from) {
			c = &cand{added: now}
			p.cands[pkt.from] = c
		}
		if c != nil && now.Sub(c.lastPing) >= pingBackGap {
			e.pingLocked(p, pkt.from, c, now)
		}
	case disco.TypePong:
		pd, ok := p.pending[tx]
		if !ok || pd.to != pkt.from {
			return
		}
		delete(p.pending, tx)
		c := p.cands[pkt.from]
		if c == nil {
			return
		}
		sample := now.Sub(pd.sent)
		if c.rtt == 0 || now.Sub(c.lastPong) > pathTimeout {
			c.rtt = sample
		} else {
			c.rtt = (3*c.rtt + sample) / 4
		}
		c.lastPong = now
		e.selectPathLocked(p, now)
	}
}

// selectPathLocked moves the tunnel to the fastest confirmed path. A path is
// only replaced by one that is clearly faster, so two similar paths do not
// flap.
func (e *Engine) selectPathLocked(p *peer, now time.Time) {
	var best netip.AddrPort
	var bestRTT time.Duration
	for ap, c := range p.cands {
		if now.Sub(c.lastPong) >= pathTimeout {
			continue
		}
		if !best.IsValid() || c.rtt < bestRTT || (c.rtt == bestRTT && ap.Compare(best) < 0) {
			best, bestRTT = ap, c.rtt
		}
	}
	if !best.IsValid() || best == p.best {
		return
	}
	if p.bestValid(now) && bestRTT+rttMargin > p.cands[p.best].rtt*7/10 {
		return
	}
	if err := e.tr.SetEndpoint(p.node.WGPub, best); err != nil {
		e.log.Error("endpoint switch failed", "peer", p.node.Name, "err", err)
		return
	}
	p.best = best
	e.log.Info("path selected", "peer", p.node.Name, "endpoint", best.String(),
		"rtt", bestRTT.Round(10*time.Microsecond).String())
}
