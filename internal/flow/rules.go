package flow

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
)

// MaxRules bounds the per-packet linear rule scan.
const MaxRules = 256

// Rule is one filter entry. Rules are evaluated in order and the first match
// decides. Port matches the packet's destination port, so "in tcp 22" means
// inbound connections to local port 22 and "out tcp 22" means outbound
// connections to remote port 22.
type Rule struct {
	ID     uint32       `json:"id"`
	Action string       `json:"action"` // allow | drop
	Dir    string       `json:"dir"`    // in | out | any
	Proto  string       `json:"proto"`  // any | tcp | udp | icmp
	Remote netip.Prefix `json:"remote"` // remote (peer) address; zero = any
	Port   uint16       `json:"port"`   // destination port; 0 = any
	Hits   uint64       `json:"hits"`
}

// Policy is the persisted filter state.
type Policy struct {
	Shields bool   `json:"shields"`
	Rules   []Rule `json:"rules"`
}

type verdict uint8

const (
	vNone verdict = iota
	vAllow
	vDrop
)

type crule struct {
	rule   Rule
	drop   bool
	anyDir bool
	dir    Dir
	proto  uint8 // 0 = any, ProtoICMP = both ICMP families
	hits   atomic.Uint64
}

type ruleset struct {
	rules []*crule
}

func compile(r Rule) (*crule, error) {
	c := &crule{}
	switch r.Action {
	case "allow":
	case "drop":
		c.drop = true
	default:
		return nil, errors.New("action must be allow or drop")
	}
	switch r.Dir {
	case "in":
		c.dir = In
	case "out":
		c.dir = Out
	case "any", "":
		r.Dir = "any"
		c.anyDir = true
	default:
		return nil, errors.New("dir must be in, out or any")
	}
	switch r.Proto {
	case "any", "":
		r.Proto = "any"
	case "tcp":
		c.proto = ProtoTCP
	case "udp":
		c.proto = ProtoUDP
	case "icmp":
		c.proto = ProtoICMP
	default:
		return nil, errors.New("proto must be any, tcp, udp or icmp")
	}
	if r.Port != 0 && c.proto != ProtoTCP && c.proto != ProtoUDP {
		return nil, errors.New("port requires proto tcp or udp")
	}
	if r.Remote.IsValid() {
		r.Remote = r.Remote.Masked()
	}
	c.hits.Store(r.Hits)
	c.rule = r
	return c, nil
}

func (c *crule) match(dir Dir, p *Packet, remote netip.Addr) bool {
	if !c.anyDir && c.dir != dir {
		return false
	}
	switch c.proto {
	case 0:
	case ProtoICMP:
		if p.Proto != ProtoICMP && p.Proto != ProtoICMPv6 {
			return false
		}
	default:
		if p.Proto != c.proto {
			return false
		}
	}
	if c.rule.Remote.IsValid() && !c.rule.Remote.Contains(remote) {
		return false
	}
	if c.rule.Port != 0 && (p.Frag || p.DstPort != c.rule.Port) {
		return false
	}
	return true
}

func (rs *ruleset) eval(dir Dir, p *Packet, remote netip.Addr) verdict {
	if rs == nil {
		return vNone
	}
	for _, c := range rs.rules {
		if c.match(dir, p, remote) {
			c.hits.Add(1)
			if c.drop {
				return vDrop
			}
			return vAllow
		}
	}
	return vNone
}

// ParseRule builds a rule from CLI-style fields:
// <allow|drop> <in|out|any> <any|tcp|udp|icmp> <cidr|ip|any> <port|any>.
func ParseRule(f []string) (Rule, error) {
	var r Rule
	if len(f) != 5 {
		return r, errors.New("want: <allow|drop> <in|out|any> <any|tcp|udp|icmp> <cidr|ip|any> <port|any>")
	}
	r.Action, r.Dir, r.Proto = f[0], f[1], f[2]
	if f[3] != "any" {
		if pfx, err := netip.ParsePrefix(f[3]); err == nil {
			r.Remote = pfx
		} else if a, err := netip.ParseAddr(f[3]); err == nil {
			r.Remote = netip.PrefixFrom(a, a.BitLen())
		} else {
			return r, fmt.Errorf("bad remote %q", f[3])
		}
	}
	if f[4] != "any" {
		var port uint16
		if _, err := fmt.Sscanf(f[4], "%d", &port); err != nil || port == 0 || fmt.Sprint(port) != f[4] {
			return r, fmt.Errorf("bad port %q", f[4])
		}
		r.Port = port
	}
	if _, err := compile(r); err != nil {
		return r, err
	}
	return r, nil
}
