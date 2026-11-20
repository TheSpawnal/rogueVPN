//go:build linux

// Command lab builds the network used by test/mesh.sh: three mesh nodes and
// a coordination server joined by a simulated internet, with two of the
// nodes behind separate NAT routers.
//
//	a (192.168.1.2) -- natA (10.0.0.2) --+
//	b (192.168.2.2) -- natB (10.0.0.3) --+-- wan bridge -- coord (10.0.0.1)
//	c (10.0.0.4) ------------------------+
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const prefix = "wl-"

var spaces = []string{"wan", "coord", "natA", "natB", "a", "b", "c"}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "lab: %s: %v\n", what, err)
		os.Exit(1)
	}
}

type lab struct {
	root netns.NsHandle
	ns   map[string]netns.NsHandle
}

// link creates a veth pair with one end in each namespace.
func (l *lab) link(nsA, ifA, nsB, ifB string) {
	tmpA, tmpB := "t"+nsA+ifA, "t"+nsB+ifB
	la := netlink.NewLinkAttrs()
	la.Name = tmpA
	must(netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: tmpB}), "veth "+tmpA)
	for _, e := range []struct{ tmp, ns, name string }{{tmpA, nsA, ifA}, {tmpB, nsB, ifB}} {
		lk, err := netlink.LinkByName(e.tmp)
		must(err, "find "+e.tmp)
		must(netlink.LinkSetNsFd(lk, int(l.ns[e.ns])), "move "+e.tmp)
		h := l.handle(e.ns)
		lk, err = h.LinkByName(e.tmp)
		must(err, "find moved "+e.tmp)
		must(h.LinkSetName(lk, e.name), "rename "+e.tmp)
		must(h.LinkSetUp(lk), "up "+e.name)
		h.Close()
	}
}

func (l *lab) handle(ns string) *netlink.Handle {
	h, err := netlink.NewHandleAt(l.ns[ns])
	must(err, "handle "+ns)
	return h
}

func (l *lab) addr(ns, ifc, cidr string) {
	h := l.handle(ns)
	defer h.Close()
	lk, err := h.LinkByName(ifc)
	must(err, "link "+ifc)
	a, err := netlink.ParseAddr(cidr)
	must(err, cidr)
	must(h.AddrAdd(lk, a), "addr "+cidr)
}

func (l *lab) gateway(ns, gw string) {
	h := l.handle(ns)
	defer h.Close()
	must(h.RouteAdd(&netlink.Route{Gw: net.ParseIP(gw)}), "default route in "+ns)
}

func up() {
	runtime.LockOSThread()
	root, err := netns.Get()
	must(err, "current netns")
	l := &lab{root: root, ns: map[string]netns.NsHandle{}}
	for _, n := range spaces {
		h, err := netns.NewNamed(prefix + n)
		must(err, "create netns "+n)
		l.ns[n] = h
		lo := l.handle(n)
		lk, err := lo.LinkByName("lo")
		must(err, "lo")
		must(lo.LinkSetUp(lk), "lo up")
		lo.Close()
	}
	must(netns.Set(root), "return to root netns")

	// The simulated internet is a bridge.
	h := l.handle("wan")
	la := netlink.NewLinkAttrs()
	la.Name = "br0"
	br := &netlink.Bridge{LinkAttrs: la}
	must(h.LinkAdd(br), "bridge")
	must(h.LinkSetUp(br), "bridge up")
	for i, peer := range []string{"coord", "natA", "natB", "c"} {
		port := fmt.Sprintf("p%d", i)
		l.link("wan", port, peer, "wan")
		lk, err := h.LinkByName(port)
		must(err, port)
		must(h.LinkSetMaster(lk, br), "enslave "+port)
	}
	h.Close()
	l.link("natA", "lan", "a", "eth0")
	l.link("natB", "lan", "b", "eth0")

	l.addr("coord", "wan", "10.0.0.1/24")
	l.addr("natA", "wan", "10.0.0.2/24")
	l.addr("natB", "wan", "10.0.0.3/24")
	l.addr("c", "wan", "10.0.0.4/24")
	l.addr("natA", "lan", "192.168.1.1/24")
	l.addr("natB", "lan", "192.168.2.1/24")
	l.addr("a", "eth0", "192.168.1.2/24")
	l.addr("b", "eth0", "192.168.2.2/24")
	l.gateway("a", "192.168.1.1")
	l.gateway("b", "192.168.2.1")
}

func down() {
	for _, n := range spaces {
		netns.DeleteNamed(prefix + n)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: lab up|down")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "up":
		down()
		up()
	case "down":
		down()
	default:
		os.Exit(2)
	}
}
