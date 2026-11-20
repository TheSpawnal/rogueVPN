// Package platform isolates everything that differs between operating
// systems: TUN creation, interface addressing and default paths. Linux is
// implemented; other systems compile against stubs so the rest of the code
// base stays portable.
package platform

import (
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// CreateTUN opens a layer-3 tunnel device. The wireguard-go tun package
// already covers Linux (/dev/net/tun), Windows (Wintun), macOS and the BSDs.
func CreateTUN(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

// LocalAddrs returns the unicast addresses of all interfaces that are up,
// skipping loopback, link-local addresses and the named interface.
func LocalAddrs(skipIface string) []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Name == skipIface || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}
