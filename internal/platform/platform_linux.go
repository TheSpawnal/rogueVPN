//go:build linux

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
)

// Default paths.
const (
	DefaultStateDir = "/var/lib/wyrm"
	DefaultRunDir   = "/run/wyrm"
	DefaultCoordDir = "/var/lib/wyrm-coord"
)

// ConfigureInterface assigns addr to the interface, sets its MTU and brings
// it up. The prefix length of addr yields the on-link route for the mesh.
func ConfigureInterface(name string, addr netip.Prefix, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	ipn := &net.IPNet{
		IP:   addr.Addr().AsSlice(),
		Mask: net.CIDRMask(addr.Bits(), addr.Addr().BitLen()),
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: ipn}); err != nil {
		return fmt.Errorf("addr %s: %w", addr, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("mtu: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("up: %w", err)
	}
	return nil
}

// RestrictSocket applies owner/group/mode to a unix socket path. gid < 0
// leaves the group unchanged.
func RestrictSocket(path string, gid int, mode os.FileMode) error {
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}
