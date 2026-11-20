//go:build !linux

package platform

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
)

// Default paths. On Windows these resolve under %ProgramData%.
var (
	DefaultStateDir = filepath.Join(base(), "wyrm")
	DefaultRunDir   = filepath.Join(base(), "wyrm", "run")
	DefaultCoordDir = filepath.Join(base(), "wyrm-coord")
)

func base() string {
	if d := os.Getenv("ProgramData"); d != "" {
		return d
	}
	return os.TempDir()
}

// ErrUnsupported marks functionality not yet ported to this system.
var ErrUnsupported = errors.New("platform: not implemented on this operating system")

// ConfigureInterface is the porting seam for interface addressing. The
// Windows implementation belongs here (winipcfg / IP Helper API).
func ConfigureInterface(name string, addr netip.Prefix, mtu int) error {
	return ErrUnsupported
}

// RestrictSocket is the porting seam for local API access control. On
// Windows the socket ACL is inherited from its directory.
func RestrictSocket(path string, gid int, mode os.FileMode) error {
	return nil
}
