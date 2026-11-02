//go:build windows

package netstd

import (
	"fmt"

	"github.com/easytier/easytier/easytier-go/platform"
	"golang.org/x/sys/windows"
)

func applySocketOptions(
	descriptor uintptr,
	network string,
	options platform.BindConfig,
) error {
	if options.ReusePort && !options.ReuseAddr {
		return fmt.Errorf("socket reuse_port requires reuse_addr on Windows")
	}
	if options.ReuseAddr {
		if err := windows.SetsockoptInt(windows.Handle(descriptor),
			windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			return fmt.Errorf("set socket SO_REUSEADDR: %w", err)
		}
	}
	if options.OnlyV6 && (network == "tcp6" || network == "udp6") {
		if err := windows.SetsockoptInt(windows.Handle(descriptor),
			windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
			return fmt.Errorf("set socket IPV6_V6ONLY: %w", err)
		}
	}
	return nil
}
