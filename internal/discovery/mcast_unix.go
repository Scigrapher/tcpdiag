//go:build !windows

package discovery

import (
	"net"
	"syscall"
)

// control returns a ListenConfig.Control hook that enables address reuse,
// broadcast, and joins the multicast group on one specific interface.
func control(groupIP, ifIP net.IP, broadcast bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			f := int(fd)
			if e := syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
				opErr = e
			}
			if broadcast {
				if e := syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); e != nil {
					opErr = e
				}
			}
			// A large receive buffer keeps bursts of beacons from being dropped.
			_ = syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
			if groupIP != nil && groupIP.To4() != nil && ifIP != nil && ifIP.To4() != nil {
				var m syscall.IPMreq
				copy(m.Multiaddr[:], groupIP.To4())
				copy(m.Interface[:], ifIP.To4())
				if e := syscall.SetsockoptIPMreq(f, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, &m); e != nil {
					opErr = e
				}
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
