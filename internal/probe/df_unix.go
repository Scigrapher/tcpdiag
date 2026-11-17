//go:build !windows

package probe

import "syscall"

const (
	ipMTUDiscover = 10
	ipPMTUDiscDo  = 2
)

// dfControl returns a Dialer.Control hook that enables RFC 1191 path MTU
// discovery, so oversized datagrams produce EMSGSIZE instead of being quietly
// fragmented.
func dfControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			f := int(fd)
			if e := syscall.SetsockoptInt(f, syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo); e != nil {
				opErr = e
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
