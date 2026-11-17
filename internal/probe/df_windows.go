//go:build windows

package probe

import (
	"syscall"
	"unsafe"
)

var (
	ws2b           = syscall.NewLazyDLL("ws2_32.dll")
	setsockoptProc = ws2b.NewProc("setsockopt")
)

const (
	ipProtoIPv4    = 0
	ipDontFragment = 22 // IP_DONTFRAGMENT on Windows
)

// dfControl returns a Dialer.Control hook that sets the DF bit on outbound
// datagrams so the path refuses to fragment and reports its real MTU.
func dfControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			one := int32(1)
			r, _, e := setsockoptProc.Call(fd, uintptr(ipProtoIPv4), uintptr(ipDontFragment),
				uintptr(unsafe.Pointer(&one)), 4)
			if r != 0 {
				opErr = e
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
