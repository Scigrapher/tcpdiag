//go:build windows

package discovery

import (
	"net"
	"syscall"
	"unsafe"
)

var (
	ws2        = syscall.NewLazyDLL("ws2_32.dll")
	setsockopt = ws2.NewProc("setsockopt")
)

const (
	soLSocket        = 0xffff
	ipProtoIP        = 0
	ipAddMembership  = 12
	soReuseAddr      = 0x0004
	soBroadcast      = 0x0020
	soRecvBufferSize = 0x1002
)

type ipMreq struct {
	multiaddr  [4]byte
	interface_ [4]byte
}

// control returns a ListenConfig.Control hook that enables address reuse,
// broadcast, and joins the multicast group on one specific interface.
func control(groupIP, ifIP net.IP, broadcast bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			set := func(level, opt int, val int32) {
				v := val
				r, _, e := setsockopt.Call(fd, uintptr(level), uintptr(opt),
					uintptr(unsafe.Pointer(&v)), 4)
				if r != 0 {
					opErr = e
				}
			}
			set(soLSocket, soReuseAddr, 1)
			set(soLSocket, soBroadcast, boolInt(broadcast))
			buf := 4 << 20
			r, _, _ := setsockopt.Call(fd, uintptr(ipProtoIP), uintptr(soRecvBufferSize),
				uintptr(unsafe.Pointer(&buf)), 4)
			_ = r
			if groupIP != nil {
				var m ipMreq
				copy(m.multiaddr[:], groupIP.To4())
				copy(m.interface_[:], ifIP.To4())
				r, _, e := setsockopt.Call(fd, uintptr(ipProtoIP), uintptr(ipAddMembership),
					uintptr(unsafe.Pointer(&m)), unsafe.Sizeof(m))
				if r != 0 {
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

func boolInt(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
