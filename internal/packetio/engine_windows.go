//go:build windows

package packetio

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	ws2             = syscall.NewLazyDLL("ws2_32.dll")
	procWSAStartup  = ws2.NewProc("WSAStartup")
	procSocket      = ws2.NewProc("socket")
	procCloseSocket = ws2.NewProc("closesocket")
	procBind        = ws2.NewProc("bind")
	procWSAIoctl    = ws2.NewProc("WSAIoctl")
	procRecvFrom    = ws2.NewProc("recvfrom")
)

const (
	afInet     = 2
	soSockRaw  = 3
	ipProtoIP  = 0
	sioRcvAll  = 0x98000001
	rcvAllOn   = 1
	sockLenRaw = 1 << 16
	wsaEACCES  = 10013
)

var initWSAOnce sync.Once

type sockaddrIn struct {
	sinFamily uint16
	sinPort   uint16
	sinAddr   uint32
	sinZero   [8]byte
}

func wsaStartup() error {
	var err error
	initWSAOnce.Do(func() {
		var data struct {
			major, minor uint16
			fixup        [8]byte
			sockinfo     *byte
			cpu, vers    uint16
		}
		r, _, e := procWSAStartup.Call(uintptr(0x0202), uintptr(unsafe.Pointer(&data)))
		if r != 0 {
			err = fmt.Errorf("WSAStartup failed: %d/%w", r, e)
		}
	})
	return err
}

func v4ToNBO(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func eno(e error) int {
	if ne, ok := e.(syscall.Errno); ok {
		return int(ne)
	}
	return -1
}

// injectMode describes how much control the inject socket actually got.
type injectMode int

const (
	injectNone  injectMode = iota
	injectNpcap            // Npcap L2 injection
)

func (m injectMode) String() string {
	switch m {
	case injectNpcap:
		return "Npcap (wpcap.dll L2 injection)"
	}
	return "unavailable (capture only)"
}

// winEngine captures with SIO_RCVALL and injects with Npcap. Modern Windows
// accepts raw-socket TCP sendto calls but drops the packets, so Npcap is the
// only reliable raw TCP transmit path.
type winEngine struct {
	mu        sync.Mutex
	name      string
	localIP   netip.Addr
	capture   syscall.Handle
	npcap     *npcapInjector
	mode      injectMode
	injectErr error
	in        chan *Packet
	done      chan struct{}
	once      sync.Once
	captured  uint64
	injected  uint64
	dropped   uint64
	l2Frames  uint64
	l2NonIP   uint64
}

func openWindows(o Options) (Engine, error) {
	if err := wsaStartup(); err != nil {
		return nil, err
	}
	ip := o.LocalIP
	if !ip.Is4() {
		return nil, fmt.Errorf("windows raw backend needs an IPv4 local address, got %s", ip)
	}
	e := &winEngine{
		name:    "windows-rawsock",
		localIP: ip,
		in:      make(chan *Packet, 8192),
		done:    make(chan struct{}),
	}

	// --- capture: SOCK_RAW + SIO_RCVALL ----------------------------------
	cs, _, errno := procSocket.Call(afInet, soSockRaw, ipProtoIP)
	if int(cs) == -1 || int(cs) == ^int(0) {
		return nil, fmt.Errorf("socket(SOCK_RAW) failed: %w (raw capture requires an elevated shell)", errno)
	}
	e.capture = syscall.Handle(cs)

	sa := sockaddrIn{sinFamily: afInet, sinPort: 0, sinAddr: v4ToNBO(ip)}
	if r, _, errno := procBind.Call(uintptr(e.capture), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); r != 0 {
		procCloseSocket.Call(uintptr(e.capture))
		return nil, fmt.Errorf("bind(%s) on raw socket failed: %w", ip, errno)
	}
	var bytesReturned uint32
	on := uint32(rcvAllOn)
	if r, _, errno := procWSAIoctl.Call(
		uintptr(e.capture), sioRcvAll,
		uintptr(unsafe.Pointer(&on)), 4,
		0, 0, uintptr(unsafe.Pointer(&bytesReturned)), 0, 0); r != 0 {
		procCloseSocket.Call(uintptr(e.capture))
		if eno(errno) == wsaEACCES {
			return nil, fmt.Errorf("SIO_RCVALL denied (WSAEACCES): run tcpdiag from an elevated (Administrator) prompt to capture packets")
		}
		return nil, fmt.Errorf("SIO_RCVALL failed: %w", errno)
	}

	// --- inject: try progressively weaker forms --------------------------
	e.openInjector(ip)

	go e.captureLoop()
	return e, nil
}

// openInjector opens Npcap for layer-2 injection. Windows raw sockets accept
// TCP sendto calls but drop the packets (Microsoft's raw-socket restriction),
// so there is no raw-socket fallback that can work for TCP.
func (e *winEngine) openInjector(ip netip.Addr) {
	inj, err := newNpcapInjector(ip)
	if err != nil {
		e.mode = injectNone
		e.injectErr = err
		return
	}
	e.npcap = inj
	e.mode = injectNpcap
}

func (e *winEngine) captureLoop() {
	buf := make([]byte, sockLenRaw)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		select {
		case <-e.done:
			return
		default:
		}
		got, _, errno := procRecvFrom.Call(uintptr(e.capture), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0, 0)
		// recvfrom returns SOCKET_ERROR (-1) on failure. On 64-bit Windows the
		// syscall wrapper can surface that as 0x00000000FFFFFFFF rather than
		// ^uintptr(0), so an int conversion is positive and must not be used as
		// a slice length or allocation size.
		if !validRecvLen(got, len(buf)) {
			select {
			case <-e.done:
				return
			default:
			}
			if eno(errno) != 10040 {
				e.mu.Lock()
				e.dropped++
				e.mu.Unlock()
				time.Sleep(time.Millisecond)
			}
			continue
		}
		n := int(got)
		raw := make([]byte, n)
		copy(raw, buf[:n])
		// Some filter/virtual adapters hand over Ethernet framed data even
		// though SIO_RCVALL is supposed to deliver bare IP. Normalise so the
		// pcap link type is always right and Wireshark cannot mislabel it.
		payload, hadL2, _ := StripL2(raw)
		if !IsIP(payload) {
			e.mu.Lock()
			e.dropped++
			if hadL2 {
				e.l2NonIP++
			}
			e.mu.Unlock()
			continue
		}
		if hadL2 {
			e.mu.Lock()
			e.l2Frames++
			e.mu.Unlock()
		}
		b := make([]byte, len(payload))
		copy(b, payload)
		p := &Packet{Buf: b, At: time.Now()}
		p.NanoAt = p.At.UnixNano()
		e.mu.Lock()
		e.captured++
		e.mu.Unlock()
		select {
		case e.in <- p:
		case <-e.done:
			return
		default:
			e.mu.Lock()
			e.dropped++
			e.mu.Unlock()
		}
	}
}

// validRecvLen rejects both zero-length reads and Windows SOCKET_ERROR, which
// can arrive as 0xFFFFFFFF instead of a negative int on 64-bit builds.
func validRecvLen(n uintptr, cap int) bool {
	return n > 0 && n <= uintptr(cap)
}

// Send transmits a complete IPv4 packet through Npcap at layer 2.
func (e *winEngine) Send(ipPacket []byte) error {
	e.mu.Lock()
	mode := e.mode
	inj := e.npcap
	e.mu.Unlock()
	if mode == injectNone {
		return fmt.Errorf("packet injection unavailable on this host (%v); observe mode still works", e.injectErr)
	}
	if err := inj.Send(ipPacket); err != nil {
		return err
	}
	e.mu.Lock()
	e.injected++
	e.mu.Unlock()
	return nil
}

func (e *winEngine) Recv() <-chan *Packet { return e.in }
func (e *winEngine) LocalIP() netip.Addr  { return e.localIP }
func (e *winEngine) Injectable() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mode != injectNone
}
func (e *winEngine) Name() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.mode {
	case injectNpcap:
		return e.name + "+npcap"
	}
	return e.name + "-capture"
}

func (e *winEngine) Capabilities() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []string{
		fmt.Sprintf("capture=%d injected=%d ring-drops=%d", e.captured, e.injected, e.dropped),
		fmt.Sprintf("ethernet-framed buffers normalised=%d non-IP dropped=%d", e.l2Frames, e.l2NonIP),
		"SIO_RCVALL promiscuous capture",
		"injection: " + e.mode.String(),
	}
	if e.injectErr != nil && e.mode != injectNpcap {
		out = append(out, "Npcap injection unavailable: "+e.injectErr.Error())
	}
	if e.mode == injectNone {
		out = append(out, "install Npcap (included with Wireshark) for raw TCP injection; --stack=observe still works for capture-only analysis")
	} else {
		out = append(out, "requires Administrator privileges")
	}
	return out
}

func (e *winEngine) Close() error {
	e.once.Do(func() {
		close(e.done)
		if e.capture != 0 {
			off := uint32(0)
			var br uint32
			procWSAIoctl.Call(uintptr(e.capture), sioRcvAll, uintptr(unsafe.Pointer(&off)), 4, 0, 0, uintptr(unsafe.Pointer(&br)), 0, 0)
			procCloseSocket.Call(uintptr(e.capture))
		}
		if e.npcap != nil {
			_ = e.npcap.Close()
		}
	})
	return nil
}
