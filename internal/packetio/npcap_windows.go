//go:build windows

package packetio

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Npcap is required for raw TCP transmission on modern Windows: the OS accepts
// raw-socket sendto calls but drops TCP data (Microsoft's raw-socket
// restriction). Npcap injects at layer 2, which is the only practical path
// without a custom kernel driver. It is normally installed with Wireshark.

var (
	npcapLoadOnce sync.Once
	npcapDLL      *syscall.DLL
	npcapLoadErr  error

	npcapFind  *syscall.Proc
	npcapFree  *syscall.Proc
	npcapOpen  *syscall.Proc
	npcapSend  *syscall.Proc
	npcapClose *syscall.Proc
)

var procSetDllDirectory = syscall.NewLazyDLL("kernel32.dll").NewProc("SetDllDirectoryW")

type npcapIf struct {
	next        *npcapIf
	name        *byte
	description *byte
	addresses   *npcapAddr
	flags       uint32
}

type npcapAddr struct {
	next      *npcapAddr
	addr      *sockaddrIn
	netmask   *sockaddrIn
	broadaddr *sockaddrIn
	dstaddr   *sockaddrIn
}

type npcapDevice struct {
	Name        string
	Description string
	IPs         []netip.Addr
}

func loadNpcap() error {
	npcapLoadOnce.Do(func() {
		var paths []string
		if runtime.GOARCH == "386" {
			paths = []string{
				`C:\Windows\SysWOW64\Npcap\wpcap.dll`,
				`C:\Windows\SysWOW64\wpcap.dll`,
			}
		} else {
			paths = []string{
				`C:\Windows\System32\Npcap\wpcap.dll`,
				`C:\Windows\System32\wpcap.dll`,
			}
		}
		// wpcap.dll depends on Packet.dll and the Npcap driver DLLs in the same
		// directory. Windows does not search that directory by default.
		dir := `C:\Windows\System32\Npcap`
		if runtime.GOARCH == "386" {
			dir = `C:\Windows\SysWOW64\Npcap`
		}
		if dirPtr, err := syscall.UTF16PtrFromString(dir); err == nil {
			procSetDllDirectory.Call(uintptr(unsafe.Pointer(dirPtr)))
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			dll, err := syscall.LoadDLL(p)
			if err != nil {
				npcapLoadErr = err
				continue
			}
			npcapDLL = dll
			break
		}
		if npcapDLL == nil {
			dll, err := syscall.LoadDLL("wpcap.dll")
			if err != nil {
				npcapLoadErr = fmt.Errorf("Npcap wpcap.dll not found: %w", err)
				return
			}
			npcapDLL = dll
		}
		for name, target := range map[string]**syscall.Proc{
			"pcap_findalldevs": &npcapFind,
			"pcap_freealldevs": &npcapFree,
			"pcap_open_live":   &npcapOpen,
			"pcap_sendpacket":  &npcapSend,
			"pcap_close":       &npcapClose,
		} {
			p, err := npcapDLL.FindProc(name)
			if err != nil {
				npcapLoadErr = fmt.Errorf("Npcap %s: %w", name, err)
				return
			}
			*target = p
		}
	})
	return npcapLoadErr
}

func cStringPtr(p *byte) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}

func npcapDevices() ([]npcapDevice, error) {
	if err := loadNpcap(); err != nil {
		return nil, err
	}
	var list *npcapIf
	errbuf := make([]byte, 256)
	r, _, _ := npcapFind.Call(uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(r) != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", cStringPtr(&errbuf[0]))
	}
	defer npcapFree.Call(uintptr(unsafe.Pointer(list)))
	var out []npcapDevice
	for it := list; it != nil; it = it.next {
		d := npcapDevice{Name: cStringPtr(it.name), Description: cStringPtr(it.description)}
		for a := it.addresses; a != nil; a = a.next {
			if a.addr == nil || a.addr.sinFamily != afInet {
				continue
			}
			b := (*[4]byte)(unsafe.Pointer(&a.addr.sinAddr))
			if ip, ok := netip.AddrFromSlice(b[:]); ok {
				d.IPs = append(d.IPs, ip)
			}
		}
		out = append(out, d)
	}
	return out, nil
}

type npcapInjector struct {
	handle   uintptr
	device   string
	localIP  netip.Addr
	localMAC net.HardwareAddr
	mu       sync.Mutex
	arp      map[netip.Addr]npcapARP
}

type npcapARP struct {
	mac net.HardwareAddr
	at  time.Time
}

var procSendARP = syscall.NewLazyDLL("iphlpapi.dll").NewProc("SendARP")

func newNpcapInjector(localIP netip.Addr) (*npcapInjector, error) {
	devs, err := npcapDevices()
	if err != nil {
		return nil, err
	}
	var chosen *npcapDevice
	for i := range devs {
		for _, ip := range devs[i].IPs {
			if ip == localIP {
				chosen = &devs[i]
				break
			}
		}
		if chosen != nil {
			break
		}
	}
	if chosen == nil {
		var names []string
		for _, d := range devs {
			names = append(names, fmt.Sprintf("%s (%v)", d.Description, d.IPs))
		}
		return nil, fmt.Errorf("Npcap: no device with local IP %s; devices: %v", localIP, names)
	}
	mac, err := localHardwareAddr(localIP)
	if err != nil {
		return nil, err
	}
	namePtr, err := syscall.BytePtrFromString(chosen.Name)
	if err != nil {
		return nil, err
	}
	errbuf := make([]byte, 256)
	h, _, _ := npcapOpen.Call(
		uintptr(unsafe.Pointer(namePtr)),
		65536,
		0,
		100,
		uintptr(unsafe.Pointer(&errbuf[0])))
	if h == 0 {
		return nil, fmt.Errorf("pcap_open_live(%s): %s", chosen.Description, cStringPtr(&errbuf[0]))
	}
	return &npcapInjector{
		handle:   h,
		device:   chosen.Name,
		localIP:  localIP,
		localMAC: mac,
		arp:      map[netip.Addr]npcapARP{},
	}, nil
}

func localHardwareAddr(ip netip.Addr) (net.HardwareAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifi := range ifs {
		if len(ifi.HardwareAddr) < 6 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := n.IP.To4()
			if v4 == nil {
				continue
			}
			if got, ok := netip.AddrFromSlice(v4); ok && got == ip {
				return ifi.HardwareAddr, nil
			}
		}
	}
	return nil, fmt.Errorf("no hardware address for %s", ip)
}

func (n *npcapInjector) Send(ipPacket []byte) error {
	dst, err := DstAddr(ipPacket)
	if err != nil {
		return err
	}
	mac, err := n.dstMAC(dst)
	if err != nil {
		return err
	}
	frame := make([]byte, 14+len(ipPacket))
	copy(frame[0:6], mac)
	copy(frame[6:12], n.localMAC)
	frame[12], frame[13] = 0x08, 0x00
	copy(frame[14:], ipPacket)
	n.mu.Lock()
	defer n.mu.Unlock()
	r, _, _ := npcapSend.Call(n.handle, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if int32(r) != 0 {
		return fmt.Errorf("pcap_sendpacket to %s: error %d (is the Npcap driver running?)", dst, int32(r))
	}
	return nil
}

func (n *npcapInjector) dstMAC(dst netip.Addr) (net.HardwareAddr, error) {
	n.mu.Lock()
	if e, ok := n.arp[dst]; ok && time.Since(e.at) < time.Minute {
		mac := e.mac
		n.mu.Unlock()
		return mac, nil
	}
	n.mu.Unlock()
	mac, err := sendARP(dst, n.localIP)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.arp[dst] = npcapARP{mac: mac, at: time.Now()}
	n.mu.Unlock()
	return mac, nil
}

func sendARP(dst, src netip.Addr) (net.HardwareAddr, error) {
	var mac [8]byte
	n := uint32(len(mac))
	r, _, _ := procSendARP.Call(
		uintptr(v4ToNBO(dst)),
		uintptr(v4ToNBO(src)),
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&n)))
	if r != 0 {
		return nil, fmt.Errorf("SendARP(%s): Windows error %d (Npcap injection needs the peer on the local subnet)", dst, r)
	}
	if n < 6 {
		return nil, errors.New("SendARP returned a short hardware address")
	}
	return net.HardwareAddr(append([]byte{}, mac[:6]...)), nil
}

func (n *npcapInjector) Close() error {
	if n == nil || n.handle == 0 {
		return nil
	}
	npcapClose.Call(n.handle)
	n.handle = 0
	return nil
}
