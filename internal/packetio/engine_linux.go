//go:build linux

package packetio

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// linuxEngine uses an AF_PACKET SOCK_RAW socket: full L2 capture and injection
// with no libpcap dependency (pure Go; needs root or CAP_NET_RAW).
type linuxEngine struct {
	mu       sync.Mutex
	name     string
	iface    *net.Interface
	localIP  netip.Addr
	fd       int
	in       chan *Packet
	done     chan struct{}
	once     sync.Once
	arp      map[netip.Addr]net.HardwareAddr
	arpWait  map[netip.Addr]chan struct{}
	captured uint64
	injected uint64
	dropped  uint64
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }

// addr8 pads a hardware address into the 8-byte field of SockaddrLinklayer.
func addr8(hw net.HardwareAddr) [8]byte {
	var a [8]byte
	copy(a[:], hw)
	return a
}

func openLinux(o Options) (Engine, error) {
	ifname := o.IfaceName
	if ifname == "" {
		n, err := routeInterface(o.LocalIP)
		if err != nil {
			return nil, err
		}
		ifname = n
	}
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", ifname, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w (raw mode needs root or CAP_NET_RAW)", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind(%s): %w", ifname, err)
	}
	e := &linuxEngine{
		name:    "linux-afpacket",
		iface:   ifi,
		localIP: o.LocalIP,
		fd:      fd,
		in:      make(chan *Packet, 8192),
		done:    make(chan struct{}),
		arp:     map[netip.Addr]net.HardwareAddr{},
		arpWait: map[netip.Addr]chan struct{}{},
	}
	e.warmARP()
	go e.captureLoop()
	return e, nil
}

// routeInterface finds the egress interface for target using a non-sending UDP
// connect, then matching the chosen source address back to an interface.
func routeInterface(target netip.Addr) (string, error) {
	if !target.Is4() {
		return "", fmt.Errorf("raw mode currently supports IPv4 only")
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(target.String(), "9"))
	if err != nil {
		return "", fmt.Errorf("cannot determine egress interface: %w", err)
	}
	defer conn.Close()
	src := conn.LocalAddr().(*net.UDPAddr).IP
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(src) {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("could not map source address %s to an interface", src)
}

func (e *linuxEngine) warmARP() {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] == "0x0" {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		hw, err := net.ParseMAC(f[3])
		if err != nil || len(hw) != 6 {
			continue
		}
		e.mu.Lock()
		e.arp[ip] = hw
		e.mu.Unlock()
	}
}

func (e *linuxEngine) captureLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-e.done:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(e.fd, buf, 0)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if n < 14 {
			continue
		}
		frame := buf[:n]
		switch binary.BigEndian.Uint16(frame[12:14]) {
		case 0x0806:
			e.learnARP(frame[14:])
			continue
		}
		// Normalise to a bare IP packet so the pcap link type is always right.
		payload, _, _ := StripL2(frame)
		if !IsIP(payload) {
			continue
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

func (e *linuxEngine) learnARP(a []byte) {
	if len(a) < 28 || binary.BigEndian.Uint16(a[6:8]) != 2 {
		return
	}
	spa, ok := netip.AddrFromSlice(a[14:18])
	if !ok {
		return
	}
	sha := net.HardwareAddr(append([]byte{}, a[8:14]...))
	e.mu.Lock()
	e.arp[spa] = sha
	ch := e.arpWait[spa]
	e.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (e *linuxEngine) resolve(dst netip.Addr) (net.HardwareAddr, error) {
	e.mu.Lock()
	if hw, ok := e.arp[dst]; ok {
		e.mu.Unlock()
		return hw, nil
	}
	ch, ok := e.arpWait[dst]
	if !ok {
		ch = make(chan struct{}, 1)
		e.arpWait[dst] = ch
	}
	e.mu.Unlock()

	if err := e.arpRequest(dst); err != nil {
		return nil, err
	}
	select {
	case <-ch:
		e.mu.Lock()
		hw := e.arp[dst]
		e.mu.Unlock()
		if hw != nil {
			return hw, nil
		}
	case <-time.After(2 * time.Second):
	}
	e.mu.Lock()
	delete(e.arpWait, dst)
	e.mu.Unlock()
	return nil, fmt.Errorf("ARP resolution failed for %s", dst)
}

func (e *linuxEngine) arpRequest(dst netip.Addr) error {
	if e.localIP == (netip.Addr{}) || !e.localIP.Is4() {
		return fmt.Errorf("no local IPv4 configured for ARP")
	}
	sh := e.iface.HardwareAddr
	if len(sh) != 6 {
		return fmt.Errorf("interface %s has no hardware address", e.iface.Name)
	}
	lb, db := e.localIP.As4(), dst.As4()
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], sh)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	a := frame[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], 1)
	copy(a[8:14], sh)
	copy(a[14:18], lb[:])
	copy(a[24:28], db[:])
	bc := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return syscall.Sendto(e.fd, frame, 0, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0806), Ifindex: e.iface.Index,
		Hatype: 1, Halen: 6, Addr: bc,
	})
}

func (e *linuxEngine) Send(ipPacket []byte) error {
	dst, err := DstAddr(ipPacket)
	if err != nil {
		return err
	}
	hw, err := e.resolve(dst)
	if err != nil {
		return err
	}
	frame := make([]byte, 14+len(ipPacket))
	copy(frame[0:6], hw)
	copy(frame[6:12], e.iface.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], ipPacket)
	if err := syscall.Sendto(e.fd, frame, 0, &syscall.SockaddrLinklayer{
		Protocol: htons(0x0800), Ifindex: e.iface.Index,
		Hatype: 1, Halen: 6, Addr: addr8(hw),
	}); err != nil {
		return fmt.Errorf("sendto(%s): %w", dst, err)
	}
	e.mu.Lock()
	e.injected++
	e.mu.Unlock()
	return nil
}

func (e *linuxEngine) Recv() <-chan *Packet { return e.in }
func (e *linuxEngine) LocalIP() netip.Addr  { return e.localIP }
func (e *linuxEngine) Name() string         { return e.name }
func (e *linuxEngine) Injectable() bool     { return true }

func (e *linuxEngine) Capabilities() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return []string{
		fmt.Sprintf("iface=%s captured=%d injected=%d ring-drops=%d", e.iface.Name, e.captured, e.injected, e.dropped),
		"AF_PACKET SOCK_RAW full L2 capture and injection",
		"built-in ARP resolver",
		"requires root or CAP_NET_RAW",
	}
}

func (e *linuxEngine) Close() error {
	e.once.Do(func() {
		close(e.done)
		syscall.Close(e.fd)
	})
	return nil
}
