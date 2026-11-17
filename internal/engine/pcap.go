package engine

import (
	"bufio"
	"encoding/binary"
	"hash/fnv"
	"os"
	"sync"
	"time"
)

// DLT_RAW / DLT_EN10MB link types.
const (
	DLTRaw   = 101
	DLTEther = 1
)

// PCAPFilter limits a capture to the ports tcpdiag itself uses. Without this,
// SIO_RCVALL/AF_PACKET hand over every connection the host has open, so a
// capture of one diagnostic session is buried in unrelated traffic.
type PCAPFilter struct {
	mu    sync.RWMutex
	ports map[uint16]struct{}
}

// NewPCAPFilter builds a port filter. A nil filter matches everything.
func NewPCAPFilter(ports []uint16) *PCAPFilter {
	f := &PCAPFilter{ports: make(map[uint16]struct{}, len(ports))}
	for _, p := range ports {
		if p != 0 {
			f.ports[p] = struct{}{}
		}
	}
	return f
}

// Match reports whether an IPv4 packet belongs to a tcpdiag flow. TCP and UDP
// are matched by port. ICMP errors are matched through the quoted packet, which
// is how the TTL walk's time-exceeded replies stay in the file.
func (f *PCAPFilter) Match(ip []byte) bool {
	if f == nil {
		return true
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.ports) == 0 {
		return true
	}
	return f.matchIPv4(ip)
}

// AddPorts extends the filter after discovery. Peers may advertise ports that
// differ from this instance's defaults, and those flows must stay in the pcap.
func (f *PCAPFilter) AddPorts(ports ...uint16) {
	if f == nil || len(ports) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range ports {
		if p != 0 {
			f.ports[p] = struct{}{}
		}
	}
}

func (f *PCAPFilter) matchIPv4(ip []byte) bool {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return false
	}
	switch ip[9] {
	case 6, 17: // TCP, UDP
		return f.matchPorts(ip[ihl:])
	case 1: // ICMP: errors quote the packet that triggered them.
		if len(ip[ihl:]) < 8 {
			return false
		}
		return f.matchIPv4(ip[ihl+8:])
	}
	return false
}

func (f *PCAPFilter) matchPorts(l4 []byte) bool {
	if len(l4) < 4 {
		return false
	}
	sp := binary.BigEndian.Uint16(l4[0:2])
	dp := binary.BigEndian.Uint16(l4[2:4])
	_, okS := f.ports[sp]
	_, okD := f.ports[dp]
	return okS || okD
}

type packetSource int

const (
	sourceUnknown packetSource = iota
	sourceCaptured
	sourceInjected
)

const dedupeWindow = 2 * time.Second

// PCAPWriter emits classic libpcap files so everything the tool observed can
// be opened in Wireshark and compared against the tool's own conclusions.
type PCAPWriter struct {
	f          *os.File
	w          *bufio.Writer
	mu         sync.Mutex
	n          uint64
	link       int
	prependEth bool
	suspect    uint64
	filter     *PCAPFilter
	filtered   uint64
	injected   uint64
	duplicate  uint64
	recentCap  map[uint64]time.Time
	recentInj  map[uint64]time.Time
	lastPrune  time.Time
}

// OpenPCAP creates a pcap file.
func OpenPCAP(path string, linkType int) (*PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))
	p := &PCAPWriter{
		f: f, w: bufio.NewWriterSize(f, 1<<20), link: linkType, prependEth: linkType == DLTEther,
		recentCap: map[uint64]time.Time{}, recentInj: map[uint64]time.Time{},
	}
	if _, err := p.w.Write(hdr); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}

// SetFilter restricts subsequent captured/injected writes to matching flows.
// WritePacket (the raw test/helper API) is never filtered.
func (p *PCAPWriter) SetFilter(f *PCAPFilter) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.filter = f
	p.mu.Unlock()
}

// WritePacket appends one packet without filtering. It exists for callers that
// already know the packet is relevant, and for tests.
func (p *PCAPWriter) WritePacket(data []byte, at time.Time) error {
	return p.write(data, at, sourceUnknown)
}

// WriteCaptured appends a packet seen by the packet engine.
func (p *PCAPWriter) WriteCaptured(data []byte, at time.Time) error {
	return p.write(data, at, sourceCaptured)
}

// WriteInjected appends a packet tcpdiag transmitted itself. Some Windows
// capture paths do not deliver locally injected raw-socket packets back to
// SIO_RCVALL, which made a raw run look like it emitted only UDP control
// traffic. Recording the packet we built closes that blind spot.
func (p *PCAPWriter) WriteInjected(data []byte, at time.Time) error {
	return p.write(data, at, sourceInjected)
}

func (p *PCAPWriter) write(data []byte, at time.Time, source packetSource) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	filter := p.filter
	p.mu.Unlock()
	if source != sourceUnknown && filter != nil && !filter.Match(data) {
		p.mu.Lock()
		p.filtered++
		p.mu.Unlock()
		return nil
	}
	if len(data) > 262144 {
		data = data[:262144]
	}
	var ph [16]byte
	binary.LittleEndian.PutUint32(ph[0:4], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(ph[4:8], uint32(at.Nanosecond()))
	if p.prependEth {
		// Wireshark needs a link-layer framing it trusts. Prepending a minimal
		// Ethernet header with the IPv4 ethertype makes the dissection
		// unambiguous when the capture source supplies bare IP packets.
		encapped := make([]byte, 14+len(data))
		copy(encapped[0:6], []byte{0x02, 0, 0, 0, 0, 1})
		copy(encapped[6:12], []byte{0x02, 0, 0, 0, 0, 2})
		encapped[12] = 0x08
		encapped[13] = 0
		copy(encapped[14:], data)
		data = encapped
	}
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(ph[12:16], uint32(len(data)))
	p.mu.Lock()
	defer p.mu.Unlock()
	if source != sourceUnknown {
		now := time.Now()
		p.pruneLocked(now)
		key := packetKey(data)
		switch source {
		case sourceCaptured:
			if seen, ok := p.recentInj[key]; ok && now.Sub(seen) < dedupeWindow {
				p.duplicate++
				return nil
			}
			p.recentCap[key] = now
		case sourceInjected:
			if seen, ok := p.recentCap[key]; ok && now.Sub(seen) < dedupeWindow {
				p.duplicate++
				return nil
			}
			p.recentInj[key] = now
			p.injected++
		}
	}
	if !p.prependEth && !packetioIsIP(data) {
		// Writing a non-IP buffer into a DLT_RAW file is what makes Wireshark
		// read the first byte as an absurd IP version and dissect the traffic as
		// something it is not. Count it so this is visible instead of silent.
		p.suspect++
	}
	if _, err := p.w.Write(ph[:]); err != nil {
		return err
	}
	if _, err := p.w.Write(data); err != nil {
		return err
	}
	p.n++
	if p.n%512 == 0 {
		return p.w.Flush()
	}
	return nil
}

func (p *PCAPWriter) pruneLocked(now time.Time) {
	if now.Sub(p.lastPrune) < time.Second {
		return
	}
	p.lastPrune = now
	for k, t := range p.recentCap {
		if now.Sub(t) > dedupeWindow {
			delete(p.recentCap, k)
		}
	}
	for k, t := range p.recentInj {
		if now.Sub(t) > dedupeWindow {
			delete(p.recentInj, k)
		}
	}
}

// packetKey identifies the same bytes arriving through both the capture and
// injection paths. A retransmission gets a fresh IPv4 identification field from
// our stack, so it is not collapsed with the original.
func packetKey(data []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return h.Sum64()
}

// Suspect reports how many packets were written to a DLT_RAW file without
// beginning with an IP header. Non-zero means the capture source handed over
// link-layer framed data and the link type is wrong.
func (p *PCAPWriter) Suspect() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.suspect
}

// packetioIsIP avoids importing packetio here just for a header check.
func packetioIsIP(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	return b[0]>>4 == 4 && b[0]&0x0f >= 5 || b[0]>>4 == 6
}

func (p *PCAPWriter) Count() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// Filtered reports packets seen by the engine but deliberately left out of the
// file because they did not belong to a tcpdiag flow.
func (p *PCAPWriter) Filtered() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.filtered
}

// Injected reports packets added to the file from tcpdiag's own transmit path,
// rather than from the platform capture.
func (p *PCAPWriter) Injected() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.injected
}

// Duplicates reports packets suppressed because the capture and injection
// paths both delivered the same bytes.
func (p *PCAPWriter) Duplicates() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.duplicate
}

func (p *PCAPWriter) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.w.Flush(); err != nil {
		p.f.Close()
		return err
	}
	return p.f.Close()
}
