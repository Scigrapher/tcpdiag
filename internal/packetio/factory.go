package packetio

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"
)

// Available reports the raw backends this platform can offer, best first.
func Available() []string {
	if runtime.GOOS == "windows" {
		return []string{"windows-rawsock+npcap (SIO_RCVALL capture + Npcap injection; Administrator and Npcap required)", "sim"}
	}
	if runtime.GOOS == "linux" {
		return []string{"linux-afpacket (AF_PACKET, root/CAP_NET_RAW)", "sim"}
	}
	return []string{"sim"}
}

// Open selects a backend. "auto" prefers the privileged platform backend and
// reports why it declined if it is unavailable, so the caller can degrade to
// kernel-stack mode with an actionable message instead of a hard failure.
func Open(o Options) (Engine, error) {
	switch o.Backend {
	case "sim":
		if o.Sim == nil {
			return nil, fmt.Errorf("backend sim requires Options.Sim")
		}
		return o.Sim, nil
	case "windows", "windows-rawsock", "npcap", "windows-npcap":
		return openWindows(o)
	case "linux", "afpacket", "linux-afpacket":
		return openLinux(o)
	case "", "auto":
		return tryPlatform(o)
	default:
		return nil, fmt.Errorf("unknown packet backend %q (available: %v)", o.Backend, Available())
	}
}

func tryPlatform(o Options) (Engine, error) {
	switch runtime.GOOS {
	case "windows":
		return openWindows(o)
	case "linux":
		return openLinux(o)
	default:
		return nil, fmt.Errorf("%w: platform %s has no privileged capture backend; use --stack=kernel or --backend=sim", ErrNoRawBackend, runtime.GOOS)
	}
}

// ---------------------------------------------------------------------------
// Impairment wrapper
// ---------------------------------------------------------------------------

type impairEngine struct {
	Engine
	im    *Impairment
	rng   *rand.Rand
	mu    sync.Mutex
	drops uint64
	dups  uint64
	holds uint64
	in    chan *Packet
	done  chan struct{}
	once  sync.Once
}

// WithImpairment wraps an engine so locally observed traffic exhibits the
// requested defects. Egress defects are applied before transmission, ingress
// defects after capture, so the stack under test genuinely has to cope.
func WithImpairment(e Engine, im *Impairment) Engine {
	if !im.Enabled() {
		return e
	}
	w := &impairEngine{
		Engine: e,
		im:     im,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		in:     make(chan *Packet, 8192),
		done:   make(chan struct{}),
	}
	go w.ingest()
	return w
}

func (w *impairEngine) Name() string     { return w.Engine.Name() + "+impair" }
func (w *impairEngine) Injectable() bool { return w.Engine.Injectable() }

func (w *impairEngine) Capabilities() []string {
	return append(w.Engine.Capabilities(), "impairment("+w.im.String()+")")
}

func (w *impairEngine) roll(pct float64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rng.Float64()*100 < pct
}

func (w *impairEngine) jitter() time.Duration {
	im := w.im
	if im.Jitter <= 0 {
		return 0
	}
	w.mu.Lock()
	d := w.rng.Int63n(int64(2*im.Jitter) + 1)
	w.mu.Unlock()
	return time.Duration(d) - im.Jitter
}

func (w *impairEngine) Send(ipPacket []byte) error {
	im := w.im
	if im.LossPct > 0 && w.roll(im.LossPct) {
		w.mu.Lock()
		w.drops++
		w.mu.Unlock()
		return nil
	}
	if im.Delay > 0 || im.Jitter > 0 {
		d := im.Delay + w.jitter()
		if d > 0 {
			time.Sleep(d)
		}
	}
	if im.RateMbps > 0 {
		w.mu.Lock()
		hold := time.Duration(float64(len(ipPacket)*8) / (im.RateMbps * 1e6) * float64(time.Second))
		w.mu.Unlock()
		if hold > 0 {
			time.Sleep(hold)
		}
	}
	if err := w.Engine.Send(ipPacket); err != nil {
		return err
	}
	if im.DupPct > 0 && w.roll(im.DupPct) {
		w.mu.Lock()
		w.dups++
		w.mu.Unlock()
		_ = w.Engine.Send(ipPacket)
	}
	return nil
}

func (w *impairEngine) ingest() {
	src := w.Engine.Recv()
	im := w.im
	for {
		select {
		case <-w.done:
			return
		case p, ok := <-src:
			if !ok {
				return
			}
			if im.LossPct > 0 && w.roll(im.LossPct) {
				w.mu.Lock()
				w.drops++
				w.mu.Unlock()
				continue
			}
			if im.DupPct > 0 && w.roll(im.DupPct) {
				dup := *p
				dup.Buf = append([]byte{}, p.Buf...)
				w.mu.Lock()
				w.dups++
				w.mu.Unlock()
				select {
				case w.in <- &dup:
				case <-w.done:
					return
				}
			}
			delay := im.Delay + w.jitter()
			if im.ReorderPct > 0 && w.roll(im.ReorderPct) {
				if delay <= 0 {
					delay = 200 * time.Microsecond
				}
				delay += time.Duration(1+w.rng.Int63n(7)) * delay
				w.mu.Lock()
				w.holds++
				w.mu.Unlock()
			}
			if delay > 0 {
				pk := *p
				go func(d time.Duration, pk *Packet) {
					t := time.NewTimer(d)
					defer t.Stop()
					select {
					case <-t.C:
						select {
						case w.in <- pk:
						case <-w.done:
						}
					case <-w.done:
					}
				}(delay, &pk)
				continue
			}
			select {
			case w.in <- p:
			case <-w.done:
				return
			}
		}
	}
}

func (w *impairEngine) Recv() <-chan *Packet { return w.in }

func (w *impairEngine) Close() error {
	w.once.Do(func() { close(w.done) })
	return w.Engine.Close()
}
