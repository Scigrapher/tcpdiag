package report

import (
	"fmt"
	"net"
	"strings"

	"tcpdiag/internal/wire"
)

// StackPair holds one stack's view of the conversation. Running the kernel
// stack and the custom stack side by side is what separates a path problem
// from a stack/offload problem, so the report compares them itself instead of
// telling the user to do it by hand.
type StackPair struct {
	Stack string         `json:"stack"`
	Local *wire.Snapshot `json:"local,omitempty"`
	Peer  *wire.Snapshot `json:"peer,omitempty"`
}

// lossPct approximates the retransmission rate of one stack.
func lossPct(s *wire.Snapshot) float64 {
	if s == nil {
		return 0
	}
	base := s.SegsSent
	if base == 0 {
		base = s.BytesSent / 1400
	}
	return pct(s.RetransSent, base)
}

// StackComparison diffs the kernel and custom-stack measurements of the same
// path. Divergence is the finding; agreement means the path is implicated.
func StackComparison(kernel, raw *StackPair) []Finding {
	if kernel == nil || raw == nil {
		return nil
	}
	if kernel.Local == nil || raw.Local == nil {
		return nil
	}
	k, r := kernel.Local, raw.Local
	kernelLoss, rawLoss := lossPct(k), lossPct(r)
	var out []Finding

	switch {
	case kernelLoss > 0.2 && rawLoss < kernelLoss/3:
		out = append(out, Finding{
			ID:         "STACK_KERNEL_ONLY",
			Title:      fmt.Sprintf("Kernel retransmits %.2f%% while the custom stack on the same path retransmits %.2f%%", kernelLoss, rawLoss),
			Severity:   Medium,
			Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("kernel: %d retransmits / %d segments (%.3f%%), %d dup-ACKs received", k.RetransSent, k.SegsSent, kernelLoss, k.DupAcksRecv),
				fmt.Sprintf("custom: %d retransmits / %d segments (%.3f%%), %d dup-ACKs received", r.RetransSent, r.SegsSent, rawLoss, r.DupAcksRecv),
			},
			Cause:   "the two stacks saw the same path and only one of them retransmitted, so the cause is inside the host: the OS stack, its timers, or NIC offload - not the network",
			Actions: exactSteps("kernel-only", nil),
			Filters: []string{"tcp.analysis.spurious_retransmission", "tcp.analysis.duplicate_ack"},
		})
	case rawLoss > 0.2 && kernelLoss < rawLoss/3:
		out = append(out, Finding{
			ID:         "STACK_PATH",
			Title:      fmt.Sprintf("Custom stack retransmits %.2f%% while the kernel stack retransmits %.2f%%", rawLoss, kernelLoss),
			Severity:   Medium,
			Confidence: "medium",
			Evidence: []string{
				fmt.Sprintf("custom: %d retransmits (%.3f%%)", r.RetransSent, rawLoss),
				fmt.Sprintf("kernel: %d retransmits (%.3f%%)", k.RetransSent, kernelLoss),
			},
			Cause:   "the custom stack is more sensitive here; if its timers are tighter this is expected. Compare with --min-rto before concluding",
			Actions: exactSteps("path", nil),
		})
	case kernelLoss > 0.2 && rawLoss > 0.2:
		out = append(out, Finding{
			ID:         "STACK_AGREE",
			Title:      fmt.Sprintf("Both stacks agree: %.2f%% and %.2f%% of segments were retransmitted", kernelLoss, rawLoss),
			Severity:   High,
			Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("kernel %.3f%% (%d segs), custom %.3f%% (%d segs)", kernelLoss, k.SegsSent, rawLoss, r.SegsSent),
				fmt.Sprintf("fast: kernel %d / custom %d; rto: kernel %d / custom %d; spurious: kernel %d / custom %d",
					k.FastRetrans, r.FastRetrans, k.RtoRetrans, r.RtoRetrans, k.SpuriousRetrans, r.SpuriousRetrans),
			},
			Cause:   "two independent implementations on the same path reached the same conclusion, which rules out the stacks and points at the network itself",
			Actions: exactSteps("both", nil),
			Filters: []string{"tcp.analysis.fast_retransmission", "tcp.analysis.lost_segment"},
		})
	}
	return out
}

// CaptureFinding reports what the raw engine actually saw, so "is it capturing
// my traffic?" is answered by the tool rather than by opening Wireshark.
func CaptureFinding(c *wire.Capture, stackMode string) []Finding {
	if c == nil {
		return nil
	}
	var out []Finding
	wantTCP := stackMode == "raw" || stackMode == "both" || stackMode == "observe" || c.PCAP != ""
	if wantTCP && c.DiagTCP == 0 {
		switch {
		case c.Packets > 0 && c.Injected > 0:
			out = append(out, Finding{
				ID:         "CAPTURE_TCP_UNSEEN",
				Title:      fmt.Sprintf("tcpdiag transmitted %d TCP packet(s) but the capture saw none of them", c.Injected),
				Severity:   High,
				Confidence: "high",
				Evidence: []string{
					fmt.Sprintf("engine %s captured %d packets; tcpdiag-flow TCP=%d (all TCP=%d, unrelated TCP=%d)",
						c.Engine, c.Packets, c.DiagTCP, c.TCP, c.TCP-c.DiagTCP),
					fmt.Sprintf("tcpdiag injected %d packets / %d bytes", c.Injected, c.TxBytes),
					fmt.Sprintf("pcap added %d locally injected packet(s) from our own stack", c.PCAPSynthetic),
				},
				Cause:   "the platform capture path is not delivering locally injected raw TCP back to the capture loop. Windows SIO_RCVALL is the usual offender; the traffic is on the wire even though the sniffer does not show it",
				Actions: exactSteps("tcp-unseen", c),
			})
		case c.TCP > 0:
			out = append(out, Finding{
				ID:         "CAPTURE_NO_DIAG_TCP",
				Title:      fmt.Sprintf("Capture saw %d TCP packet(s), but none from tcpdiag", c.TCP),
				Severity:   Critical,
				Confidence: "high",
				Evidence: []string{
					fmt.Sprintf("engine %s captured %d packets / %d bytes", c.Engine, c.Packets, c.Bytes),
					fmt.Sprintf("protocol breakdown: tcp=%d (tcpdiag TCP=0) udp=%d (tcpdiag UDP=%d) icmp=%d other=%d",
						c.TCP, c.UDP, c.DiagUDP, c.ICMP, c.Other),
					fmt.Sprintf("%d TCP packet(s) belonged to other applications; 0 belonged to tcpdiag", c.TCP-c.DiagTCP),
					fmt.Sprintf("tcpdiag itself injected %d packets / %d bytes", c.Injected, c.TxBytes),
				},
				Cause:   "the capture is dominated by unrelated connections to the same peer; the tcpdiag connection itself never carried TCP. Usually the handshake never completed (peer unreachable, firewall, or wrong port), which is why Wireshark looked like 'all UDP'",
				Actions: exactSteps("no-tcp", c),
			})
		default:
			out = append(out, Finding{
				ID:         "CAPTURE_NO_TCP",
				Title:      fmt.Sprintf("Capture saw no TCP at all: %d packets, tcp=0 udp=%d icmp=%d", c.Packets, c.UDP, c.ICMP),
				Severity:   Critical,
				Confidence: "high",
				Evidence: []string{
					fmt.Sprintf("engine %s captured %d packets / %d bytes", c.Engine, c.Packets, c.Bytes),
					fmt.Sprintf("protocol breakdown: tcp=%d udp=%d icmp=%d other=%d", c.TCP, c.UDP, c.ICMP, c.Other),
					fmt.Sprintf("tcpdiag itself injected %d packets / %d bytes", c.Injected, c.TxBytes),
				},
				Cause:   "the raw engine is running but no TCP reached it, so the user-space connection never carried traffic. Typically the handshake never completed (the peer is unreachable, a firewall dropped the port, or injection is unavailable on this host)",
				Actions: exactSteps("no-tcp", c),
			})
		}
	}
	if c.Injected > 0 && c.Packets == 0 {
		out = append(out, Finding{
			ID:         "CAPTURE_TX_ONLY",
			Title:      "Packets were injected but nothing was captured",
			Severity:   High,
			Confidence: "medium",
			Evidence: []string{
				fmt.Sprintf("injected %d packets, captured %d", c.Injected, c.Packets),
			},
			Cause:   "transmission works but the capture side is starved. On Windows SIO_RCVALL sees inbound traffic only, and an inbound firewall rule or a virtual adapter in promiscuous-off state produces exactly this",
			Actions: exactSteps("tx-only", c),
		})
	}
	return out
}

// exactSteps replaces vague advice with commands that can be pasted. The
// argument is which situation to tailor for.
func exactSteps(kind string, c *wire.Capture) []string {
	switch kind {
	case "kernel-only":
		return []string{
			`Re-run the comparison and read the STACK COMPARISON section: tcpdiag -stack=both -report both.md -v`,
			`Disable receive offload on the adapter, then re-run and see if the kernel column drops to the custom stack's level:`,
			`    PowerShell (admin): Get-NetAdapterAdvancedProperty -Name "<adapter>" | where DisplayName -match "Large Receive|Recv Segment|Checksum|Offload"`,
			`    then: Disable-NetAdapterOffload_RSC / set the corresponding advanced property to Disabled, or: netsh int tcp set global autotuninglevel=disabled`,
			`Re-run with the custom stack's timers matched to the kernel to rule out timer differences: tcpdiag -stack=both -min-rto 200ms -timestamps=false`,
		}
	case "path":
		return []string{
			`Match the custom stack's timers to the kernel's and re-run: tcpdiag -stack=raw -min-rto 200ms -max-rto 12s`,
			`Then re-run the comparison: tcpdiag -stack=both -report both.md`,
		}
	case "both":
		return []string{
			`Measure the path directly: tcpdiag -probe -probe-sweep -probe-mtu`,
			`Find the hop that drops packets (elevated): tcpdiag -stack=raw -probe -probe-ttl`,
			`Confirm the loss is reproducible rather than stack-dependent by replaying it: tcpdiag selftest -impair "loss=<observed %>"`,
		}
	case "no-tcp":
		ports := ""
		if c != nil {
			ports = fmt.Sprintf(" (engine %s)", c.Engine)
		}
		return []string{
			`Check the "local" block printed at startup: it names the adapter and address in use. If it names a virtual adapter, force the real one: tcpdiag -stack=raw -local-ip 192.168.1.x -iface "Wi-Fi"`,
			`Confirm the peer is reachable on the raw port from here: tcpdiag -probe -probe-count 5 (and on the peer: tcpdiag -probe -probe-count 5)`,
			`Allow the ports both ways in the firewall: tcp 42425 and 42426 for the raw plane, udp 42426 for probes, udp 42077 for discovery`,
			`Run without discovery to rule out address selection: tcpdiag -stack=raw -peer <peer-ip>:42424 -discover=false` + ports,
			`Check the printed capability line: if injection is not "IP_HDRINCL", re-run from an elevated shell`,
		}
	case "tx-only":
		return []string{
			`Verify the shell is elevated: the startup capability line must show capture working`,
			`On Windows, SIO_RCVALL only sees inbound traffic, so confirm the peer is actually sending: check its "injected" counter in /stats`,
			`Bind the interface explicitly: tcpdiag -stack=raw -iface "Wi-Fi" -local-ip 192.168.1.x`,
			`Allow inbound tcp/42425-42426 in the local firewall`,
		}
	case "tcp-unseen":
		return []string{
			`Keep the pcap: tcpdiag writes locally injected TCP into it directly, so the SYN/data it sent is still visible in Wireshark`,
			`Confirm the run is elevated: the startup capability line must show capture working, not "capture only"`,
			`On Windows, confirm SIO_RCVALL is not being intercepted by a third-party LSP/filter driver; test with Wireshark/Npcap as a control`,
			`Bind the real adapter explicitly: tcpdiag --stack=raw --iface "<adapter>" --local-ip <ip> --pcap wire.pcap`,
			`Check that the peer is actually listening on tcp/42425 and that inbound tcp/42425-42426 is allowed on both hosts`,
		}
	}
	return nil
}

// CaptureLines renders the capture summary for both output formats.
func CaptureLines(c *wire.Capture) []string {
	if c == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("engine: %s", c.Engine),
		fmt.Sprintf("captured: %d packets / %d bytes  (tcp %d, udp %d, icmp %d, other %d)",
			c.Packets, c.Bytes, c.TCP, c.UDP, c.ICMP, c.Other),
		fmt.Sprintf("tcpdiag flows only: tcp %d, udp %d", c.DiagTCP, c.DiagUDP),
		fmt.Sprintf("of those, %d are tcpdiag control traffic (discovery beacons and probe packets on our own ports)", c.Control),
		fmt.Sprintf("largest captured packet: %d bytes; oversized (offload-sized): %d", c.MaxBytes, c.Oversized),
		fmt.Sprintf("injected by tcpdiag: %d packets / %d bytes", c.Injected, c.TxBytes),
	}
	if c.PCAP != "" {
		scope := "tcpdiag flows only"
		if c.PCAPAll {
			scope = "all host traffic"
		}
		line := fmt.Sprintf("pcap scope: %s; %d unrelated packet(s) omitted", scope, c.PCAPFiltered)
		if c.PCAPSynthetic > 0 {
			line += fmt.Sprintf("; %d locally injected packet(s) written from our own stack", c.PCAPSynthetic)
		}
		if c.PCAPDuplicate > 0 {
			line += fmt.Sprintf("; %d duplicate(s) suppressed", c.PCAPDuplicate)
		}
		out = append(out, line)
	}
	return out
}

// hostOf pulls the address out of a "ip:port" endpoint string.
func hostOf(ep string) string {
	if h, _, err := net.SplitHostPort(ep); err == nil {
		return h
	}
	return strings.TrimSpace(ep)
}
