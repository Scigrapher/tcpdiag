# tcpdiag

Diagnoses TCP retransmission problems between two machines: **TCP Dup ACK**,
**TCP Fast Retransmission**, **TCP Spurious Retransmission**, out-of-order
delivery, zero windows, and the path conditions that cause them.

It is built around one idea: **you should be able to get a complete diagnosis
from one machine**. To make that possible, every block of data a node transmits
carries that node's full telemetry *and* its payload is cryptographically bound
to what it has received. Watching one direction therefore tells you about both.

```
   A                                                       B
   |  ---- block N: payload = PRNG(seed, N, recvChainB) --->|   payload only
   |             + A's telemetry: retransmits, dup-ACKs,     |   decrypts if A
   |               holes, RTT histogram, cwnd, RTO, kernel   |   really received
   |               counters...                               |   what A claimed
   |  <-- block M: payload = PRNG(seed, M, recvChainA) ------|
   |             + B's telemetry                              |
```

Because B's payload is derived from B's receive history, a payload that verifies
at A is proof that the blocks A sent actually reached B. Loss can be attributed
to a direction from a single observation point.

## Build

Pure Go, no cgo. Kernel and observe modes need no packet-capture library.
Windows raw TCP transmission requires Npcap (installed with Wireshark); Linux
raw mode uses `AF_PACKET`.

Windows:

```powershell
.\scripts\build.ps1
```

Linux/macOS:

```bash
./scripts/build.sh
```

Both scripts increment the patch version in `cmd/tcpdiag/main.go` on every
build and then write the binary. Use `-NoBump` / `--no-bump` to rebuild the
current version, or `-Version 1.3.0` / `--version 1.3.0` to set an explicit
version. A direct `go build` does not change the version. The built binary
prints it with `tcpdiag -version`.

Tested on Windows (amd64) and cross-checked for Linux (amd64).

## Quick start

Run this on **both** machines:

```
tcpdiag
```

They announce themselves over UDP broadcast + multicast, pick a dial/listen
role deterministically (lowest peer ID dials), and start streaming data in both
directions while measuring. Press Ctrl-C for a written diagnosis.

Watch it in a browser on either machine:

```
tcpdiag -http :8083
```

Then open `http://<that-machine>:8083/` (dashboard), `/report` (markdown),
`/stats` (JSON), `/peers`.

## Stack modes

| `--stack` | What it does | Privileges |
|---|---|---|
| `kernel`  | Streams over ordinary OS TCP sockets; measures the application-visible result. | none |
| `raw`     | **Our own TCP implementation**: builds IPv4/TCP headers itself, runs its own state machine, retransmission timers, fast retransmit, SACK and delayed ACKs, and sends them through a raw packet engine. | Administrator + Npcap (Windows) / root or `CAP_NET_RAW` (Linux) |
| `both`    | Runs the kernel session and the raw session over the same path at the same time and reports them side by side. The most useful mode for separating *path* problems from *stack* problems. | as above |
| `observe` | Low-rate kernel session plus a **passive analyser** attached to the raw engine: it reconstructs dup-ACK / fast-retransmit / spurious-retransmit annotations for the kernel connection from sequence numbers on the wire. Wireshark-grade analysis without Npcap. | as above |

The raw engine uses `SIO_RCVALL` + `IP_HDRINCL` on Windows and `AF_PACKET` on
Linux. If it cannot start, `tcpdiag` says exactly why and, except in
`--stack=raw`, continues on the kernel stack instead of failing.

On Windows, raw TCP injection is performed with Npcap at layer 2. Windows raw
sockets accept TCP `sendto` calls but drop the packets, so `IP_HDRINCL` is not
a usable transmit path. If Npcap is unavailable, `--stack=raw` fails with a
clear error; `--stack=observe` still works for capture-only analysis.

Raw mode also uses a private TCP option on every segment so the user-space
stack can distinguish its peer from the OS listener that shields the raw port
from kernel RSTs. Both ends must run the same build for raw mode to negotiate.

The two ends need a data plane in common: `raw` can talk to `raw` or `both`;
`kernel`/`observe` can talk to `kernel`, `observe` or `both`. tcpdiag reports a
`STACK_MISMATCH` finding and stops dialing a port the peer never opens. With
`--peer` and discovery off, declare the peer's mode with `--peer-stack`.

## Diagnosing your specific symptoms

Your three Wireshark annotations have different root causes, and tcpdiag
separates them instead of lumping them together:

| Symptom | tcpdiag's discriminator | Typical cause |
|---|---|---|
| **TCP Dup ACK** | Counted at the receiver, per burst, correlated with open holes | any hole; benign in small numbers |
| **TCP Fast Retransmission** | Three dup-ACKs, and *how the hole was later filled*: a genuine drop vs a block that simply arrived late (`late` counter) | congestion drop, or **reordering** mistaken for loss |
| **TCP Spurious Retransmission** | Retransmitted range was already ACKed/SACKed (`already_acked`), or the timer fired inside `SRTT + 2*RTTVAR` (`within_rtt`) | delayed ACKs, variable RTT/bufferbloat, receive offload (LRO/GRO), aggressive timers |

The report names the direction (`inbound (peer to us)` / `outbound (us to
peer)`), so an asymmetric path - usually one bad AP or uplink - is obvious.

### Useful runs

```bash
# Baseline both directions, live dashboard, markdown report on disk
tcpdiag -http :8083 -report diag.md

# Compare the OS stack against our own stack on the same path
tcpdiag -stack=both -report diag.md

# Wireshark-style analysis of the OS connection without Npcap (elevated)
tcpdiag -stack=observe -pcap seen.pcap

# Find the rate at which the path starts dropping (the usual Wi-Fi culprit)
tcpdiag -probe -probe-sweep

# TCP handshake, echo, small-write, bulk and full-duplex probes (any stack mode)
tcpdiag -probe -probe-tcp

# Run the probes once, then print the report and exit through normal cleanup
tcpdiag -probe -probe-tcp -exit-after-probes -report diag.md

# Locate which hop actually drops packets (elevated, raw)
tcpdiag -stack=raw -probe -probe-ttl

# Rule out a PMTU blackhole
tcpdiag -probe -probe-mtu

# Reproduce the symptoms on a healthy lab link and validate the detector
tcpdiag selftest -impair "loss=2,delay=15ms,jitter=5ms,reorder=1,dup=0.3"
```

## Active probes

`--probe` waits for a peer and then runs an `udp-echo` baseline. The other
probes are opt-in. Every instance keeps its echo server running on UDP
`42426` (or `--probe-port`), so either side can be measured at any time.
Add `--exit-after-probes` to run the requested probes once and then trigger the
normal shutdown path: sessions close, the report prints, and `--report` /
`--jsonl` / `--csv` are written exactly as they are on Ctrl-C.

| Probe | Enabled by | What it does | What to read |
|---|---|---|---|
| **udp-echo** | `--probe` (always first) | Sends `--probe-count` authenticated UDP echo packets, 64 bytes each, 20 ms apart. | RTT min/avg/p50/p99/max, jitter, loss, out-of-order and duplicates. This is the baseline that tells you whether the path is healthy when idle. |
| **tcp-handshake** | `--probe --probe-tcp` | Opens `--probe-tcp-connections` OS TCP connections and completes a zero-byte echo on each. | Connect + first-byte latency, success rate and loss. This tests SYN/SYN-ACK/ACK and firewall/NAT state on the always-on TCP probe service, independent of the diagnostic stack. |
| **tcp-echo** | `--probe --probe-tcp` | Sends `--probe-count` request/response frames over one OS TCP connection. | Request/response RTT, jitter and stalls. TCP preserves ordering, so this is a clean measure of stream turnaround. |
| **tcp-small** | `--probe --probe-tcp` | Sends `--probe-tcp-small` one-byte writes over one connection. | Small-write latency and stalls. This is where Nagle, delayed ACKs and ACK-return-path problems show up; set `--probe-tcp-nodelay=false` to compare. |
| **tcp-upload / tcp-download** | `--probe --probe-tcp` | Transfers `--probe-tcp-bytes` in one direction using a deterministic pattern and CRC32 verification. | Throughput, duration and whether the stream was corrupted/truncated. Upload and download are measured separately so an asymmetric path is visible. |
| **tcp-duplex** | `--probe --probe-tcp` | Transfers `--probe-tcp-bytes` in both directions simultaneously on one TCP connection. | Per-direction throughput and CRC verification under full-duplex load. This is the probe most likely to reproduce dup-ACK / fast-retransmit behaviour caused by the ACK return path. |
| **sweep-NMbps** | `--probe --probe-sweep` | Sends 200 x 1024-byte bursts at 1, 5, 20, 50, 100, 200 and 500 Mbit/s. Pacing is deadline-based, so the offered rate is the rate on the wire. | Loss at each rate. The first rate with sustained loss is the loaded-link cliff. If a rate gets no replies but the previous rate worked, the burst was dropped on the path or by the receiver - the peer is still reachable. |
| **tcp-connect** | `--probe` (unless the peer is raw-only) | Opens 20 ordinary kernel TCP connections, 50 ms apart, to the peer's kernel data-plane port. | Connection setup latency and SYN/handshake loss. This exercises firewall/NAT/SYN behaviour, not bulk transfer. A raw-only peer has no kernel listener, so this is skipped; use the raw session status instead. |
| **path-mtu** | `--probe --probe-mtu` | Sends DF-marked UDP echo probes with increasing payload size to the peer's echo port. | The largest payload that round-trips. Add 28 bytes for the IP+UDP headers to get the path MTU. If large payloads vanish while small ones work, you have a PMTU blackhole. |
| **ttl-walk** | `--probe --probe-ttl` (raw/elevated) | Sends raw TCP SYN probes with TTL 1, 2, 3 ... and records the ICMP time-exceeded replies. | The router at each hop and loss per TTL. The first TTL where replies stop or loss jumps is the hop dropping the traffic. |

The UDP echo, sweep and MTU probes all use the peer's advertised probe port and
need it open in both directions. `tcp-connect` needs the kernel data-plane port
(`--data-port`, default `42424`). With `--peer` and discovery off, pass
`--peer-stack` so tcpdiag knows whether the peer has a kernel listener; pass
`--peer-raw-port` if the peer's raw port is not the local default.

The `tcp-*` suite above does **not** use the diagnostic data plane. Every
instance runs an ordinary OS TCP echo service on `--probe-tcp-port` (default
`42427`), so the TCP probes work the same with `--stack=kernel`, `raw`, `both`
or `observe`. If `--pcap` is enabled, these flows are included in the capture
for Wireshark analysis. With `--peer` and discovery off, use
`--peer-tcp-probe-port` if the peer uses a non-default TCP probe port.
Both machines must run a build that includes the TCP probe service.
On a very slow or badly impaired path, lower `--probe-tcp-bytes` or raise
`--probe-tcp-timeout` so a transfer timeout is not mistaken for corruption.

High-rate sweep results can also be limited by the receiving host or by the
probe server itself. The note on a failing rate says whether the peer was
proven reachable at a lower rate, so do not read `100% loss` as
"unreachable host".

## Flags

**Identity / discovery**
`--name` `--peer host:port` `--peer-stack kernel|raw|both|observe`
`--peer-raw-port` `--discover` `--discovery-port` `--multicast`

**Traffic**
`--block-size` `--rate` (Mbit/s) `--duration` `--total` `--feed <file|dir>`
(stream real file contents instead of synthetic data; give both sides the same
input) `--nodelay`

**Stack selection**
`--stack kernel|raw|both|observe` `--backend auto|windows|npcap|linux|sim`
`--iface` `--local-ip` `--connect-timeout` `--connect-attempts`

**Custom stack tuning** (raw mode)
`--mss` `--rcv-buf` `--snd-buf` `--min-rto` `--max-rto` `--timestamps`
`--sack` `--delayed-ack` `--ttl` `--tos`

**Impairment** - inject defects so you can reproduce and confirm the failure
`--impair "loss=2,dup=0.5,reorder=1,delay=12ms,jitter=4ms,rate=100,burst=3@20"`

**Probes** `--probe` `--probe-count` `--probe-sweep` `--probe-mtu` `--probe-ttl`
`--exit-after-probes`
`--probe-tcp` `--probe-tcp-port` `--probe-tcp-connections`
`--probe-tcp-bytes` `--probe-tcp-small` `--probe-tcp-nodelay`
`--probe-tcp-timeout` `--peer-tcp-probe-port`

**Output** `--http :8083` `--report file.md` `--jsonl file` `--csv file`
`--pcap file.pcap` `--pcap-dlt raw|ethernet` `--pcap-all` `--bind <ip>` `-v`

### The report does the comparisons for you

Two sections exist so the "what to do" list never tells you to do something
tcpdiag could do itself:

- **WIRE OBSERVATION** - what the raw engine actually saw: packet and byte
  totals, a TCP/UDP/ICMP/other breakdown, a separate **tcpdiag flows only**
  TCP/UDP count, the largest captured packet and how many were oversized, plus
  how many packets the pcap filter omitted. If the tcpdiag TCP count is `0`
  while unrelated TCP is present, the capture is healthy but the diagnostic
  connection is not; the finding names which case applies. `--pcap` is only for
  keeping the evidence; the analysis is already in the report.
- **STACK COMPARISON** - when run with `--stack=both`, the kernel and the custom
  stack are diffed directly: retransmits, fast/RTO/spurious, dup-ACKs and the
  resulting rate. If only the kernel retransmits, the finding points inside the
  host (stack timers or NIC offload); if both do, the network is the cause.

### What lands in the pcap

`--pcap` writes only tcpdiag flows by default: TCP `42424`, `42425`, `42426`,
probe UDP `42426`, discovery UDP `42077`, and ICMP errors that quote one of
those packets. Other applications on the same host are omitted, so a capture of
one run is not buried under unrelated sessions to the same peer. Pass
`--pcap-all` when you deliberately want every packet the capture backend sees.

The writer also records packets tcpdiag's raw stack transmits itself. Windows'
`SIO_RCVALL` does not reliably deliver locally injected raw-socket packets back
to the capture loop; without this, a raw-mode capture looked like it contained
only UDP discovery traffic even while the tool was sending TCP SYNs. Duplicates
reported by both paths are collapsed, and the report says how many packets were
filtered or added.

`--pcap` works alongside `--stack=kernel` too: tcpdiag opens the packet backend
in capture-only mode and attaches the passive analyser. That still needs
Administrator/root or `CAP_NET_RAW`; without it the run continues and says why
no file was written.

### Console vs file report

The report printed to your terminal on exit is a **fixed-width text layout**,
not markdown: every table is measured across all cells first and then padded, so
the `local` and `remote` columns line up on screen no matter how different the
magnitudes are, long paragraphs are folded at 96 columns with a hanging indent,
and the RTT histogram uses ASCII bars. Live status lines use the same discipline
- counters are right-aligned, so a field does not shift sideways as its value
grows from `9` to `12345678`.

`--report` writes markdown by default; pass a `.txt` name to get the terminal
layout on disk. The dashboard exposes both: `/report` (markdown) and
`/report.txt` (plain text).

**Discovery goes quiet.** Once peers are connected and exchanging data the periodic
beacon stops — it is LAN-wide noise and clutters every capture. A newly started
peer still finds you because beacons and probes are answered directly; if you
want the constant beacon back, use `--keep-advertising`. Beacons also resume
automatically if a session stalls and no data has been exchanged for 15s.

Subcommands: `tcpdiag selftest` (two user-space stacks over an impaired
in-process link, no privileges needed), `tcpdiag peers` (list peers seen on the
LAN), `tcpdiag probe` (measure only).

## Firewalls

Allow, in both directions:

- UDP `42077` - discovery beacons (broadcast + multicast `239.255.42.99`)
- TCP `42424` - kernel data plane
- TCP `42425`/`42426` - raw data plane
- UDP `42426` - probe echo
- TCP `42427` - always-on OS TCP probe service (used by `--probe-tcp`)

Discovery is a convenience; `--peer host:port --discover=false` works across
routed boundaries where broadcast does not.

## How the measurement works

- **In-band telemetry.** Each node embeds a `Snapshot` (retransmit counts by
  kind, dup-ACK counts, hole list with fill latency and fill source, RTT
  histogram, RTO/SRTT/RTTVAR, cwnd, advertised and peer window, zero-window
  events, and the OS's own TCP counters) in the report section of every block.
- **Causal chain.** `PrevSentDigest` links every transmitted block into a hash
  chain, so a receiver detects skipped or replayed blocks even when the bytes it
  did receive are perfect. After a hole the chain re-anchors rather than
  reporting noise.
- **Receive-bound payload.** The payload keystream is
  `PRNG(session_seed, block_seq, sender_receive_chain_head)`. Both ends can
  regenerate it, so a mismatch means corruption, replay, or a claim about
  received data that did not hold.
- **Cross-checking.** The tool's private view is compared with the operating
  system's counters (`GetTcpStatisticsEx` on Windows, `/proc/net/snmp` and
  `/proc/net/netstat` on Linux - including `TCPSpuriousRTOs`). Disagreement is
  reported as a finding, because it usually means offload or a driver rather
  than the network.

## Tests

```
go test ./...          # default: no elevation, no firewall prompts
go test -short ./...   # skips the two loopback socket tests as well
```

**The default suite never prompts for elevation.** Nothing in it requires
privileges: the custom TCP stack, the link simulator and the report engine run
entirely in-process, and the probe tests bind **only `127.0.0.1`**. That detail
matters - on Windows a listening socket bound to the wildcard address
(`0.0.0.0`), created by an unsigned binary, raises a firewall/elevation dialog,
which would hang `go test` in CI. `internal/testpolicy` enforces the rule as a
test: if anyone reintroduces `StartServer(`, `NewClient(` or a `"0.0.0.0"` bind
into the default suite, `go test` fails and names the file.

Tests that genuinely need a non-loopback path are **opt-in** and skipped by
default:

```
TCPDIAG_TEST_NETWORK=1 TCPDIAG_TEST_PEER=192.168.1.22 go test ./internal/probe
```

Use `--bind 127.0.0.1` when running two instances on one host, so neither
instance opens a LAN listener (an invalid `--bind` is rejected at startup).

Covers the segment codec (checksums including odd-length payloads, option and
SACK round trips), a full three-way handshake and 256 KiB bulk transfer of the
custom stack over a simulated 2 %-loss + reordering link, the causal chain and
its tamper detection, one-sided diagnosis over a frame-dropping relay, the
link simulator's accuracy, and the diagnosis engine's classification rules.

## Known limitations

- Raw mode needs elevation, and `SIO_RCVALL` on Windows sees only traffic to and
  from the local host (not everything on the LAN).
- Windows raw mode requires Npcap for layer-2 TCP injection. The Npcap driver
  must be installed and running (it is normally installed with Wireshark).
- Npcap injection resolves the peer with ARP, so Windows raw mode currently
  requires the peer to be on the same IPv4 subnet.
- Both ends must run the same build: raw mode uses a private TCP option to
  separate the user-space stack from the OS port shield.
- Raw mode is IPv4 only.
- Sessions are keyed per peer; running several instances on one host needs
  distinct `--data-port`/`--raw-port`/`--probe-port` values.
- The custom stack implements what a diagnosis needs: handshake, cumulative and
  selective ACKs, window scaling, timestamps, slow start, congestion avoidance,
  fast retransmit and recovery, RTO with exponential backoff and Karn's rule,
  zero-window probing, and FIN/RST handling. It is not intended as a general
  purpose TCP stack.
