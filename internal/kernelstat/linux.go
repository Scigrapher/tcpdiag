//go:build linux

package kernelstat

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type linuxReader struct{}

// New returns the platform reader.
func New() Reader { return &linuxReader{} }

func (linuxReader) Name() string { return "linux-proc-net" }

// Read parses /proc/net/snmp and /proc/net/netstat. The TcpExt line is
// especially useful: TCPSpuriousRTOs, TCPSynRetrans and TCPTimeouts are the
// kernel's own verdict on the exact symptoms being investigated.
func (linuxReader) Read() map[string]uint64 {
	out := map[string]uint64{}
	parseProcNetFile("/proc/net/snmp", "", out)
	parseProcNetFile("/proc/net/netstat", "tcpext_", out)
	parseProcNetFile("/proc/net/dev", "dev_", out)
	return out
}

func parseProcNetFile(path, prefix string, out map[string]uint64) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var keys []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if isHeader(fields) {
			keys = fields
			continue
		}
		if keys == nil || len(keys) != len(fields) {
			continue
		}
		base := strings.ToLower(strings.TrimSpace(name))
		for i, v := range fields {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			key := base + "_" + strings.ToLower(keys[i])
			if prefix != "" && strings.Contains(base, "ext") {
				key = prefix + strings.ToLower(keys[i])
			}
			out[key] = n
		}
	}
}

func isHeader(fields []string) bool {
	for _, f := range fields {
		if _, err := strconv.ParseUint(f, 10, 64); err == nil {
			return false
		}
		return true
	}
	return false
}
