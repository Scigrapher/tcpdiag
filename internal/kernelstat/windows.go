//go:build windows

package kernelstat

import (
	"syscall"
	"unsafe"
)

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTcpStatsEx = iphlpapi.NewProc("GetTcpStatisticsEx")
)

// mibTCPStats mirrors MIB_TCPSTATS (16 DWORDs) from iprtrmib.h.
type mibTCPStats struct {
	State        uint32
	RtoAlgorithm uint32
	RtoMin       uint32
	RtoMax       uint32
	MaxConn      uint32
	ActiveOpens  uint32
	PassiveOpens uint32
	AttemptFails uint32
	EstabResets  uint32
	CurrEstab    uint32
	InSegs       uint32
	OutSegs      uint32
	RetransSegs  uint32
	InErrs       uint32
	OutRsts      uint32
	NumCol       uint32
}

type winReader struct{}

// New returns the platform reader.
func New() Reader { return &winReader{} }

func (winReader) Name() string { return "windows-iphlpapi" }

func (winReader) Read() map[string]uint64 {
	var st mibTCPStats
	// AF_INET == 2
	r, _, _ := procGetTcpStatsEx.Call(uintptr(uintptr(unsafe.Pointer(&st))), 2)
	if r != 0 {
		return map[string]uint64{"windows_get_tcp_stats_error": uint64(r)}
	}
	return map[string]uint64{
		"win_tcp_retrans_segs":  uint64(st.RetransSegs),
		"win_tcp_in_segs":       uint64(st.InSegs),
		"win_tcp_out_segs":      uint64(st.OutSegs),
		"win_tcp_estab_resets":  uint64(st.EstabResets),
		"win_tcp_attempt_fails": uint64(st.AttemptFails),
		"win_tcp_out_rsts":      uint64(st.OutRsts),
		"win_tcp_in_errs":       uint64(st.InErrs),
		"win_tcp_active_opens":  uint64(st.ActiveOpens),
		"win_tcp_passive_opens": uint64(st.PassiveOpens),
		"win_tcp_curr_estab":    uint64(st.CurrEstab),
		"win_tcp_rto_min_ms":    uint64(st.RtoMin),
		"win_tcp_rto_max_ms":    uint64(st.RtoMax),
	}
}
