//go:build !linux && !windows

package kernelstat

// New returns a no-op reader on platforms without a counters source.
func New() Reader { return stub{} }

type stub struct{}

func (stub) Name() string            { return "none" }
func (stub) Read() map[string]uint64 { return nil }
