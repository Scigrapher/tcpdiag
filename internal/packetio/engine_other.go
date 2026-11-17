//go:build !linux

package packetio

import (
	"fmt"
	"runtime"
)

func openLinux(o Options) (Engine, error) {
	return nil, fmt.Errorf("the AF_PACKET backend is Linux-only (this is %s)", runtime.GOOS)
}
