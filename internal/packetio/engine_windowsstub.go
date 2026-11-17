//go:build !windows

package packetio

import "fmt"

func openWindows(o Options) (Engine, error) {
	return nil, fmt.Errorf("the SIO_RCVALL raw backend is Windows-only (this is not Windows)")
}
