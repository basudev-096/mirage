//go:build !linux

package tarpit

import (
	"net"
	"time"
)

func tcpRTT(net.Conn) (time.Duration, bool) { return 0, false }
