//go:build linux
// +build linux

package tarpit

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// tcpRTT reads the kernel's smoothed RTT estimate for conn using
// getsockopt(IPPROTO_TCP, TCP_INFO). The tcpi_rtt field is in microseconds.
//
// Returns (rtt, true) on success. Returns (0, false) when the measurement is
// unavailable — either because the connection type is unsupported, the kernel
// hasn't accumulated an RTT sample yet, or the syscall fails.
func tcpRTT(conn net.Conn) (time.Duration, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, false
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}

	var rttUs uint32
	var sysErr error

	ctrlErr := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			sysErr = err
			return
		}
		rttUs = info.Rtt
	})

	if ctrlErr != nil || sysErr != nil || rttUs == 0 {
		return 0, false
	}

	return time.Duration(rttUs) * time.Microsecond, true
}
