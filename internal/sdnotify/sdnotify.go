// Package sdnotify implements the systemd sd_notify protocol (READY, WATCHDOG,
// RELOADING, STOPPING) without a cgo dependency, by writing datagrams to the
// socket named in $NOTIFY_SOCKET. All functions no-op when not run under systemd.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends a single state string (e.g. "READY=1") to systemd. It is a no-op
// when NOTIFY_SOCKET is unset.
func Notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if len(addr) > 0 && addr[0] == '@' {
		addr = "\x00" + addr[1:] // abstract namespace socket
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Ready signals startup completion.
func Ready() error { return Notify("READY=1") }

// Stopping signals shutdown has begun.
func Stopping() error { return Notify("STOPPING=1") }

// WatchdogInterval returns the ping interval (WATCHDOG_USEC/2) and whether the
// watchdog is enabled for this process.
func WatchdogInterval() (time.Duration, bool) {
	usec := os.Getenv("WATCHDOG_USEC")
	if usec == "" {
		return 0, false
	}
	// Honor WATCHDOG_PID if set (must match our PID).
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" {
		if p, err := strconv.Atoi(pid); err == nil && p != os.Getpid() {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return time.Duration(n) * time.Microsecond / 2, true
}

// RunWatchdog pings WATCHDOG=1 at half the configured interval until stop is
// closed. No-op when the watchdog is disabled.
func RunWatchdog(stop <-chan struct{}) {
	interval, ok := WatchdogInterval()
	if !ok {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = Notify("WATCHDOG=1")
		}
	}
}
