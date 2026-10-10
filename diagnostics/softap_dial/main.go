//go:build darwin

// softap_dial compares ways of opening a TCP connection to the SoftAP
// control socket, to pin down why non-root dials fail with EHOSTUNREACH
// while Apple's nc succeeds from the same shell.
//
// Join the bulb's SoftAP first, then run without sudo:
//
//	networksetup -setairportnetwork en0 "LIFX Candle Color 8274eb"
//	go run ./diagnostics/softap_dial
//
// Modes:
//
//	default  — plain dial, kernel picks source address and interface
//	bound-ip — LocalAddr bound to our address on the SoftAP subnet (what
//	           the library does today)
//	bound-if — IP_BOUND_IF to the interface on the SoftAP subnet, no
//	           source-address bind
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	addr := flag.String("addr", "172.16.0.1:56700", "SoftAP control socket")
	attempts := flag.Int("n", 3, "attempts per mode")
	timeout := flag.Duration("timeout", 3*time.Second, "per-dial timeout")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dst := net.ParseIP(host).To4()

	ifc, src := interfaceFor(dst)
	fmt.Printf("euid=%d dst=%s iface=%v src=%v\n\n", os.Geteuid(), *addr, ifName(ifc), src)

	modes := []struct {
		name   string
		dialer func() *net.Dialer
	}{
		{"default", func() *net.Dialer { return &net.Dialer{Timeout: *timeout} }},
		{"bound-ip", func() *net.Dialer {
			d := &net.Dialer{Timeout: *timeout}
			if src != nil {
				d.LocalAddr = &net.TCPAddr{IP: src}
			}
			return d
		}},
		{"bound-if", func() *net.Dialer {
			d := &net.Dialer{Timeout: *timeout}
			if ifc != nil {
				idx := ifc.Index
				d.Control = func(_, _ string, c syscall.RawConn) error {
					var serr error
					err := c.Control(func(fd uintptr) {
						serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
					})
					if err != nil {
						return err
					}
					return serr
				}
			}
			return d
		}},
	}

	for _, m := range modes {
		for i := 1; i <= *attempts; i++ {
			start := time.Now()
			conn, err := m.dialer().DialContext(context.Background(), "tcp4", *addr)
			took := time.Since(start).Round(time.Millisecond)
			if err != nil {
				fmt.Printf("%-8s #%d FAIL %-6s %v\n", m.name, i, took, err)
			} else {
				fmt.Printf("%-8s #%d OK   %-6s local=%s\n", m.name, i, took, conn.LocalAddr())
				conn.Close()
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
}

// interfaceFor returns the up interface whose IPv4 network contains dst,
// and our address on it.
func interfaceFor(dst net.IP) (*net.Interface, net.IP) {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		ix := &ifaces[i]
		if ix.Flags&net.FlagUp == 0 || ix.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ix.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.Contains(dst) {
				return ix, n.IP.To4()
			}
		}
	}
	return nil, nil
}

func ifName(ix *net.Interface) string {
	if ix == nil {
		return "<none>"
	}
	return ix.Name
}
