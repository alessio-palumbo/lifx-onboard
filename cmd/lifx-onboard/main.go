// lifx-onboard is a command-line front end for the lifx-onboard library. It
// onboards LIFX SoftAP devices onto a home WiFi network without needing a
// GUI client, and doubles as the hardware test harness for the library.
//
// Usage:
//
//	lifx-onboard ssid "LIFX A19 228447" --home-ssid MyNet   # by SoftAP SSID
//	lifx-onboard ssid d073d5228447 --home-ssid MyNet        # by serial (or just 228447); scans for the SSID
//	lifx-onboard auto [serial]                               # scan, then onboard one device
//	lifx-onboard bulk [--max N] [--idle 2m]                  # scan and onboard every device found
//	lifx-onboard bulk 8274eb d073d5826a68                    # ...or only these devices
//	lifx-onboard scan [--all]                                # list visible SoftAPs
//
// The home WiFi password is read from LIFX_ONBOARD_PASSWORD, from stdin
// with --password-stdin, or from a no-echo prompt when attached to a TTY.
//
// On macOS, run it from the bundle built by scripts/bundle.sh: it relaunches
// itself through LaunchServices so macOS applies the app's own Location
// Services grant (unredacted WiFi scans). See launch_darwin.go.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. Onboarding failures map to the phase that broke so scripts can
// branch on where it went wrong.
const (
	exitOK          = 0
	exitFailure     = 1
	exitUsage       = 2
	exitScan        = 3
	exitJoin        = 4
	exitWait        = 5
	exitDial        = 6
	exitConfigure   = 7
	exitRejoin      = 8
	exitVerify      = 9
	exitInterrupted = 130
)

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

var commands = []command{
	{"ssid", "onboard a device by its SoftAP SSID, serial, or last 6 hex chars", runSSID},
	{"auto", "scan for a SoftAP and onboard it", runAuto},
	{"bulk", "scan repeatedly and onboard every SoftAP found, or only the listed serials", runBulk},
	{"scan", "list visible LIFX SoftAPs", runScan},
}

func main() {
	if code, ok := relaunchViaLaunchServices(); ok {
		os.Exit(code)
	}
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	reportExit(code)
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return exitOK
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "lifx-onboard: unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: lifx-onboard <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-6s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'lifx-onboard <command> -h' for command flags.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  LIFX_ONBOARD_SSID             default for --home-ssid")
	fmt.Fprintln(w, "  LIFX_ONBOARD_PASSWORD         home WiFi password")
	fmt.Fprintln(w, "  LIFX_ONBOARD_REJOIN_PASSWORD  password for --rejoin-ssid")
	fmt.Fprintln(w, "  LIFX_BULB_SSID                default bulb SSID for 'ssid'")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 ok, 1 failure, 2 usage, 3 scan, 4 join, 5 wait, 6 dial,")
	fmt.Fprintln(w, "            7 configure, 8 rejoin, 9 verify, 130 interrupted")
}
