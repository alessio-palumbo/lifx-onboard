package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	onboard "github.com/alessio-palumbo/lifx-onboard"
	"github.com/alessio-palumbo/lifxlan-go/pkg/controller"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
	"golang.org/x/term"
)

const (
	envHomeSSID       = "LIFX_ONBOARD_SSID"
	envPassword       = "LIFX_ONBOARD_PASSWORD"
	envRejoinPassword = "LIFX_ONBOARD_REJOIN_PASSWORD"
	envBulbSSID       = "LIFX_BULB_SSID"
)

// sharedFlags holds the flags common to every onboarding subcommand.
type sharedFlags struct {
	homeSSID      string
	passwordStdin bool
	security      string
	iface         string
	legacyTLS     bool
	noVerify      bool
	verifyTimeout time.Duration
	dialTimeout   time.Duration
	rejoinSSID    string
	rejoinTimeout time.Duration
	findTimeout   time.Duration
	json          bool
	verbose       bool
}

func (s *sharedFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.homeSSID, "home-ssid", os.Getenv(envHomeSSID), "home WiFi SSID to hand to the device (env "+envHomeSSID+")")
	fs.BoolVar(&s.passwordStdin, "password-stdin", false, "read the home WiFi password from the first line of stdin")
	fs.StringVar(&s.security, "security", "wpa2-aes", "home network security: "+strings.Join(securityNames(), ", "))
	fs.StringVar(&s.iface, "iface", "", "host WiFi interface (auto-detected when empty)")
	fs.BoolVar(&s.legacyTLS, "legacy-tls", false, "use TLS 1.0 + RSA-AES-CBC-SHA for pre-2020 firmware")
	fs.BoolVar(&s.noVerify, "no-verify", false, "skip waiting for the device to reappear on the home LAN")
	fs.DurationVar(&s.verifyTimeout, "verify-timeout", onboard.DefaultVerifyTimeout, "max time to wait for the device on the home LAN (returns as soon as it's seen)")
	fs.DurationVar(&s.dialTimeout, "dial-timeout", onboard.DefaultDialTimeout, "TLS handshake timeout")
	fs.StringVar(&s.rejoinSSID, "rejoin-ssid", "", "network the host rejoins afterwards (default: the one it was on before, else --home-ssid; password from env "+envRejoinPassword+")")
	fs.DurationVar(&s.findTimeout, "find-timeout", onboard.DefaultFindTimeout, "how long to keep looking for the device's SoftAP (e.g. right after a reset)")
	fs.DurationVar(&s.rejoinTimeout, "rejoin-timeout", onboard.DefaultRejoinTimeout, "how long to keep retrying the host's rejoin to the home network")
	fs.BoolVar(&s.json, "json", false, "emit events and results as NDJSON on stdout")
	fs.BoolVar(&s.verbose, "v", false, "verbose (debug) logging on stderr")
}

// options builds the library Options from the parsed flags. It resolves the
// home password, so it may prompt.
func (s *sharedFlags) options(stdin io.Reader, stderr io.Writer) (onboard.Options, error) {
	if s.homeSSID == "" {
		return onboard.Options{}, fmt.Errorf("--home-ssid is required (or set %s)", envHomeSSID)
	}
	sec, err := parseSecurity(s.security)
	if err != nil {
		return onboard.Options{}, err
	}
	var password string // open networks have none
	if sec != onboard.SecurityOpen {
		if password, err = readPassword(stdin, stderr, s.passwordStdin, s.homeSSID); err != nil {
			return onboard.Options{}, err
		}
	}
	opts := onboard.Options{
		SSID:          s.homeSSID,
		Password:      password,
		Security:      sec,
		Interface:     s.iface,
		LegacyTLS:     s.legacyTLS,
		DialTimeout:   s.dialTimeout,
		FindTimeout:   s.findTimeout,
		RejoinTimeout: s.rejoinTimeout,
		Logger:        newLogger(stderr, s.verbose),
	}
	if !s.noVerify {
		opts.VerifyTimeout = s.verifyTimeout
	}
	return opts, nil
}

var securityByName = map[string]onboard.Security{
	"open":       onboard.SecurityOpen,
	"wpa2-aes":   onboard.SecurityWpa2AesPsk,
	"wpa2-tkip":  onboard.SecurityWpa2TkipPsk,
	"wpa2-mixed": onboard.SecurityWpa2MixedPsk,
}

func securityNames() []string {
	return []string{"open", "wpa2-aes", "wpa2-tkip", "wpa2-mixed"}
}

func parseSecurity(name string) (onboard.Security, error) {
	sec, ok := securityByName[strings.ToLower(name)]
	if !ok {
		return 0, fmt.Errorf("unknown --security %q (want one of: %s)", name, strings.Join(securityNames(), ", "))
	}
	return sec, nil
}

// readPassword resolves the home WiFi password. Order: --password-stdin,
// then LIFX_ONBOARD_PASSWORD, then a no-echo prompt if stdin is a TTY. The
// password is never accepted as a plain flag so it stays out of shell
// history.
func readPassword(stdin io.Reader, stderr io.Writer, fromStdin bool, ssid string) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if p := os.Getenv(envPassword); p != "" {
		return p, nil
	}
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(stderr, "Password for %q: ", ssid)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return string(b), nil
	}
	return "", fmt.Errorf("no password: set %s, pass --password-stdin, or run interactively", envPassword)
}

// parseInterspersed parses fs while allowing positional arguments before,
// between, or after flags — the stdlib flag package stops at the first
// positional otherwise.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func newLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// signalContext returns a context cancelled on SIGINT/SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// attachSender wires a lifxlan-go Controller into opts for LAN verification.
// Returns a no-op closer when verification is disabled.
//
// The controller is started lazily, on the first GetDevices call — i.e.
// when verification begins, after the host has rejoined the home network.
// Started earlier, it keeps discovering while the host sits on the device's
// SoftAP, records the device at 172.16.0.1, and (sessions being keyed by
// serial) keeps that stale address until the session times out.
func attachSender(opts *onboard.Options) (func(), error) {
	if opts.VerifyTimeout <= 0 {
		return func() {}, nil
	}
	ls := &lazySender{
		newCtrl: func() (devicesSource, error) { return controller.New() },
		netKey:  localNetworkKey,
	}
	opts.Sender = ls
	return ls.close, nil
}

type devicesSource interface {
	GetDevices() []device.Device
	Close() error
}

// lazySender creates the LAN controller on first use and recreates it when
// the host's IPv4 addresses change. lifxlan-go computes its discovery
// broadcast address once, from the interfaces up at creation time; right
// after a rejoin the host may still be waiting for DHCP (creation fails) or
// may be moved to another network by the OS (broadcasts go to the old
// subnet). Creation failures are retried on the next poll.
type lazySender struct {
	mu      sync.Mutex
	newCtrl func() (devicesSource, error)
	netKey  func() string
	ctrl    devicesSource
	key     string
}

func (l *lazySender) GetDevices() []device.Device {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.netKey()
	if l.ctrl != nil && key != l.key {
		_ = l.ctrl.Close()
		l.ctrl = nil
	}
	if l.ctrl == nil {
		c, err := l.newCtrl()
		if err != nil {
			return nil
		}
		l.ctrl, l.key = c, key
	}
	return l.ctrl.GetDevices()
}

func (l *lazySender) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctrl != nil {
		_ = l.ctrl.Close()
	}
}

// localNetworkKey summarises the host's broadcast-capable IPv4 networks, so
// lazySender can tell when they change.
func localNetworkKey() string {
	ifaces, _ := net.Interfaces()
	var parts []string
	for _, ix := range ifaces {
		if ix.Flags&net.FlagUp == 0 || ix.Flags&net.FlagBroadcast == 0 || ix.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ix.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				parts = append(parts, ix.Name+"="+n.String())
			}
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// streamEvents starts a goroutine printing events from the returned channel.
// The stop func closes the channel and waits for the printer to drain, so
// every event is written before the final result.
func streamEvents(p *printer) (chan onboard.Event, func()) {
	ch := make(chan onboard.Event, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range ch {
			p.event(e)
		}
	}()
	return ch, func() {
		close(ch)
		<-done
	}
}

// exitCodeFor maps an onboarding outcome to a process exit code.
func exitCodeFor(ctx context.Context, res onboard.Result, err error) int {
	if err == nil {
		return exitOK
	}
	if ctx.Err() != nil {
		return exitInterrupted
	}
	if errors.Is(err, onboard.ErrMissingCredentials) || errors.Is(err, onboard.ErrInvalidBulbSSID) {
		return exitUsage
	}
	switch res.Phase {
	case onboard.PhaseScan:
		return exitScan
	case onboard.PhaseJoin:
		return exitJoin
	case onboard.PhaseWait:
		return exitWait
	case onboard.PhaseDial:
		return exitDial
	case onboard.PhaseConfigure:
		return exitConfigure
	case onboard.PhaseRejoin:
		return exitRejoin
	case onboard.PhaseVerify:
		return exitVerify
	}
	return exitFailure
}

// warnLocationAccess requests macOS Location Services (needed for scans to
// return real SSIDs) and warns when it isn't granted. No-op on builds where
// the request is unsupported.
func warnLocationAccess(stderr io.Writer) {
	status := onboard.RequestMacOSLocationAccess()
	if status != onboard.AuthStatusUnsupported && !status.Granted() {
		fmt.Fprintf(stderr, "warning: Location Services %s — scans will return redacted SSIDs. Run from the bundle (scripts/bundle.sh) and allow LifxOnboard in System Settings → Privacy & Security → Location Services.\n", status)
	}
}

// usageError prints msg plus the flag defaults and returns exitUsage.
func usageError(fs *flag.FlagSet, stderr io.Writer, msg string) int {
	fmt.Fprintf(stderr, "lifx-onboard %s: %s\n\n", fs.Name(), msg)
	fs.SetOutput(stderr)
	fs.Usage()
	return exitUsage
}
