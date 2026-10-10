package onboard

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/internal/wire"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifx-onboard/softap"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// Default timing values, exposed for callers that want to tune them.
const (
	DefaultVerifyTimeout = 60 * time.Second
	DefaultDialTimeout   = 10 * time.Second
	DefaultVerifyPoll    = 1 * time.Second
	DefaultWaitTimeout   = 30 * time.Second
	DefaultWaitPoll      = 1 * time.Second
	DefaultRejoinTimeout = 30 * time.Second
	DefaultRejoinPoll    = 2 * time.Second
	DefaultFindTimeout   = 30 * time.Second
	DefaultFindPoll      = 2 * time.Second
	DefaultAutoJoinWait  = 10 * time.Second
)

// Security is the home-network security mode advertised to the device.
type Security = wire.WifiSecurity

// Re-exported security constants so callers don't have to import internal/wire.
const (
	SecurityOpen         = wire.WifiSecurityOpen
	SecurityWpa2AesPsk   = wire.WifiSecurityWpa2AesPsk
	SecurityWpa2TkipPsk  = wire.WifiSecurityWpa2TkipPsk
	SecurityWpa2MixedPsk = wire.WifiSecurityWpa2MixedPsk
)

// Options configures a single call to Onboard.
type Options struct {
	// Target restricts the scan to a specific device serial. Zero matches the
	// first LIFX SoftAP found, optionally constrained by MinRSSI.
	Target device.Serial

	// SSID and Password are the home network credentials the device will use
	// after the handoff. SSID is required; an empty Password means an open
	// network.
	SSID, Password string

	// Security is the home network's security mode. Defaults to
	// SecurityWpa2AesPsk, or SecurityOpen when Password is empty.
	Security Security

	// MinRSSI optionally filters scan results.
	MinRSSI float64

	// IncludeNonLIFX widens the scan to non-LIFX APs. Useful for tests; do
	// not set for normal onboarding.
	IncludeNonLIFX bool

	// SoftAPAddr overrides the dial target. Defaults to softap.DefaultAddr.
	SoftAPAddr string

	// LegacyTLS forces TLS 1.0 + RSA-AES-CBC-SHA for very old firmware.
	LegacyTLS bool

	// DialTimeout bounds the TLS handshake. Defaults to DefaultDialTimeout.
	DialTimeout time.Duration

	// Sender is the LAN transport used during verification. Required if
	// VerifyTimeout > 0; ignored otherwise.
	Sender LANSender

	// VerifyTimeout controls how long Onboard waits for the device to reappear
	// on the home LAN. Zero (the zero value) disables verification — Onboard
	// returns once the host has rejoined. DefaultVerifyTimeout is a sensible
	// value to opt in with.
	VerifyTimeout time.Duration

	// VerifyPoll is the cadence used to poll Sender.GetDevices during
	// verification. Defaults to DefaultVerifyPoll.
	VerifyPoll time.Duration

	// RejoinSSID, if non-empty, is the network the host rejoins after the
	// handoff. When empty the host rejoins the network it was on before
	// joining the SoftAP (when the Scanner or Joiner can report it, see
	// scanner.CurrentNetworkReporter), falling back to SSID — the network
	// handed to the device.
	RejoinSSID string

	// RejoinPassword is passed to Joiner.RejoinHome with RejoinSSID. Needed
	// when the target isn't saved on the host; empty is fine for known
	// networks. Defaults to Password when RejoinSSID == SSID.
	RejoinPassword string

	// FindTimeout bounds how long the device's SoftAP is looked for before
	// giving up: Onboard keeps scanning, and every entry point keeps
	// retrying Joiner.Join. A freshly reset device can take a while to
	// bring its SoftAP up. Defaults to DefaultFindTimeout.
	FindTimeout time.Duration

	// FindPoll is the delay between scan / join attempts. Defaults to
	// DefaultFindPoll.
	FindPoll time.Duration

	// RejoinTimeout bounds how long Joiner.RejoinHome is retried. Right
	// after the device drops its SoftAP the host's WiFi may not see the
	// home network yet ("Could not find network"), so the first attempt
	// commonly fails. Defaults to DefaultRejoinTimeout.
	RejoinTimeout time.Duration

	// RejoinPoll is the delay between RejoinHome attempts. Defaults to
	// DefaultRejoinPoll.
	RejoinPoll time.Duration

	// AutoJoinWait is how long to wait for the OS to reconnect to the
	// host's original network on its own before forcing a join. The OS
	// auto-joins known networks once the SoftAP disappears, and a
	// concurrent explicit join tends to fail slowly ("tmpErr"). Only used
	// when the current network can be read (scanner.CurrentNetworkReporter).
	// Defaults to DefaultAutoJoinWait; negative disables the wait.
	AutoJoinWait time.Duration

	// WaitTimeout bounds how long OnboardBySSID waits for the SoftAP
	// control socket (172.16.0.1:56700 by default) to become reachable
	// after the join completes. Defaults to DefaultWaitTimeout.
	WaitTimeout time.Duration

	// WaitPoll is the cadence used while waiting for the SoftAP socket.
	// Defaults to DefaultWaitPoll.
	WaitPoll time.Duration

	// Scanner is the WiFi scan backend. Defaults to scanner.NewDefaultScanner.
	Scanner scanner.Scanner

	// Joiner is the WiFi association backend. Defaults to
	// scanner.NewDefaultJoiner.
	Joiner scanner.Joiner

	// Interface names the host WiFi interface. Passed through to the default
	// Scanner/Joiner constructors when Scanner/Joiner are nil.
	Interface string

	// Logger receives debug/info messages. Nil discards.
	Logger *slog.Logger

	// Events receives FSM transitions. Drops events when full or nil — never
	// blocks Onboard.
	Events chan<- Event
}

// defaults fills in zero-valued fields and validates required ones.
func (o *Options) defaults() error {
	if o.SSID == "" {
		return ErrMissingCredentials
	}
	switch {
	case o.Password == "" && o.Security != 0 && o.Security != SecurityOpen:
		return fmt.Errorf("%w: password required for a secured network", ErrMissingCredentials)
	case o.Password == "":
		o.Security = SecurityOpen
	case o.Security == 0:
		o.Security = SecurityWpa2AesPsk
	}
	if o.SoftAPAddr == "" {
		o.SoftAPAddr = softap.DefaultAddr
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.VerifyTimeout < 0 {
		o.VerifyTimeout = 0
	}
	if o.VerifyPoll <= 0 {
		o.VerifyPoll = DefaultVerifyPoll
	}
	if o.WaitTimeout <= 0 {
		o.WaitTimeout = DefaultWaitTimeout
	}
	if o.WaitPoll <= 0 {
		o.WaitPoll = DefaultWaitPoll
	}
	if o.FindTimeout <= 0 {
		o.FindTimeout = DefaultFindTimeout
	}
	if o.FindPoll <= 0 {
		o.FindPoll = DefaultFindPoll
	}
	if o.RejoinTimeout <= 0 {
		o.RejoinTimeout = DefaultRejoinTimeout
	}
	if o.RejoinPoll <= 0 {
		o.RejoinPoll = DefaultRejoinPoll
	}
	if o.AutoJoinWait == 0 {
		o.AutoJoinWait = DefaultAutoJoinWait
	}
	if o.Scanner == nil {
		o.Scanner = scanner.NewDefaultScanner(o.Interface)
	}
	if o.Joiner == nil {
		o.Joiner = scanner.NewDefaultJoiner(o.Interface)
	}
	return nil
}
