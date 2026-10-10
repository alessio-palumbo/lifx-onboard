package onboard

import (
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// Event is the union of progress notifications emitted during onboarding.
// Consumers receive events by passing a buffered channel via Options.Events.
// The library never blocks on a slow consumer: if the channel is full the
// event is dropped.
type Event interface {
	isEvent()
}

// EventScanning fires at the start of each WiFi scan pass.
type EventScanning struct{ Interface string }

// EventDiscovered fires once per scan that found at least one candidate.
type EventDiscovered struct{ APs []scanner.AP }

// EventJoining fires before attempting to associate with a device SoftAP.
type EventJoining struct {
	Serial device.Serial
	SSID   string
}

// EventJoined fires once the host is associated with the device SoftAP.
type EventJoined struct{ Serial device.Serial }

// EventWaitingForSoftAP fires after the host joins the SoftAP SSID but
// before the TLS control socket is reachable. Used only by OnboardBySSID,
// where the join completes immediately but the bulb's TCP stack may take
// a moment to accept connections.
type EventWaitingForSoftAP struct {
	Serial  device.Serial
	Addr    string
	Timeout time.Duration
}

// EventOnSoftAP fires once the SoftAP control socket has accepted a TCP
// connection. The TLS dial follows immediately.
type EventOnSoftAP struct {
	Serial device.Serial
	Addr   string
	Took   time.Duration
}

// EventDialing fires before opening the TLS socket to the device.
type EventDialing struct {
	Serial device.Serial
	Addr   string
}

// EventConfigured fires after WifiSetAccessPoint has been written to the
// device.
type EventConfigured struct{ Serial device.Serial }

// EventRejoining fires before the host tries to rejoin SSID after the
// handoff. It may fire more than once when falling back to another network.
type EventRejoining struct {
	Serial device.Serial
	SSID   string
}

// EventRejoined fires once the host has rejoined SSID.
type EventRejoined struct {
	Serial device.Serial
	SSID   string
}

// EventVerifying fires when waiting for the device to re-appear on the home
// LAN via the consumer LANSender.
type EventVerifying struct {
	Serial  device.Serial
	Timeout time.Duration
}

// EventVerified fires when the device has been observed on the home LAN.
type EventVerified struct {
	Serial device.Serial
	Took   time.Duration
}

// EventFailed fires when a phase errors. Onboarding may continue with the
// next candidate (in BulkOnboard) or terminate (in Onboard) depending on
// caller policy.
type EventFailed struct {
	Serial device.Serial
	Phase  string
	Err    error
}

func (EventScanning) isEvent()         {}
func (EventDiscovered) isEvent()       {}
func (EventJoining) isEvent()          {}
func (EventJoined) isEvent()           {}
func (EventWaitingForSoftAP) isEvent() {}
func (EventOnSoftAP) isEvent()         {}
func (EventDialing) isEvent()          {}
func (EventConfigured) isEvent()       {}
func (EventRejoining) isEvent()        {}
func (EventRejoined) isEvent()         {}
func (EventVerifying) isEvent()        {}
func (EventVerified) isEvent()         {}
func (EventFailed) isEvent()           {}
