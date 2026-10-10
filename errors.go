package onboard

import (
	"errors"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifx-onboard/softap"
)

// Errors returned from Onboard and BulkOnboard. Errors from the subpackages
// are re-exported here so callers have a single place to match on.
var (
	// ErrUnsupportedPlatform is returned when WiFi scanning or joining is not
	// implemented for the current GOOS.
	ErrUnsupportedPlatform = scanner.ErrUnsupportedPlatform

	// ErrScanRedacted means a WiFi scan found networks but the OS hid their
	// names. On macOS: grant Location Services to an app launched by
	// LaunchServices (see the README).
	ErrScanRedacted = scanner.ErrRedacted

	// ErrNoDevicesFound means the WiFi scan completed without finding a LIFX
	// SoftAP matching the target/filter.
	ErrNoDevicesFound = errors.New("onboard: no SoftAP devices found")

	// ErrJoinFailed means the host could not associate with the device's
	// SoftAP. The underlying cause is wrapped.
	ErrJoinFailed = errors.New("onboard: failed to join device SoftAP")

	// ErrTLSDial means the TLS connection to the device could not be opened.
	ErrTLSDial = softap.ErrDial

	// ErrSend means a payload could not be written to the SoftAP TLS socket.
	ErrSend = softap.ErrSend

	// ErrVerifyTimeout means the onboarded device did not appear on the home
	// LAN within the configured verification window.
	ErrVerifyTimeout = errors.New("onboard: device did not re-appear on LAN before timeout")

	// ErrSoftAPWaitTimeout means the SoftAP control socket did not become
	// reachable within Options.WaitTimeout after the host joined the SoftAP
	// SSID. Used by OnboardBySSID.
	ErrSoftAPWaitTimeout = errors.New("onboard: SoftAP control socket did not respond before timeout")

	// ErrLeftSoftAP means the host dropped off the device's SoftAP while
	// waiting for it (e.g. the device was switched off and the OS rejoined
	// another network). Used by OnboardBySSID's wait phase.
	ErrLeftSoftAP = errors.New("onboard: host left the device SoftAP")

	// ErrInvalidBulbSSID means the SSID passed to OnboardBySSID does not
	// encode a recognizable LIFX device serial in its trailing 6 hex chars.
	ErrInvalidBulbSSID = errors.New("onboard: bulb SSID does not encode a LIFX serial")

	// ErrMissingCredentials means the home network SSID was not supplied, or
	// a secured network was requested without a password.
	ErrMissingCredentials = errors.New("onboard: home WiFi credentials not provided")
)
