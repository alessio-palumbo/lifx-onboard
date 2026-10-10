// Package scanner defines the host WiFi scan and join contracts used by the
// onboard library. Platform implementations live in subpackages selected by
// build tag; tests and unusual setups (e.g. headless servers, BLE-driven
// provisioning) can supply their own.
package scanner

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// ErrUnsupportedPlatform is returned by NewDefaultScanner/NewDefaultJoiner
// on platforms where no WiFi scan/join backend is implemented.
var ErrUnsupportedPlatform = errors.New("scanner: WiFi scan/join not implemented on this platform")

// ErrRedacted is returned by Scan when networks were found but the OS hid
// every name. On macOS this means the process lacks Location Services or
// wasn't launched by LaunchServices as an app.
var ErrRedacted = errors.New("scanner: WiFi scan results are redacted by the OS (macOS: needs Location Services and a LaunchServices-launched app)")

// LIFXOUI is the first three bytes of every LIFX device's WiFi MAC.
var LIFXOUI = [3]byte{0xd0, 0x73, 0xd5}

// APFromSSID derives a Serial and BSSID from a LIFX SoftAP SSID, which always
// ends with the last 6 hex chars of the device's MAC. Returns ok=false if
// the SSID isn't a recognizable LIFX AP and includeNonLIFX is false.
//
// When includeNonLIFX is true, non-LIFX SSIDs are accepted with Serial and
// BSSID left zero — even if they happen to end with 6 hex chars (e.g.
// "Neighbour4C0A17"), they don't encode a LIFX serial.
func APFromSSID(ssid string, includeNonLIFX bool) (AP, bool) {
	isLIFX := strings.HasPrefix(ssid, "LIFX") && len(ssid) >= 10
	if !isLIFX {
		if includeNonLIFX {
			return AP{SSID: ssid}, true
		}
		return AP{}, false
	}

	tail := strings.ToLower(ssid[len(ssid)-6:])
	var suffix [3]byte
	if _, err := hex.Decode(suffix[:], []byte(tail)); err != nil {
		// Looks LIFX but the trailing 6 aren't hex — odd, drop it.
		return AP{}, false
	}
	return AP{
		SSID:   ssid,
		BSSID:  [6]byte{LIFXOUI[0], LIFXOUI[1], LIFXOUI[2], suffix[0], suffix[1], suffix[2]},
		Serial: device.Serial{LIFXOUI[0], LIFXOUI[1], LIFXOUI[2], suffix[0], suffix[1], suffix[2], 0, 0},
	}, true
}

// AP is a candidate SoftAP observed during a scan.
type AP struct {
	// Serial is derived from the trailing 6 hex characters of the SSID, which
	// match the device's WiFi MAC. Zero if the SSID does not encode a serial.
	Serial device.Serial
	SSID   string
	BSSID  [6]byte
	RSSI   float64
}

// Scanner enumerates WiFi networks visible to the host. Implementations are
// expected to return only LIFX SoftAPs unless the caller asks for everything
// via ScanOptions.IncludeNonLIFX.
type Scanner interface {
	// Scan performs a single scan pass and returns the visible APs. Returning
	// an empty slice with a nil error is valid.
	Scan(ctx context.Context, opts ScanOptions) ([]AP, error)

	// Interface returns the WiFi interface name the scanner is bound to, for
	// diagnostic logging.
	Interface() string
}

// ScanOptions controls a single scan pass.
type ScanOptions struct {
	// MinRSSI filters out APs weaker than this value. Zero disables the
	// filter.
	MinRSSI float64
	// IncludeNonLIFX disables the LIFX SSID-prefix filter. Useful for tests
	// and for devices flashed with custom SSIDs.
	IncludeNonLIFX bool
}

// CurrentNetworkReporter is optionally implemented by a Scanner or Joiner
// that can report the SSID the host is currently associated with. The
// onboard library uses it to rejoin the network the host was on before it
// joined a device's SoftAP. Returns "" when not associated or when the OS
// hides the name (macOS without Location Services).
type CurrentNetworkReporter interface {
	CurrentSSID(ctx context.Context) (string, error)
}

// NetworkForgetter is optionally implemented by a Joiner that can remove a
// network from the host's saved/preferred networks. Joining a SoftAP saves
// it (macOS ranks it near the top of the preferred list), which makes the
// OS's auto-join wait for that SoftAP to come back instead of returning to
// the original network — and clutters the user's saved networks.
type NetworkForgetter interface {
	Forget(ctx context.Context, ssid string) error
}

// Disassociator is optionally implemented by a Scanner or Joiner that can
// drop the host's current WiFi association. Used right after the handoff:
// the device keeps its SoftAP up for several seconds after receiving
// credentials, and the OS won't auto-join the original network while still
// associated with it.
type Disassociator interface {
	Disassociate(ctx context.Context) error
}

// Joiner controls host WiFi association. The onboard library uses it to join
// a device's SoftAP before opening the TLS control channel and, optionally,
// to rejoin the home network afterwards so that LAN verification can run.
type Joiner interface {
	// Join associates the host with the given SoftAP. Implementations should
	// be idempotent: a no-op if already connected.
	Join(ctx context.Context, ap AP) error

	// RejoinHome reconnects the host to ssid. If ssid is empty the host's
	// previously-configured default network is used. Implementations may
	// return nil without action if the platform handles this transparently.
	// password may be empty for open networks or when the SSID is already
	// saved in the platform's keychain/profile store.
	RejoinHome(ctx context.Context, ssid, password string) error
}
