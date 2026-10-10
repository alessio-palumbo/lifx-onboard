//go:build darwin

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// SystemProfilerScanner shells out to `system_profiler SPAirPortDataType
// -json` and parses the resulting JSON. It works on Sonoma and Sequoia
// without sudo or entitlements, with two caveats worth knowing:
//
//   - SSIDs are redacted unless the calling process was launched by
//     LaunchServices as an app with Location Services granted (a binary
//     run from a terminal is attributed to the terminal and gets
//     "<redacted>"). See the README's macOS section.
//   - The reported list can be cached up to ~30s by the OS. For an active
//     scan use the CoreWLAN scanner (build with `-tags corewlan`).
//
// BSSID and RSSI are not exposed by system_profiler. BSSID is derived from
// the SSID (last 6 hex chars over LIFX OUI). RSSI is left zero.
type SystemProfilerScanner struct {
	iface string
}

// NewSystemProfilerScanner returns a scanner that uses system_profiler.
// iface is informational only — system_profiler reports across all WiFi
// interfaces.
func NewSystemProfilerScanner(iface string) *SystemProfilerScanner {
	return &SystemProfilerScanner{iface: iface}
}

// Interface returns the WiFi interface name supplied at construction time.
func (s *SystemProfilerScanner) Interface() string { return s.iface }

// Scan invokes system_profiler and parses its output.
func (s *SystemProfilerScanner) Scan(ctx context.Context, opts ScanOptions) ([]AP, error) {
	cmd := exec.CommandContext(ctx, "system_profiler", "SPAirPortDataType", "-json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scanner: system_profiler: %w", err)
	}
	return parseSystemProfiler(out, opts)
}

// systemProfilerOutput is the subset of the system_profiler JSON the scanner
// reads. Field names are stable across Sonoma and Sequoia.
type systemProfilerOutput struct {
	SPAirPortDataType []struct {
		Interfaces []struct {
			Name           string                  `json:"_name"`
			OtherNetworks  []systemProfilerNetwork `json:"spairport_airport_other_local_wireless_networks"`
			CurrentNetwork *systemProfilerNetwork  `json:"spairport_current_network_information,omitempty"`
		} `json:"spairport_airport_interfaces"`
	} `json:"SPAirPortDataType"`
}

type systemProfilerNetwork struct {
	Name     string `json:"_name"`
	Security string `json:"spairport_security_mode"`
}

func parseSystemProfiler(raw []byte, opts ScanOptions) ([]AP, error) {
	var doc systemProfilerOutput
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("scanner: parse system_profiler: %w", err)
	}

	seen := make(map[string]bool)
	var out []AP
	total, redacted := 0, 0
	for _, top := range doc.SPAirPortDataType {
		for _, iface := range top.Interfaces {
			for _, n := range iface.OtherNetworks {
				total++
				if n.Name == "" || n.Name == "<redacted>" {
					redacted++
					continue
				}
				if seen[n.Name] {
					continue
				}
				ap, ok := APFromSSID(n.Name, opts.IncludeNonLIFX)
				if !ok {
					continue
				}
				seen[n.Name] = true
				out = append(out, ap)
			}
		}
	}
	if total > 0 && redacted == total {
		return nil, ErrRedacted
	}
	return out, nil
}
