//go:build linux

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// NmcliScanner lists visible WiFi networks through NetworkManager
// (`nmcli device wifi list`). Unlike `iw scan` it needs no root and no
// interface name, and nmcli is already required for joining.
type NmcliScanner struct {
	iface string
}

// NewNmcliScanner returns an nmcli-backed scanner. iface may be empty to
// scan on every WiFi device NetworkManager manages.
func NewNmcliScanner(iface string) *NmcliScanner {
	return &NmcliScanner{iface: iface}
}

// Interface returns the WiFi interface name supplied at construction time.
func (s *NmcliScanner) Interface() string { return s.iface }

// Scan asks NetworkManager for a fresh scan. NetworkManager rate-limits
// rescans ("Scanning not allowed immediately following previous scan"); in
// that case the most recent cached results are returned instead.
func (s *NmcliScanner) Scan(ctx context.Context, opts ScanOptions) ([]AP, error) {
	out, err := s.list(ctx, "yes")
	if err != nil {
		if out, err = s.list(ctx, "no"); err != nil {
			return nil, err
		}
	}
	return parseNmcliWifiList(out, opts)
}

func (s *NmcliScanner) list(ctx context.Context, rescan string) ([]byte, error) {
	args := []string{"-t", "-f", "SSID,BSSID,SIGNAL", "device", "wifi", "list", "--rescan", rescan}
	if s.iface != "" {
		args = append(args, "ifname", s.iface)
	}
	out, err := exec.CommandContext(ctx, "nmcli", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("scanner: nmcli wifi list: %w", err)
	}
	return out, nil
}

// parseNmcliWifiList parses `nmcli -t -f SSID,BSSID,SIGNAL device wifi list`.
// SIGNAL is a 0–100 quality figure; it is mapped to an approximate dBm
// (quality/2 - 100) so MinRSSI means the same on every platform. Networks
// seen through several BSSIDs keep the strongest one.
func parseNmcliWifiList(raw []byte, opts ScanOptions) ([]AP, error) {
	var out []AP
	index := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		f := splitTerse(sc.Text())
		if len(f) != 3 || f[0] == "" {
			continue
		}
		quality, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		rssi := float64(quality)/2 - 100
		if opts.MinRSSI != 0 && rssi < opts.MinRSSI {
			continue
		}
		ap, ok := APFromSSID(f[0], opts.IncludeNonLIFX)
		if !ok {
			continue
		}
		if b, ok := parseColonBSSID(f[1]); ok {
			ap.BSSID = b
		}
		ap.RSSI = rssi
		if i, seen := index[ap.SSID]; seen {
			if rssi > out[i].RSSI {
				out[i] = ap
			}
			continue
		}
		index[ap.SSID] = len(out)
		out = append(out, ap)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner: read nmcli output: %w", err)
	}
	return out, nil
}

// splitTerse splits one line of nmcli terse (-t) output into fields. In
// terse mode ':' separates fields and literal ':' / '\' inside values are
// escaped with a backslash.
func splitTerse(line string) []string {
	var (
		fields []string
		cur    strings.Builder
	)
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case c == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(fields, cur.String())
}

// parseColonBSSID parses "A6:4A:0A:01:4F:DB" into a [6]byte.
func parseColonBSSID(s string) ([6]byte, bool) {
	var b [6]byte
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return b, false
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return [6]byte{}, false
		}
		b[i] = byte(v)
	}
	return b, true
}
