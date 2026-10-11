//go:build linux

package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// IWScanner uses `iw dev <iface> scan` to enumerate visible WiFi APs. Reads
// BSSID, SSID, and signal level. Requires the iw tool and permission to
// scan (CAP_NET_ADMIN, usually root). NmcliScanner, the default, needs
// neither.
type IWScanner struct {
	iface string
}

// NewIWScanner returns a scanner that runs `iw dev <iface> scan`. When
// iface is empty the first wireless interface listed by `iw dev` is used.
func NewIWScanner(iface string) *IWScanner {
	return &IWScanner{iface: iface}
}

// Interface returns the WiFi interface name supplied at construction time.
func (s *IWScanner) Interface() string { return s.iface }

// Scan invokes iw and parses its output.
func (s *IWScanner) Scan(ctx context.Context, opts ScanOptions) ([]AP, error) {
	iface := s.iface
	if iface == "" {
		devs, err := exec.CommandContext(ctx, "iw", "dev").Output()
		if err != nil {
			return nil, fmt.Errorf("scanner: iw dev: %w", err)
		}
		if iface = firstIWInterface(string(devs)); iface == "" {
			return nil, fmt.Errorf("scanner: no wireless interface found by iw dev")
		}
	}
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "scan")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scanner: iw scan: %w", err)
	}
	return parseIWScan(out, opts)
}

// parseIWScan walks the output of `iw <iface> scan`, which is a sequence of
// blocks starting with `BSS <mac>` and containing indented `SSID:` and
// `signal:` lines.
func parseIWScan(raw []byte, opts ScanOptions) ([]AP, error) {
	var (
		out     []AP
		current AP
		haveBSS bool
	)

	flush := func() {
		if !haveBSS {
			return
		}
		defer func() {
			current = AP{}
			haveBSS = false
		}()
		if opts.MinRSSI != 0 && current.RSSI < opts.MinRSSI {
			return
		}
		ap, ok := APFromSSID(current.SSID, opts.IncludeNonLIFX)
		if !ok {
			return
		}
		// Preserve the iw-reported BSSID and RSSI over the derived ones.
		ap.BSSID = current.BSSID
		ap.RSSI = current.RSSI
		out = append(out, ap)
	}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "BSS "):
			flush()
			if b, ok := parseIWBSSID(line); ok {
				current.BSSID = b
				haveBSS = true
			}
		case strings.HasPrefix(line, "\tsignal:"):
			if !haveBSS {
				continue
			}
			// Format: `\tsignal: -54.00 dBm`
			rest := strings.TrimPrefix(line, "\tsignal:")
			rest = strings.TrimSpace(rest)
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				current.RSSI = v
			}
		case strings.HasPrefix(line, "\tSSID:"):
			if !haveBSS {
				continue
			}
			current.SSID = strings.TrimSpace(strings.TrimPrefix(line, "\tSSID:"))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner: read iw output: %w", err)
	}
	return out, nil
}

// parseIWBSSID extracts the 6-byte MAC from a line like `BSS d0:73:d5:aa:bb:cc(on wlan0)`.
func parseIWBSSID(line string) ([6]byte, bool) {
	rest := strings.TrimPrefix(line, "BSS ")
	if i := strings.IndexAny(rest, " ("); i >= 0 {
		rest = rest[:i]
	}
	return parseBSSIDColon(rest)
}

func parseBSSIDColon(s string) ([6]byte, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return [6]byte{}, false
	}
	var out [6]byte
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return [6]byte{}, false
		}
		out[i] = byte(v)
	}
	return out, true
}

// firstIWInterface returns the first "Interface <name>" from `iw dev`.
func firstIWInterface(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "Interface "); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}
