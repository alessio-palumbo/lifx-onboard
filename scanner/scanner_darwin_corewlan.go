//go:build darwin && corewlan

package scanner

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework CoreWLAN
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#include <stdlib.h>

// lifx_corewlan_scan performs an active WiFi scan via CoreWLAN and returns a
// JSON-encoded array of {"ssid","bssid","rssi"} objects. The caller must
// free the returned pointer with free(). On failure, returns NULL and sets
// *errOut to a strdup'd error message (also caller-freed).
//
// iface may be NULL to use the default WiFi interface.
static char *lifx_corewlan_scan(const char *iface, char **errOut) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        CWInterface *cw = nil;
        if (iface != NULL && *iface != '\0') {
            cw = [client interfaceWithName:[NSString stringWithUTF8String:iface]];
        } else {
            cw = [client interface];
        }
        if (cw == nil) {
            *errOut = strdup("no WiFi interface available");
            return NULL;
        }

        NSError *err = nil;
        // includeHidden:YES forces an active probe rather than reading the
        // cached scan results, and reports hidden SSIDs too. Required on
        // Sequoia/Tahoe; the older scanForNetworksWithSSID:error: often
        // returns an empty set on those releases.
        NSSet<CWNetwork *> *networks = [cw scanForNetworksWithSSID:nil includeHidden:YES error:&err];
        if (err != nil) {
            const char *msg = [[err localizedDescription] UTF8String];
            *errOut = strdup(msg ? msg : "scanForNetworks failed");
            return NULL;
        }

        NSMutableArray *arr = [NSMutableArray arrayWithCapacity:[networks count]];
        for (CWNetwork *n in networks) {
            NSMutableDictionary *d = [NSMutableDictionary dictionary];
            d[@"ssid"] = n.ssid ?: @"";
            d[@"bssid"] = n.bssid ?: @"";
            d[@"rssi"] = @(n.rssiValue);
            [arr addObject:d];
        }

        NSError *jsonErr = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:arr options:0 error:&jsonErr];
        if (jsonErr != nil) {
            const char *msg = [[jsonErr localizedDescription] UTF8String];
            *errOut = strdup(msg ? msg : "json serialize failed");
            return NULL;
        }

        size_t len = [data length];
        char *buf = (char *)malloc(len + 1);
        if (buf == NULL) {
            *errOut = strdup("malloc failed");
            return NULL;
        }
        memcpy(buf, [data bytes], len);
        buf[len] = '\0';
        return buf;
    }
}

// lifx_corewlan_current_ssid returns a strdup'd copy of the SSID the
// interface is associated with, or NULL when not associated or redacted.
static char *lifx_corewlan_current_ssid(const char *iface) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        CWInterface *cw = (iface != NULL && *iface != '\0')
            ? [client interfaceWithName:[NSString stringWithUTF8String:iface]]
            : [client interface];
        NSString *ssid = [cw ssid];
        if (ssid == nil || [ssid length] == 0) {
            return NULL;
        }
        return strdup([ssid UTF8String]);
    }
}

// lifx_corewlan_disassociate drops the interface's current association.
static void lifx_corewlan_disassociate(const char *iface) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        CWInterface *cw = (iface != NULL && *iface != '\0')
            ? [client interfaceWithName:[NSString stringWithUTF8String:iface]]
            : [client interface];
        [cw disassociate];
    }
}
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"
)

// CoreWLANScanner uses Apple's CoreWLAN framework to perform an active WiFi
// scan, avoiding the system_profiler cache. SSIDs and BSSIDs come back
// empty unless the process was launched by LaunchServices as an app with
// Location Services granted (no `wifi-info` entitlement needed). Back-to-back
// scans can fail with "Resource busy" (scan throttling); callers retry.
//
// Requires building with the `corewlan` build tag. Falls back to
// SystemProfilerScanner when the tag is absent.
type CoreWLANScanner struct {
	iface string
}

// NewCoreWLANScanner returns a CoreWLAN-backed scanner. iface may be empty
// to use the system's default WiFi interface.
func NewCoreWLANScanner(iface string) *CoreWLANScanner {
	return &CoreWLANScanner{iface: iface}
}

// Interface returns the WiFi interface name supplied at construction time.
func (s *CoreWLANScanner) Interface() string { return s.iface }

// Disassociate drops the current WiFi association via
// CWInterface.disassociate. CoreWLAN reports no error; callers can check
// CurrentSSID afterwards.
func (s *CoreWLANScanner) Disassociate(context.Context) error {
	var cIface *C.char
	if s.iface != "" {
		cIface = C.CString(s.iface)
		defer C.free(unsafe.Pointer(cIface))
	}
	C.lifx_corewlan_disassociate(cIface)
	return nil
}

// CurrentSSID returns the SSID the host is associated with, or "" when not
// associated or when macOS redacts it (no Location Services, or not
// launched via LaunchServices).
func (s *CoreWLANScanner) CurrentSSID(context.Context) (string, error) {
	var cIface *C.char
	if s.iface != "" {
		cIface = C.CString(s.iface)
		defer C.free(unsafe.Pointer(cIface))
	}
	cSSID := C.lifx_corewlan_current_ssid(cIface)
	if cSSID == nil {
		return "", nil
	}
	defer C.free(unsafe.Pointer(cSSID))
	return C.GoString(cSSID), nil
}

// Scan performs an active WiFi scan via CWInterface.scanForNetworks.
func (s *CoreWLANScanner) Scan(ctx context.Context, opts ScanOptions) ([]AP, error) {
	var cIface *C.char
	if s.iface != "" {
		cIface = C.CString(s.iface)
		defer C.free(unsafe.Pointer(cIface))
	}

	var cErr *C.char
	cJSON := C.lifx_corewlan_scan(cIface, &cErr)
	if cJSON == nil {
		msg := "unknown error"
		if cErr != nil {
			msg = C.GoString(cErr)
			C.free(unsafe.Pointer(cErr))
		}
		return nil, fmt.Errorf("scanner: CoreWLAN scan: %s", msg)
	}
	defer C.free(unsafe.Pointer(cJSON))

	var raw []struct {
		SSID  string `json:"ssid"`
		BSSID string `json:"bssid"`
		RSSI  int    `json:"rssi"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cJSON)), &raw); err != nil {
		return nil, fmt.Errorf("scanner: parse CoreWLAN result: %w", err)
	}

	seen := make(map[string]bool)
	var out []AP
	emptySSIDs := 0
	for _, n := range raw {
		if n.SSID == "" {
			emptySSIDs++
			// In IncludeNonLIFX (diagnostic) mode emit even empty-SSID rows
			// keyed by BSSID, so a caller listing all APs can tell whether
			// the scan returned data with redacted/empty SSIDs.
			if opts.IncludeNonLIFX {
				ap := AP{RSSI: float64(n.RSSI)}
				if b, ok := parseBSSID(n.BSSID); ok {
					ap.BSSID = b
				}
				out = append(out, ap)
			}
			continue
		}
		if seen[n.SSID] {
			continue
		}
		ap, ok := APFromSSID(n.SSID, opts.IncludeNonLIFX)
		if !ok {
			continue
		}
		seen[n.SSID] = true
		if b, ok := parseBSSID(n.BSSID); ok {
			ap.BSSID = b
		}
		ap.RSSI = float64(n.RSSI)
		if opts.MinRSSI != 0 && ap.RSSI < opts.MinRSSI {
			continue
		}
		out = append(out, ap)
	}
	// A few empty SSIDs are hidden networks; all of them empty is redaction.
	if len(raw) > 0 && emptySSIDs == len(raw) {
		return nil, ErrRedacted
	}
	return out, nil
}

// parseBSSID converts the colon-separated form CoreWLAN returns
// ("d0:73:d5:aa:bb:cc") into a [6]byte. Returns ok=false on malformed input.
func parseBSSID(s string) ([6]byte, bool) {
	clean := strings.ReplaceAll(s, ":", "")
	if len(clean) != 12 {
		return [6]byte{}, false
	}
	var out [6]byte
	if _, err := hex.Decode(out[:], []byte(clean)); err != nil {
		return [6]byte{}, false
	}
	return out, true
}
