package scanner

// Platform-independent helpers for the Windows WLAN API backend
// (wlan_windows.go): decoding the structs wlanapi.dll returns and building
// the profile XML it consumes. Kept free of build tags so they are tested
// on every platform.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Sizes and offsets of the wlanapi.h structs we read. Every field is 4-byte
// aligned, so these hold on 32- and 64-bit Windows alike.
const (
	wlanListHeaderSize         = 8   // dwNumberOfItems, dwIndex
	wlanInterfaceInfoSize      = 532 // GUID (16) + WCHAR[256] + state (4)
	wlanAvailableNetworkSize   = 628
	wlanAvailNetSSIDLenOffset  = 512 // after WCHAR strProfileName[256]
	wlanAvailNetSSIDOffset     = 516
	wlanAvailNetQualityOffset  = 604 // wlanSignalQuality, 0–100
	wlanConnAttrSSIDLenOffset  = 520 // WLAN_CONNECTION_ATTRIBUTES.wlanAssociationAttributes.dot11Ssid
	wlanConnAttrSSIDOffset     = 524
	wlanConnAttrMinSize        = wlanConnAttrSSIDOffset + 32
	wlanInterfaceDescOffset    = 16
	wlanInterfaceDescByteCount = 512
)

// wlanInterface is one entry of WLAN_INTERFACE_INFO_LIST.
type wlanInterface struct {
	guid        [16]byte
	description string
}

// parseWlanInterfaceList decodes a WLAN_INTERFACE_INFO_LIST.
func parseWlanInterfaceList(buf []byte) ([]wlanInterface, error) {
	n, err := wlanListCount(buf, wlanInterfaceInfoSize)
	if err != nil {
		return nil, err
	}
	out := make([]wlanInterface, 0, n)
	for i := 0; i < n; i++ {
		e := buf[wlanListHeaderSize+i*wlanInterfaceInfoSize:]
		var ifc wlanInterface
		copy(ifc.guid[:], e[:16])
		ifc.description = utf16String(e[wlanInterfaceDescOffset : wlanInterfaceDescOffset+wlanInterfaceDescByteCount])
		out = append(out, ifc)
	}
	return out, nil
}

// parseWlanAvailableNetworkList decodes a WLAN_AVAILABLE_NETWORK_LIST into
// APs. Signal quality (0–100) is mapped to an approximate dBm (quality/2 -
// 100), as on Linux. Networks listed more than once (one entry per saved
// profile) keep the strongest. Returns ErrRedacted when networks are listed
// but none has a name.
func parseWlanAvailableNetworkList(buf []byte, opts ScanOptions) ([]AP, error) {
	n, err := wlanListCount(buf, wlanAvailableNetworkSize)
	if err != nil {
		return nil, err
	}
	var (
		out     []AP
		index   = map[string]int{}
		unnamed int
	)
	for i := 0; i < n; i++ {
		e := buf[wlanListHeaderSize+i*wlanAvailableNetworkSize:]
		ssid := dot11SSID(e[wlanAvailNetSSIDLenOffset:])
		if ssid == "" {
			unnamed++
			continue
		}
		quality := binary.LittleEndian.Uint32(e[wlanAvailNetQualityOffset:])
		rssi := float64(quality)/2 - 100
		if opts.MinRSSI != 0 && rssi < opts.MinRSSI {
			continue
		}
		ap, ok := APFromSSID(ssid, opts.IncludeNonLIFX)
		if !ok {
			continue
		}
		ap.RSSI = rssi
		if j, seen := index[ap.SSID]; seen {
			if rssi > out[j].RSSI {
				out[j] = ap
			}
			continue
		}
		index[ap.SSID] = len(out)
		out = append(out, ap)
	}
	if n > 0 && unnamed == n {
		return nil, ErrRedacted
	}
	return out, nil
}

// wlanCurrentSSID extracts the associated SSID from a
// WLAN_CONNECTION_ATTRIBUTES struct.
func wlanCurrentSSID(buf []byte) string {
	if len(buf) < wlanConnAttrMinSize {
		return ""
	}
	return dot11SSID(buf[wlanConnAttrSSIDLenOffset:])
}

// dot11SSID decodes a DOT11_SSID (ULONG length + UCHAR[32]).
func dot11SSID(b []byte) string {
	if len(b) < 36 {
		return ""
	}
	n := binary.LittleEndian.Uint32(b)
	if n > 32 {
		return ""
	}
	return string(b[4 : 4+n])
}

func wlanListCount(buf []byte, entrySize int) (int, error) {
	if len(buf) < wlanListHeaderSize {
		return 0, fmt.Errorf("scanner: WLAN list too short (%d bytes)", len(buf))
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if len(buf) < wlanListHeaderSize+n*entrySize {
		return 0, fmt.Errorf("scanner: WLAN list truncated: %d entries in %d bytes", n, len(buf))
	}
	return n, nil
}

func utf16String(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// wlanOpenProfileXML is a WLAN profile for an open network such as a LIFX
// SoftAP. connectionMode is manual so Windows never auto-joins it later.
func wlanOpenProfileXML(ssid string) string {
	return wlanProfileXML(ssid, "manual", `<authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption>`)
}

// wlanPSKProfileXML is a WPA2-Personal profile for a network that has no
// saved profile yet. It auto-connects like a network joined from the UI.
func wlanPSKProfileXML(ssid, password string) string {
	return wlanProfileXML(ssid, "auto", `<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>`+
		`<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>`+xmlEscape(password)+`</keyMaterial></sharedKey>`)
}

func wlanProfileXML(ssid, mode, security string) string {
	name := xmlEscape(ssid)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">`)
	b.WriteString(`<name>` + name + `</name>`)
	// hex takes precedence over name, so non-ASCII SSIDs survive exactly.
	b.WriteString(`<SSIDConfig><SSID><hex>` + strings.ToUpper(hex.EncodeToString([]byte(ssid))) + `</hex><name>` + name + `</name></SSID></SSIDConfig>`)
	b.WriteString(`<connectionType>ESS</connectionType><connectionMode>` + mode + `</connectionMode>`)
	b.WriteString(`<MSM><security>` + security + `</security></MSM>`)
	b.WriteString(`</WLANProfile>`)
	return b.String()
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
