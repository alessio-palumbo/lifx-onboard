package scanner

import (
	"encoding/binary"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func putDot11SSID(b []byte, ssid string) {
	binary.LittleEndian.PutUint32(b, uint32(len(ssid)))
	copy(b[4:], ssid)
}

func availableNetworkList(entries ...struct {
	ssid    string
	quality uint32
}) []byte {
	buf := make([]byte, wlanListHeaderSize+len(entries)*wlanAvailableNetworkSize)
	binary.LittleEndian.PutUint32(buf, uint32(len(entries)))
	for i, e := range entries {
		b := buf[wlanListHeaderSize+i*wlanAvailableNetworkSize:]
		putDot11SSID(b[wlanAvailNetSSIDLenOffset:], e.ssid)
		binary.LittleEndian.PutUint32(b[wlanAvailNetQualityOffset:], e.quality)
	}
	return buf
}

type netEntry = struct {
	ssid    string
	quality uint32
}

func TestParseWlanAvailableNetworkList(t *testing.T) {
	buf := availableNetworkList(
		netEntry{"LIFX Candle Color 8274eb", 60},
		netEntry{"My_Network", 90},
		netEntry{"LIFX Candle Color 8274eb", 80}, // same network, second profile entry
		netEntry{"", 50},                         // hidden network
		netEntry{"LIFX A19 aabbcc", 10},
	)
	got, err := parseWlanAvailableNetworkList(buf, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d APs, want 2 LIFX SoftAPs: %+v", len(got), got)
	}
	want, _ := device.SerialFromHex("d073d58274eb")
	if got[0].Serial != want || got[0].RSSI != -60 {
		t.Errorf("first AP = %+v, want serial %s with the stronger entry (-60 dBm)", got[0], want)
	}

	strong, _ := parseWlanAvailableNetworkList(buf, ScanOptions{MinRSSI: -70})
	if len(strong) != 1 {
		t.Errorf("MinRSSI -70 kept %d APs, want 1", len(strong))
	}

	all, _ := parseWlanAvailableNetworkList(buf, ScanOptions{IncludeNonLIFX: true})
	if len(all) != 3 {
		t.Errorf("IncludeNonLIFX kept %d APs, want 3 named networks", len(all))
	}
}

func TestParseWlanAvailableNetworkList_Redacted(t *testing.T) {
	buf := availableNetworkList(netEntry{"", 50}, netEntry{"", 70})
	if _, err := parseWlanAvailableNetworkList(buf, ScanOptions{}); !errors.Is(err, ErrRedacted) {
		t.Fatalf("err = %v, want ErrRedacted", err)
	}
	if _, err := parseWlanAvailableNetworkList(buf[:wlanListHeaderSize+10], ScanOptions{}); err == nil {
		t.Error("want an error for a truncated list")
	}
}

func TestParseWlanInterfaceList(t *testing.T) {
	buf := make([]byte, wlanListHeaderSize+2*wlanInterfaceInfoSize)
	binary.LittleEndian.PutUint32(buf, 2)
	for i, desc := range []string{"Intel(R) Wi-Fi 6 AX201", "USB WiFi"} {
		e := buf[wlanListHeaderSize+i*wlanInterfaceInfoSize:]
		e[0] = byte(i + 1) // GUID marker
		for j, c := range utf16.Encode([]rune(desc)) {
			binary.LittleEndian.PutUint16(e[wlanInterfaceDescOffset+2*j:], c)
		}
	}
	ifs, err := parseWlanInterfaceList(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) != 2 || ifs[0].description != "Intel(R) Wi-Fi 6 AX201" || ifs[1].guid[0] != 2 {
		t.Errorf("interfaces = %+v", ifs)
	}
}

func TestWlanCurrentSSID(t *testing.T) {
	buf := make([]byte, wlanConnAttrMinSize+100)
	putDot11SSID(buf[wlanConnAttrSSIDLenOffset:], "My_Network_5G")
	if got := wlanCurrentSSID(buf); got != "My_Network_5G" {
		t.Errorf("got %q", got)
	}
	if got := wlanCurrentSSID(buf[:10]); got != "" {
		t.Errorf("short buffer: got %q, want empty", got)
	}
}

func TestWlanProfileXML(t *testing.T) {
	for _, x := range []string{
		wlanOpenProfileXML("LIFX Candle Color 8274eb"),
		wlanPSKProfileXML(`Café & <Friends>`, `p@ss"word<>`),
	} {
		var doc struct {
			Name string `xml:"name"`
			SSID struct {
				Hex  string `xml:"hex"`
				Name string `xml:"name"`
			} `xml:"SSIDConfig>SSID"`
			Key string `xml:"MSM>security>sharedKey>keyMaterial"`
		}
		if err := xml.Unmarshal([]byte(x), &doc); err != nil {
			t.Fatalf("profile is not valid XML: %v\n%s", err, x)
		}
		if doc.Name == "" || doc.SSID.Hex == "" || doc.SSID.Name != doc.Name {
			t.Errorf("profile fields = %+v", doc)
		}
	}

	var psk struct {
		Name string `xml:"name"`
		Key  string `xml:"MSM>security>sharedKey>keyMaterial"`
	}
	_ = xml.Unmarshal([]byte(wlanPSKProfileXML(`Café & <Friends>`, `p@ss"word<>`)), &psk)
	if psk.Name != `Café & <Friends>` || psk.Key != `p@ss"word<>` {
		t.Errorf("escaping did not round-trip: %+v", psk)
	}
	if !strings.Contains(wlanOpenProfileXML("X"), "<connectionMode>manual</connectionMode>") {
		t.Error("SoftAP profile must not auto-connect")
	}
}
