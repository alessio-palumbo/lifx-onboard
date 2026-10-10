//go:build darwin

package scanner

import (
	"errors"
	"os"
	"testing"

	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func TestParseSystemProfiler_LIFXOnly(t *testing.T) {
	raw, err := os.ReadFile("testdata/system_profiler_sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	got, err := parseSystemProfiler(raw, ScanOptions{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d APs, want 2: %+v", len(got), got)
	}

	wantSerialAabbcc, _ := device.SerialFromHex("d073d5aabbcc")
	wantSerial112233, _ := device.SerialFromHex("d073d5112233")

	bySerial := map[device.Serial]AP{}
	for _, ap := range got {
		bySerial[ap.Serial] = ap
	}
	a, ok := bySerial[wantSerialAabbcc]
	if !ok {
		t.Fatalf("missing aabbcc AP; got %+v", bySerial)
	}
	if a.SSID != "LIFX Bulb aabbcc" {
		t.Errorf("SSID = %q, want %q", a.SSID, "LIFX Bulb aabbcc")
	}
	if a.BSSID != [6]byte{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc} {
		t.Errorf("BSSID = %x, want d073d5aabbcc", a.BSSID)
	}

	if _, ok := bySerial[wantSerial112233]; !ok {
		t.Fatalf("missing 112233 AP")
	}
}

func TestParseSystemProfiler_IncludeNonLIFX(t *testing.T) {
	raw, err := os.ReadFile("testdata/system_profiler_sample.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	got, err := parseSystemProfiler(raw, ScanOptions{IncludeNonLIFX: true})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// 2 LIFX + NeighborWifi. <redacted> and "LIFX Switch nothex" are both
	// filtered (the first explicitly, the second because its trailing 6
	// aren't hex and it has the LIFX prefix).
	if len(got) != 3 {
		t.Fatalf("got %d APs, want 3: %+v", len(got), got)
	}

	ssids := map[string]bool{}
	for _, ap := range got {
		ssids[ap.SSID] = true
	}
	if !ssids["NeighborWifi"] {
		t.Errorf("expected NeighborWifi in result, got %v", ssids)
	}
	if ssids["<redacted>"] {
		t.Errorf("expected <redacted> to be filtered out")
	}
}

func TestParseSystemProfiler_AllRedacted(t *testing.T) {
	raw := []byte(`{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0",
		"spairport_airport_other_local_wireless_networks":[{"_name":"<redacted>"},{"_name":"<redacted>"}]}]}]}`)
	if _, err := parseSystemProfiler(raw, ScanOptions{}); !errors.Is(err, ErrRedacted) {
		t.Fatalf("err = %v, want ErrRedacted", err)
	}

	// One hidden network among visible ones is not redaction.
	raw = []byte(`{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0",
		"spairport_airport_other_local_wireless_networks":[{"_name":"<redacted>"},{"_name":"LIFX A19 aabbcc"}]}]}]}`)
	aps, err := parseSystemProfiler(raw, ScanOptions{})
	if err != nil || len(aps) != 1 {
		t.Fatalf("aps=%v err=%v, want the LIFX AP and no error", aps, err)
	}
}
