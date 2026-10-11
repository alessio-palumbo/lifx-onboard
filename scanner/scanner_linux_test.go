//go:build linux

package scanner

import (
	"os"
	"testing"

	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func TestParseIWScan_LIFXOnly(t *testing.T) {
	raw, err := os.ReadFile("testdata/iw_scan_sample.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	got, err := parseIWScan(raw, ScanOptions{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d APs, want 2: %+v", len(got), got)
	}

	wantSerial, _ := device.SerialFromHex("d073d5aabbcc")
	var ap AP
	for _, a := range got {
		if a.Serial == wantSerial {
			ap = a
			break
		}
	}
	if ap.Serial != wantSerial {
		t.Fatalf("missing aabbcc AP: %+v", got)
	}
	if ap.SSID != "LIFX Bulb aabbcc" {
		t.Errorf("SSID = %q, want %q", ap.SSID, "LIFX Bulb aabbcc")
	}
	if ap.BSSID != [6]byte{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc} {
		t.Errorf("BSSID = %x, want d073d5aabbcc", ap.BSSID)
	}
	if ap.RSSI != -54.00 {
		t.Errorf("RSSI = %v, want -54.00", ap.RSSI)
	}
}

func TestParseIWScan_MinRSSI(t *testing.T) {
	raw, _ := os.ReadFile("testdata/iw_scan_sample.txt")
	got, _ := parseIWScan(raw, ScanOptions{MinRSSI: -60})
	// Only the -54 AP survives the -60 floor.
	if len(got) != 1 {
		t.Fatalf("got %d APs, want 1 after MinRSSI=-60: %+v", len(got), got)
	}
	if got[0].RSSI != -54.00 {
		t.Errorf("survivor RSSI = %v, want -54.00", got[0].RSSI)
	}
}

func TestParseIWScan_IncludeNonLIFX(t *testing.T) {
	raw, _ := os.ReadFile("testdata/iw_scan_sample.txt")
	got, _ := parseIWScan(raw, ScanOptions{IncludeNonLIFX: true})
	// 2 LIFX + NeighborWifi. "LIFX Switch nothex" is dropped (trailing 6 not hex).
	if len(got) != 3 {
		t.Fatalf("got %d APs, want 3: %+v", len(got), got)
	}
	ssids := map[string]bool{}
	for _, a := range got {
		ssids[a.SSID] = true
	}
	if !ssids["NeighborWifi"] {
		t.Errorf("expected NeighborWifi in result, got %v", ssids)
	}
}

func TestParseNmcliActiveSSID(t *testing.T) {
	out := "no:Neighbour\nyes:My_Network\\:Home\nno:LIFX A19 aabbcc\n"
	if got := parseNmcliActiveSSID(out); got != "My_Network:Home" {
		t.Errorf("got %q, want %q", got, "My_Network:Home")
	}
	if got := parseNmcliActiveSSID("no:My_Network\n"); got != "" {
		t.Errorf("got %q, want empty when nothing is active", got)
	}
}

func TestParseNmcliWifiList(t *testing.T) {
	raw := []byte(`LIFX Candle Color 8274eb:A6\:4A\:0A\:01\:4F\:DB:72
LIFX Candle Color 8274eb:A6\:4A\:0A\:01\:4F\:DC:90
My\:Network:3C\:7C\:3F\:0A\:B1\:48:80
:00\:11\:22\:33\:44\:55:40
LIFX A19 aabbcc:D0\:73\:D5\:AA\:BB\:CC:20
`)
	got, err := parseNmcliWifiList(raw, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d APs, want 2 LIFX SoftAPs: %+v", len(got), got)
	}
	candle := got[0]
	want, _ := device.SerialFromHex("d073d58274eb")
	if candle.SSID != "LIFX Candle Color 8274eb" || candle.Serial != want {
		t.Errorf("first AP = %+v", candle)
	}
	if candle.RSSI != -55 || candle.BSSID != [6]byte{0xa6, 0x4a, 0x0a, 0x01, 0x4f, 0xdc} {
		t.Errorf("duplicate SSID should keep the strongest BSSID: rssi=%v bssid=%x", candle.RSSI, candle.BSSID)
	}

	all, _ := parseNmcliWifiList(raw, ScanOptions{IncludeNonLIFX: true})
	var sawEscaped bool
	for _, ap := range all {
		if ap.SSID == "My:Network" {
			sawEscaped = true
		}
	}
	if !sawEscaped {
		t.Errorf("escaped ':' in SSID not decoded: %+v", all)
	}

	strong, _ := parseNmcliWifiList(raw, ScanOptions{MinRSSI: -70})
	if len(strong) != 1 {
		t.Errorf("MinRSSI -70 kept %d APs, want 1 (signal 20 ≈ -90 dBm dropped)", len(strong))
	}
}

func TestFirstIWInterface(t *testing.T) {
	out := "phy#0\n\tUnnamed/non-netdev interface\n\tInterface wlan0\n\t\tifindex 3\n\tInterface wlan1\n"
	if got := firstIWInterface(out); got != "wlan0" {
		t.Errorf("got %q, want wlan0", got)
	}
}
