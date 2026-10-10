package scanner

import (
	"testing"

	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func TestAPFromSSID(t *testing.T) {
	lifxSerial, _ := device.SerialFromHex("d073d58274eb")

	tests := []struct {
		name           string
		ssid           string
		includeNonLIFX bool
		wantOK         bool
		wantSerial     device.Serial
	}{
		{"lifx", "LIFX Candle Color 8274eb", false, true, lifxSerial},
		{"lifx uppercase hex", "LIFX Candle Color 8274EB", false, true, lifxSerial},
		{"lifx non-hex tail", "LIFX Bulb zzzzzz", true, false, device.Serial{}},
		{"non-lifx excluded", "My_Network", false, false, device.Serial{}},
		{"non-lifx included", "My_Network", true, true, device.Serial{}},
		// Ends in 6 hex chars but isn't a LIFX SoftAP: must not get a serial.
		{"non-lifx hex tail", "Neighbour4C0A17", true, true, device.Serial{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap, ok := APFromSSID(tt.ssid, tt.includeNonLIFX)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ap.Serial != tt.wantSerial {
				t.Errorf("Serial = %s, want %s", ap.Serial, tt.wantSerial)
			}
			if ok && ap.SSID != tt.ssid {
				t.Errorf("SSID = %q, want %q", ap.SSID, tt.ssid)
			}
		})
	}
}
