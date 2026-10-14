//go:build windows

package scanner

import (
	"testing"
	"unsafe"
)

// WLAN_CONNECTION_PARAMETERS is 40 bytes on 64-bit Windows and 24 on
// 32-bit; a mismatch would hand wlanapi.dll a garbled struct.
func TestWlanConnectionParametersSize(t *testing.T) {
	want := uintptr(24)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 40
	}
	if got := unsafe.Sizeof(wlanConnectionParameters{}); got != want {
		t.Fatalf("sizeof(wlanConnectionParameters) = %d, want %d", got, want)
	}
}
