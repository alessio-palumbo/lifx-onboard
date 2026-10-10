package wire

import (
	"bytes"
	"testing"
)

func TestWifiSetAccessPoint_PayloadType(t *testing.T) {
	p := &WifiSetAccessPoint{}
	if got, want := p.PayloadType(), uint16(305); got != want {
		t.Fatalf("PayloadType = %d, want %d", got, want)
	}
	if got, want := p.Size(), 98; got != want {
		t.Fatalf("Size = %d, want %d", got, want)
	}
}

func TestWifiSetAccessPoint_MarshalBinary_GoldenBytes(t *testing.T) {
	p := &WifiSetAccessPoint{Interface: WifiInterfaceStation, Security: WifiSecurityWpa2AesPsk}
	p.SetSSID("home").SetPassword("secret")

	got, err := p.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(got) != WifiSetAccessPointSize {
		t.Fatalf("length = %d, want %d", len(got), WifiSetAccessPointSize)
	}

	want := make([]byte, WifiSetAccessPointSize)
	want[0] = byte(WifiInterfaceStation)
	copy(want[1:33], "home")
	copy(want[33:97], "secret")
	want[97] = byte(WifiSecurityWpa2AesPsk)

	if !bytes.Equal(got, want) {
		t.Fatalf("bytes mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestWifiSetAccessPoint_Roundtrip(t *testing.T) {
	in := &WifiSetAccessPoint{Interface: WifiInterfaceStation, Security: WifiSecurityWpa2MixedPsk}
	in.SetSSID("My Network 🏠").SetPassword("p@ssw0rd!")

	b, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	out := &WifiSetAccessPoint{}
	if err := out.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if out.Interface != in.Interface {
		t.Errorf("Interface: got %d, want %d", out.Interface, in.Interface)
	}
	if out.Security != in.Security {
		t.Errorf("Security: got %d, want %d", out.Security, in.Security)
	}
	if out.SSID != in.SSID {
		t.Errorf("SSID: got %x, want %x", out.SSID, in.SSID)
	}
	if out.Password != in.Password {
		t.Errorf("Password: got %x, want %x", out.Password, in.Password)
	}
}

func TestWifiSetAccessPoint_TruncatesOverlongInputs(t *testing.T) {
	p := &WifiSetAccessPoint{}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'A'
	}
	p.SetSSID(string(long))

	b, _ := p.MarshalBinary()
	for i := 1; i < 33; i++ {
		if b[i] != 'A' {
			t.Fatalf("SSID byte %d = %d, want 'A'", i, b[i])
		}
	}
}

func TestWifiSetAccessPoint_UnmarshalShort(t *testing.T) {
	p := &WifiSetAccessPoint{}
	if err := p.UnmarshalBinary(make([]byte, 10)); err != ErrShortPayload {
		t.Fatalf("err = %v, want ErrShortPayload", err)
	}
}
