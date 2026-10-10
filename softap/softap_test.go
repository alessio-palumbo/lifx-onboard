package softap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/internal/wire"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// fakeAP is an in-process TLS server that captures the first message a
// client sends and stores its bytes.
type fakeAP struct {
	listener net.Listener
	received chan []byte
	closed   chan struct{}
}

func newFakeAP(t *testing.T) *fakeAP {
	t.Helper()

	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	f := &fakeAP{
		listener: ln,
		received: make(chan []byte, 1),
		closed:   make(chan struct{}),
	}

	go func() {
		defer close(f.closed)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return
		}
		f.received <- buf[:n]
	}()

	return f
}

func (f *fakeAP) Addr() string { return f.listener.Addr().String() }
func (f *fakeAP) Close() error { return f.listener.Close() }

func TestDial_Succeeds(t *testing.T) {
	ap := newFakeAP(t)
	defer ap.Close()

	conn, err := Dial(Options{Addr: ap.Addr(), DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDial_BadAddr_WrapsErrDial(t *testing.T) {
	// 127.0.0.1:1 should reject — nothing listening.
	_, err := Dial(Options{Addr: "127.0.0.1:1", DialTimeout: 500 * time.Millisecond})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrDial) {
		t.Fatalf("err = %v, want wrapped ErrDial", err)
	}
}

func TestSendSetAccessPoint_RoundtripOverTLS(t *testing.T) {
	ap := newFakeAP(t)
	defer ap.Close()

	conn, err := Dial(Options{Addr: ap.Addr(), DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	target, _ := device.SerialFromHex("d073d5aabbcc")
	if err := conn.SendSetAccessPoint(target, "home", "secret", wire.WifiSecurityWpa2AesPsk); err != nil {
		t.Fatalf("SendSetAccessPoint: %v", err)
	}
	conn.Close()

	var raw []byte
	select {
	case raw = <-ap.received:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive any bytes")
	}

	// 36-byte header + 98-byte payload.
	const wantLen = 36 + 98
	if len(raw) != wantLen {
		t.Fatalf("received %d bytes, want %d (raw: %s)", len(raw), wantLen, hex.EncodeToString(raw))
	}

	// Header field offsets per the LIFX wire format.
	if got, want := binary.LittleEndian.Uint16(raw[0:]), uint16(wantLen); got != want {
		t.Errorf("header size = %d, want %d", got, want)
	}
	var gotTarget [8]byte
	copy(gotTarget[:], raw[8:16])
	if gotTarget != [8]byte(target) {
		t.Errorf("target = %x, want %x", gotTarget, target)
	}
	if got, want := binary.LittleEndian.Uint16(raw[32:]), uint16(wire.PayloadTypeWifiSetAccessPoint); got != want {
		t.Errorf("payload type = %d, want %d", got, want)
	}

	payload := raw[36:]
	if payload[0] != byte(wire.WifiInterfaceStation) {
		t.Errorf("interface byte = %d, want %d", payload[0], wire.WifiInterfaceStation)
	}
	if got := string(trimNUL(payload[1:33])); got != "home" {
		t.Errorf("ssid = %q, want %q", got, "home")
	}
	if got := string(trimNUL(payload[33:97])); got != "secret" {
		t.Errorf("password = %q, want %q", got, "secret")
	}
	if payload[97] != byte(wire.WifiSecurityWpa2AesPsk) {
		t.Errorf("security byte = %d, want %d", payload[97], wire.WifiSecurityWpa2AesPsk)
	}
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// selfSignedCert builds a throwaway RSA cert/key pair suitable only for an
// in-process test TLS handshake.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lifx-fake-ap"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
