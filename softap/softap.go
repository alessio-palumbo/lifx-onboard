// Package softap owns the TLS control channel to a LIFX device sitting in
// SoftAP mode. It is the only socket-level component in the onboard library.
package softap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/internal/wire"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
	"github.com/alessio-palumbo/lifxlan-go/pkg/protocol"
	"github.com/alessio-palumbo/lifxprotocol-go/gen/protocol/packets"
)

// DefaultAddr is the well-known address a LIFX device exposes while in
// SoftAP mode.
const DefaultAddr = "172.16.0.1:56700"

// DefaultDialTimeout is the default TCP/TLS dial deadline.
const DefaultDialTimeout = 10 * time.Second

// Options configures a Conn.
type Options struct {
	// Addr to dial. Defaults to DefaultAddr when empty.
	Addr string
	// DialTimeout bounds the TLS handshake. Defaults to DefaultDialTimeout
	// when zero.
	DialTimeout time.Duration
	// LegacyTLS forces TLS 1.0 with the legacy RSA-AES-CBC-SHA cipher suite
	// for devices running pre-2020 firmware. Off by default.
	LegacyTLS bool
}

// Conn is a TLS connection to a single SoftAP device.
type Conn struct {
	tls *tls.Conn
}

// Dial opens a TLS connection to the device.
func Dial(opts Options) (*Conn, error) {
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}

	cfg := &tls.Config{
		InsecureSkipVerify: true, // the device presents a self-signed cert
		MinVersion:         tls.VersionTLS12,
	}
	if opts.LegacyTLS {
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS10
		// Old firmware only speaks this suite.
		cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	}

	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	c, err := tls.DialWithDialer(dialer, "tcp4", opts.Addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDial, err)
	}
	return &Conn{tls: c}, nil
}

// SendSetAccessPoint pushes the home WiFi credentials to the device. target
// is the device serial as carried in the LIFX header; pass the zero value to
// leave it unaddressed (the device only ever sees its own AP traffic so
// addressing is largely advisory here).
func (c *Conn) SendSetAccessPoint(target device.Serial, ssid, password string, security wire.WifiSecurity) error {
	payload := &wire.WifiSetAccessPoint{Interface: wire.WifiInterfaceStation, Security: security}
	payload.SetSSID(ssid).SetPassword(password)

	msg := protocol.NewMessage(payload)
	msg.SetTarget([8]byte(target))

	bytes, err := msg.MarshalBinary()
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrSend, err)
	}
	if _, err := c.tls.Write(bytes); err != nil {
		return fmt.Errorf("%w: write: %v", ErrSend, err)
	}
	return nil
}

// Close tears down the TLS connection.
func (c *Conn) Close() error {
	if c == nil || c.tls == nil {
		return nil
	}
	err := c.tls.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// Compile-time assertion that the private payload satisfies the public
// packets.Payload interface — guards against drift in lifxprotocol-go.
var _ packets.Payload = (*wire.WifiSetAccessPoint)(nil)
