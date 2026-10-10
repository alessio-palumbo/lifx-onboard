package wire

// PayloadTypeWifiSetAccessPoint is the 16-bit message type that carries home
// WiFi credentials to a device sitting in SoftAP mode.
const PayloadTypeWifiSetAccessPoint uint16 = 305

// WifiSetAccessPointSize is the on-wire payload length in bytes.
const WifiSetAccessPointSize = 98

// WifiInterface selects which radio interface the credentials apply to.
type WifiInterface uint8

const (
	WifiInterfaceUnknown WifiInterface = 0
	WifiInterfaceSoftAP  WifiInterface = 1
	// WifiInterfaceStation is the value to use when onboarding a device to a
	// home network.
	WifiInterfaceStation WifiInterface = 2
)

// WifiSecurity is the AP security mode of the home network the device should
// associate with.
type WifiSecurity uint8

const (
	WifiSecurityUnknown      WifiSecurity = 0
	WifiSecurityOpen         WifiSecurity = 1
	WifiSecurityWepPsk       WifiSecurity = 2
	WifiSecurityWpaTkipPsk   WifiSecurity = 3
	WifiSecurityWpaAesPsk    WifiSecurity = 4
	WifiSecurityWpa2AesPsk   WifiSecurity = 5
	WifiSecurityWpa2TkipPsk  WifiSecurity = 6
	WifiSecurityWpa2MixedPsk WifiSecurity = 7
)

// WifiSetAccessPoint is the request that hands a device its home WiFi
// credentials over the SoftAP TLS control channel. It implements the same
// packets.Payload contract as the public payloads.
//
// Wire layout (98 bytes, little-endian):
//
//	[0]      WifiInterface
//	[1..33)  SSID, NUL-padded
//	[33..97) Password, NUL-padded
//	[97]     WifiSecurity
type WifiSetAccessPoint struct {
	Interface WifiInterface
	SSID      [32]byte
	Password  [64]byte
	Security  WifiSecurity
}

// PayloadType returns the LIFX message type ID for WifiSetAccessPoint.
func (*WifiSetAccessPoint) PayloadType() uint16 { return PayloadTypeWifiSetAccessPoint }

// Size returns the fixed on-wire size.
func (*WifiSetAccessPoint) Size() int { return WifiSetAccessPointSize }

// MarshalBinary encodes the payload to its 98-byte wire form.
func (p *WifiSetAccessPoint) MarshalBinary() ([]byte, error) {
	buf := make([]byte, WifiSetAccessPointSize)
	buf[0] = uint8(p.Interface)
	copy(buf[1:33], p.SSID[:])
	copy(buf[33:97], p.Password[:])
	buf[97] = uint8(p.Security)
	return buf, nil
}

// UnmarshalBinary decodes a 98-byte wire payload into p.
func (p *WifiSetAccessPoint) UnmarshalBinary(data []byte) error {
	if len(data) < WifiSetAccessPointSize {
		return ErrShortPayload
	}
	p.Interface = WifiInterface(data[0])
	copy(p.SSID[:], data[1:33])
	copy(p.Password[:], data[33:97])
	p.Security = WifiSecurity(data[97])
	return nil
}

// SetSSID copies s into the SSID field, NUL-padding the remainder. Strings
// longer than 32 bytes are silently truncated to match device firmware
// behavior.
func (p *WifiSetAccessPoint) SetSSID(s string) *WifiSetAccessPoint {
	p.SSID = [32]byte{}
	copy(p.SSID[:], s)
	return p
}

// SetPassword copies s into the Password field, NUL-padding the remainder.
// Strings longer than 64 bytes are silently truncated.
func (p *WifiSetAccessPoint) SetPassword(s string) *WifiSetAccessPoint {
	p.Password = [64]byte{}
	copy(p.Password[:], s)
	return p
}
