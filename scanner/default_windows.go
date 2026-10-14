//go:build windows

package scanner

// NewDefaultScanner returns the native WLAN API client.
func NewDefaultScanner(iface string) Scanner { return NewWlanClient(iface) }

// NewDefaultJoiner returns the native WLAN API client.
func NewDefaultJoiner(iface string) Joiner { return NewWlanClient(iface) }
