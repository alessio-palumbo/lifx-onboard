//go:build linux

package scanner

// NewDefaultScanner returns the nmcli-based scanner (no root needed).
func NewDefaultScanner(iface string) Scanner { return NewNmcliScanner(iface) }

// NewDefaultJoiner returns the nmcli-based Joiner.
func NewDefaultJoiner(iface string) Joiner { return NewNmcliJoiner(iface) }
