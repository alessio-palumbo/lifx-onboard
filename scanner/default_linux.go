//go:build linux

package scanner

// NewDefaultScanner returns the iw-based scanner.
func NewDefaultScanner(iface string) Scanner { return NewIWScanner(iface) }

// NewDefaultJoiner returns the nmcli-based Joiner.
func NewDefaultJoiner(iface string) Joiner { return NewNmcliJoiner(iface) }
