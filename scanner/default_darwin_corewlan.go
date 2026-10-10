//go:build darwin && corewlan

package scanner

// NewDefaultScanner returns the CoreWLAN-backed scanner. Built only when the
// `corewlan` build tag is set; without the tag the system_profiler scanner
// is used instead.
func NewDefaultScanner(iface string) Scanner { return NewCoreWLANScanner(iface) }

// NewDefaultJoiner returns the networksetup-based Joiner. CoreWLAN does
// support associateToNetwork directly, but for parity with the no-cgo build
// we keep the same Joiner.
func NewDefaultJoiner(iface string) Joiner { return NewNetworksetupJoiner(iface) }
