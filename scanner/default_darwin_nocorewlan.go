//go:build darwin && !corewlan

package scanner

// NewDefaultScanner returns the system_profiler-based scanner. Build with
// `-tags corewlan` to use the CoreWLAN-backed scanner instead.
func NewDefaultScanner(iface string) Scanner { return NewSystemProfilerScanner(iface) }

// NewDefaultJoiner returns the networksetup-based Joiner.
func NewDefaultJoiner(iface string) Joiner { return NewNetworksetupJoiner(iface) }
