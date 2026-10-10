//go:build !darwin && !linux

package scanner

import "context"

type unsupportedScanner struct{}

func (unsupportedScanner) Scan(context.Context, ScanOptions) ([]AP, error) {
	return nil, ErrUnsupportedPlatform
}
func (unsupportedScanner) Interface() string { return "" }

type unsupportedJoiner struct{}

func (unsupportedJoiner) Join(context.Context, AP) error { return ErrUnsupportedPlatform }
func (unsupportedJoiner) RejoinHome(context.Context, string, string) error {
	return ErrUnsupportedPlatform
}

// NewDefaultScanner returns an unsupported-platform stub.
func NewDefaultScanner(iface string) Scanner { return unsupportedScanner{} }

// NewDefaultJoiner returns an unsupported-platform stub.
func NewDefaultJoiner(iface string) Joiner { return unsupportedJoiner{} }
