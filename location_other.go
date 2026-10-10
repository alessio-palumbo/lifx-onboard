//go:build !darwin || !corewlan

package onboard

// RequestMacOSLocationAccess is a no-op on non-darwin platforms and on
// darwin when the `corewlan` build tag is absent.
func RequestMacOSLocationAccess() AuthStatus {
	return AuthStatusUnsupported
}
