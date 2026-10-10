package onboard

// AuthStatus mirrors CLAuthorizationStatus from CoreLocation. It is returned
// by RequestMacOSLocationAccess so callers can decide whether to proceed.
type AuthStatus int

const (
	// AuthStatusUnsupported indicates the current build cannot request
	// Location Services. Returned on non-darwin platforms or when the binary
	// was not built with the `corewlan` build tag.
	AuthStatusUnsupported AuthStatus = -1

	// AuthStatusNotDetermined means the user has not yet decided. Usually
	// means the process is not a LaunchServices-launched app with the right
	// Info.plist entry, so the system prompt could not be shown.
	AuthStatusNotDetermined AuthStatus = 0

	AuthStatusRestricted AuthStatus = 1
	AuthStatusDenied     AuthStatus = 2

	// AuthStatusAuthorizedAlways is the legacy "always" grant.
	AuthStatusAuthorizedAlways AuthStatus = 3

	// AuthStatusAuthorizedWhenInUse is the modern "while app is open" grant
	// — sufficient for the SoftAP scanner to return real SSIDs.
	AuthStatusAuthorizedWhenInUse AuthStatus = 4
)

// String returns a human-readable name for the status.
func (a AuthStatus) String() string {
	switch a {
	case AuthStatusUnsupported:
		return "Unsupported"
	case AuthStatusNotDetermined:
		return "NotDetermined"
	case AuthStatusRestricted:
		return "Restricted"
	case AuthStatusDenied:
		return "Denied"
	case AuthStatusAuthorizedAlways:
		return "AuthorizedAlways"
	case AuthStatusAuthorizedWhenInUse:
		return "AuthorizedWhenInUse"
	}
	return "Unknown"
}

// Granted reports whether the status allows Location Services use.
func (a AuthStatus) Granted() bool {
	return a == AuthStatusAuthorizedAlways || a == AuthStatusAuthorizedWhenInUse
}
