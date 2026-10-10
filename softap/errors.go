package softap

import "errors"

// Errors returned by Dial and Conn methods.
var (
	// ErrDial means the TLS connection to the device on its SoftAP could not
	// be established. The underlying cause is wrapped.
	ErrDial = errors.New("softap: TLS dial to device failed")

	// ErrSend means a payload could not be written to the SoftAP TLS socket.
	ErrSend = errors.New("softap: send to device failed")
)
