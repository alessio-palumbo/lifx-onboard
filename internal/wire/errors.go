package wire

import "errors"

// ErrShortPayload is returned by UnmarshalBinary when fewer bytes were
// supplied than the payload's fixed Size.
var ErrShortPayload = errors.New("wire: payload too short")
