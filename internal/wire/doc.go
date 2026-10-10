// Package wire holds LIFX protocol payloads that the onboard library needs
// but that are not present in the public lifxprotocol-go module.
//
// The payloads here implement the same packets.Payload interface as the
// public ones and are otherwise indistinguishable on the wire. The
// set-access-point message (type 305 / 0x131, 98-byte payload, security
// values 1–7) is implemented from publicly available third-party
// documentation and code, e.g.:
//
//   - https://github.com/magicmonkey/lifxjs/blob/master/Protocol.md
//   - https://github.com/tserong/lifx-hacks/blob/master/onboard.py
//
// The package is internal so the private payload types never leak into a
// consumer's API surface.
package wire
