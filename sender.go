package onboard

import "github.com/alessio-palumbo/lifxlan-go/pkg/device"

// LANSender is the minimum surface the onboard library requires from the
// consumer's LAN transport. lifxlan-go's *controller.Controller satisfies
// this interface as-is — no adapter required.
//
// The library polls GetDevices during the verification phase to detect when
// a freshly-onboarded device has rejoined the home network.
type LANSender interface {
	GetDevices() []device.Device
}
