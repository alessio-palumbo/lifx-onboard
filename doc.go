// Package onboard drives LIFX SoftAP onboarding from a host machine.
//
// A factory-fresh LIFX device advertises its own WiFi network (SSID prefixed
// with "LIFX"). Onboarding joins that network, opens a TLS connection to the
// device on 172.16.0.1:56700, and sends a single payload carrying the home
// WiFi credentials. The device then reboots and joins the home network.
//
// This module owns only the SoftAP control channel. Discovery and message
// delivery for already-onboarded devices on the home LAN are delegated to
// the consumer via the LANSender interface; lifxlan-go's
// *controller.Controller satisfies it without any adapter.
package onboard
