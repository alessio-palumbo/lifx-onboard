//go:build darwin

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// NetworksetupJoiner uses macOS's `networksetup -setairportnetwork` to join
// WiFi networks. Works for open SoftAPs without a password. When iface is
// empty, the joiner auto-detects the Wi-Fi hardware port via
// `networksetup -listallhardwareports` on first use and caches the result.
//
// Joining saves the network to the preferred list; Forget removes it again.
// Rejoining a saved network without a password uses the stored one, but
// races the OS's own auto-join (failing with "-3900 tmpErr"), so the
// onboard layer prefers to let auto-join reconnect the original network.
type NetworksetupJoiner struct {
	iface string

	detectOnce sync.Once
	detected   string
	detectErr  error
}

// NewNetworksetupJoiner returns a Joiner that drives `networksetup`. Pass
// the empty string to let the joiner auto-detect the host's Wi-Fi
// interface, or an explicit name (e.g. "en0") to override detection.
func NewNetworksetupJoiner(iface string) *NetworksetupJoiner {
	return &NetworksetupJoiner{iface: iface}
}

// resolveIface returns the explicitly-configured interface name or runs
// detection. The result is cached for the lifetime of the joiner.
func (j *NetworksetupJoiner) resolveIface(ctx context.Context) (string, error) {
	if j.iface != "" {
		return j.iface, nil
	}
	j.detectOnce.Do(func() {
		j.detected, j.detectErr = detectWiFiInterface(ctx)
	})
	if j.detectErr != nil {
		return "", j.detectErr
	}
	return j.detected, nil
}

// Join associates the host with the device's SoftAP (no password — SoftAPs
// are open networks).
//
// networksetup is unusually lenient about reporting failure: it exits 0 even
// when it can't find the requested SSID, can't power on Wi-Fi, or gets
// rejected by the join layer. Join therefore inspects stdout/stderr for
// known failure markers and verifies the association actually took by
// reading the current SSID afterwards.
func (j *NetworksetupJoiner) Join(ctx context.Context, ap AP) error {
	iface, err := j.resolveIface(ctx)
	if err != nil {
		return fmt.Errorf("scanner: networksetup join %q: %w", ap.SSID, err)
	}

	if err := j.ensurePoweredOn(ctx, iface); err != nil {
		return fmt.Errorf("scanner: networksetup join %q: %w", ap.SSID, err)
	}

	cmd := exec.CommandContext(ctx, "networksetup", "-setairportnetwork", iface, ap.SSID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: networksetup join %q: %w: %s", ap.SSID, err, out)
	}
	if msg := networksetupFailureMessage(out); msg != "" {
		return fmt.Errorf("scanner: networksetup join %q: %s", ap.SSID, msg)
	}

	// We deliberately do NOT verify the join by SSID: on macOS 26
	// `networksetup -getairportnetwork` reports "not associated" even when
	// connected, and CWInterface.ssid is only readable by a
	// LaunchServices-launched process with Location Services. The wait
	// phase in the onboard layer treats TCP reachability of the SoftAP as
	// ground truth instead.
	return nil
}

// ensurePoweredOn turns the Wi-Fi adapter on if it is currently off.
// Without this `setairportnetwork` exits 0 without doing anything when the
// adapter is powered down.
func (j *NetworksetupJoiner) ensurePoweredOn(ctx context.Context, iface string) error {
	out, err := exec.CommandContext(ctx, "networksetup", "-getairportpower", iface).Output()
	if err != nil {
		return fmt.Errorf("networksetup -getairportpower: %w", err)
	}
	if strings.Contains(string(out), ": On") {
		return nil
	}
	cmd := exec.CommandContext(ctx, "networksetup", "-setairportpower", iface, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("networksetup -setairportpower on: %w: %s", err, out)
	}
	return nil
}

// networksetupFailureMessage scans networksetup output for known
// failure-on-zero-exit markers and returns a single-line trimmed copy of
// the offending message. Returns "" when the output looks clean.
func networksetupFailureMessage(out []byte) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	markers := []string{
		"could not find network",
		"failed to join",
		"error:",
		"not associated",
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			return strings.ReplaceAll(s, "\n", " ")
		}
	}
	return ""
}

// RejoinHome reconnects to ssid. If ssid is empty, RejoinHome is a no-op —
// macOS auto-rejoins the highest-priority known network once disconnected
// from the SoftAP. When password is non-empty it is passed to networksetup,
// which is required on first join to a network not yet stored in the
// keychain (macOS 26 Tahoe rejects passwordless joins to WPA networks even
// if the credential is in the keychain).
func (j *NetworksetupJoiner) RejoinHome(ctx context.Context, ssid, password string) error {
	if ssid == "" {
		return nil
	}
	iface, err := j.resolveIface(ctx)
	if err != nil {
		return fmt.Errorf("scanner: networksetup rejoin %q: %w", ssid, err)
	}
	if err := j.ensurePoweredOn(ctx, iface); err != nil {
		return fmt.Errorf("scanner: networksetup rejoin %q: %w", ssid, err)
	}
	args := []string{"-setairportnetwork", iface, ssid}
	if password != "" {
		args = append(args, password)
	}
	cmd := exec.CommandContext(ctx, "networksetup", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: networksetup rejoin %q: %w: %s", ssid, err, out)
	}
	if msg := networksetupFailureMessage(out); msg != "" {
		return fmt.Errorf("scanner: networksetup rejoin %q: %s", ssid, msg)
	}
	return nil
}

// Forget removes ssid from the interface's preferred networks via
// `networksetup -removepreferredwirelessnetwork`.
func (j *NetworksetupJoiner) Forget(ctx context.Context, ssid string) error {
	iface, err := j.resolveIface(ctx)
	if err != nil {
		return fmt.Errorf("scanner: networksetup forget %q: %w", ssid, err)
	}
	out, err := exec.CommandContext(ctx, "networksetup", "-removepreferredwirelessnetwork", iface, ssid).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: networksetup forget %q: %w: %s", ssid, err, out)
	}
	low := strings.ToLower(string(out))
	if strings.Contains(low, "error") || strings.Contains(low, "privilege") || strings.Contains(low, "not found") {
		return fmt.Errorf("scanner: networksetup forget %q: %s", ssid, strings.TrimSpace(string(out)))
	}
	return nil
}

// detectWiFiInterface returns the macOS BSD device name for the Wi-Fi
// hardware port (e.g. "en0"). It parses `networksetup -listallhardwareports`
// output, which groups entries by blank lines:
//
//	Hardware Port: Wi-Fi
//	Device: en0
//	Ethernet Address: xx:xx:xx:xx:xx:xx
func detectWiFiInterface(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "networksetup", "-listallhardwareports")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("networksetup -listallhardwareports: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var currentPort string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			currentPort = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		case strings.HasPrefix(line, "Device:") && currentPort == "Wi-Fi":
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev != "" {
				return dev, nil
			}
		}
	}
	return "", fmt.Errorf("no Wi-Fi hardware port found in networksetup output")
}
