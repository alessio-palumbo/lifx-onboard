//go:build linux

package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NmcliJoiner uses NetworkManager's nmcli to associate the host with WiFi
// networks. SoftAPs are open networks so no password is needed for Join.
// RejoinHome uses `nmcli connection up` against the saved profile name,
// which is typically the SSID.
type NmcliJoiner struct {
	iface string
}

// NewNmcliJoiner returns a Joiner backed by nmcli. iface names the WiFi
// device (e.g. "wlan0", "wlp3s0"); pass empty to let nmcli pick.
func NewNmcliJoiner(iface string) *NmcliJoiner {
	return &NmcliJoiner{iface: iface}
}

// Join associates with the device's open SoftAP via nmcli.
func (j *NmcliJoiner) Join(ctx context.Context, ap AP) error {
	args := []string{"device", "wifi", "connect", ap.SSID}
	if j.iface != "" {
		args = append(args, "ifname", j.iface)
	}
	cmd := exec.CommandContext(ctx, "nmcli", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: nmcli join %q: %w: %s", ap.SSID, err, out)
	}
	return nil
}

// Forget deletes the NetworkManager connection profile nmcli created when
// joining ssid (profiles are named after the SSID).
func (j *NmcliJoiner) Forget(ctx context.Context, ssid string) error {
	out, err := exec.CommandContext(ctx, "nmcli", "connection", "delete", "id", ssid).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: nmcli forget %q: %w: %s", ssid, err, out)
	}
	return nil
}

// CurrentSSID returns the SSID of the active WiFi connection via
// `nmcli -t -f ACTIVE,SSID device wifi`, or "" when not associated.
func (j *NmcliJoiner) CurrentSSID(ctx context.Context) (string, error) {
	args := []string{"-t", "-f", "ACTIVE,SSID", "device", "wifi", "list"}
	if j.iface != "" {
		args = append(args, "ifname", j.iface)
	}
	out, err := exec.CommandContext(ctx, "nmcli", args...).Output()
	if err != nil {
		return "", fmt.Errorf("scanner: nmcli current ssid: %w", err)
	}
	return parseNmcliActiveSSID(string(out)), nil
}

// parseNmcliActiveSSID picks the SSID from the "yes:<ssid>" line of
// `nmcli -t -f ACTIVE,SSID` output. Terse mode escapes ':' and '\' in
// values with a backslash.
func parseNmcliActiveSSID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "yes:")
		if !ok {
			continue
		}
		return strings.NewReplacer(`\:`, ":", `\\`, `\`).Replace(rest)
	}
	return ""
}

// RejoinHome reconnects the host to ssid. If ssid is empty,
// NetworkManager's autoconnect handles reassociation and this is a no-op.
// When password is empty, RejoinHome prefers the saved profile
// (`nmcli connection up <ssid>`); when it is non-empty, RejoinHome forces a
// fresh join (`nmcli device wifi connect <ssid> password <password>`) so
// that the home network can be joined on a host that has never connected
// to it before.
func (j *NmcliJoiner) RejoinHome(ctx context.Context, ssid, password string) error {
	if ssid == "" {
		return nil
	}
	var cmd *exec.Cmd
	if password == "" {
		cmd = exec.CommandContext(ctx, "nmcli", "connection", "up", ssid)
	} else {
		args := []string{"device", "wifi", "connect", ssid, "password", password}
		if j.iface != "" {
			args = append(args, "ifname", j.iface)
		}
		cmd = exec.CommandContext(ctx, "nmcli", args...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scanner: nmcli rejoin %q: %w: %s", ssid, err, out)
	}
	return nil
}
