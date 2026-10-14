//go:build windows

package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native WLAN API (wlanapi.dll). Used instead of `netsh wlan`, whose output
// is localized and so can't be parsed reliably.
var (
	wlanapi                         = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle              = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle             = wlanapi.NewProc("WlanCloseHandle")
	procWlanFreeMemory              = wlanapi.NewProc("WlanFreeMemory")
	procWlanEnumInterfaces          = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanScan                    = wlanapi.NewProc("WlanScan")
	procWlanGetAvailableNetworkList = wlanapi.NewProc("WlanGetAvailableNetworkList")
	procWlanQueryInterface          = wlanapi.NewProc("WlanQueryInterface")
	procWlanSetProfile              = wlanapi.NewProc("WlanSetProfile")
	procWlanGetProfile              = wlanapi.NewProc("WlanGetProfile")
	procWlanDeleteProfile           = wlanapi.NewProc("WlanDeleteProfile")
	procWlanConnect                 = wlanapi.NewProc("WlanConnect")
	procWlanDisconnect              = wlanapi.NewProc("WlanDisconnect")
)

const (
	wlanClientVersion           = 2 // Windows Vista and later
	wlanOpcodeCurrentConnection = 7
	wlanConnectionModeProfile   = 0
	dot11BSSTypeInfrastructure  = 1

	// Windows needs a few seconds to complete a scan; drivers must finish
	// within 4s.
	wlanScanWait = 4 * time.Second
	// How long Join / RejoinHome wait for the association to show up.
	wlanAssociateTimeout = 15 * time.Second
)

var errWlanNotConnected = errors.New("not connected")

// WlanClient drives WiFi through the native Windows WLAN API. It implements
// Scanner, Joiner, CurrentNetworkReporter, NetworkForgetter and
// Disassociator.
//
// Scans need Location access on Windows 11 24H2 and later (Settings →
// Privacy & security → Location → "Let desktop apps access your
// location"); without it scan results come back without names.
type WlanClient struct {
	iface string
}

// NewWlanClient returns a WLAN API client. iface selects the adapter by
// (part of) its description, e.g. "Intel"; empty uses the first adapter.
func NewWlanClient(iface string) *WlanClient {
	return &WlanClient{iface: iface}
}

// Interface returns the adapter filter supplied at construction time.
func (c *WlanClient) Interface() string { return c.iface }

// Scan triggers a scan and lists the visible networks.
func (c *WlanClient) Scan(ctx context.Context, opts ScanOptions) ([]AP, error) {
	var aps []AP
	err := c.session(func(h windows.Handle, guid *windows.GUID) error {
		// ERROR_BUSY means a scan is already running; its results are fine.
		if r, _, _ := procWlanScan.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), 0, 0, 0); r != 0 && syscall.Errno(r) != windows.ERROR_BUSY {
			return wlanError("WlanScan", r)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wlanScanWait):
		}
		var list unsafe.Pointer
		r, _, _ := procWlanGetAvailableNetworkList.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), 0, 0, uintptr(unsafe.Pointer(&list)))
		if r != 0 {
			if syscall.Errno(r) == windows.ERROR_ACCESS_DENIED {
				return fmt.Errorf("%w (Windows: turn on Location services and \"Let desktop apps access your location\")", ErrRedacted)
			}
			return wlanError("WlanGetAvailableNetworkList", r)
		}
		defer procWlanFreeMemory.Call(uintptr(list))
		n := int(*(*uint32)(list))
		buf := unsafe.Slice((*byte)(list), wlanListHeaderSize+n*wlanAvailableNetworkSize)
		var err error
		aps, err = parseWlanAvailableNetworkList(buf, opts)
		if errors.Is(err, ErrRedacted) {
			return fmt.Errorf("%w (Windows: turn on Location services and \"Let desktop apps access your location\")", err)
		}
		return err
	})
	return aps, err
}

// Join connects to the device's open SoftAP through a temporary profile
// (removed again by Forget) and waits for the association.
func (c *WlanClient) Join(ctx context.Context, ap AP) error {
	err := c.session(func(h windows.Handle, guid *windows.GUID) error {
		if err := setProfile(h, guid, wlanOpenProfileXML(ap.SSID)); err != nil {
			return err
		}
		return connectProfile(h, guid, ap.SSID)
	})
	if err != nil {
		return fmt.Errorf("scanner: wlan join %q: %w", ap.SSID, err)
	}
	return c.waitAssociated(ctx, ap.SSID)
}

// RejoinHome connects to ssid. A saved profile is used as is (Windows keeps
// the password); otherwise a profile is created, WPA2-Personal when a
// password is given, open when not.
func (c *WlanClient) RejoinHome(ctx context.Context, ssid, password string) error {
	if ssid == "" {
		return nil
	}
	err := c.session(func(h windows.Handle, guid *windows.GUID) error {
		exists, err := profileExists(h, guid, ssid)
		if err != nil {
			return err
		}
		if !exists {
			xmlProfile := wlanOpenProfileXML(ssid)
			if password != "" {
				xmlProfile = wlanPSKProfileXML(ssid, password)
			}
			if err := setProfile(h, guid, xmlProfile); err != nil {
				return err
			}
		}
		return connectProfile(h, guid, ssid)
	})
	if err != nil {
		return fmt.Errorf("scanner: wlan rejoin %q: %w", ssid, err)
	}
	return c.waitAssociated(ctx, ssid)
}

// CurrentSSID returns the network the adapter is associated with, or "".
func (c *WlanClient) CurrentSSID(context.Context) (string, error) {
	var ssid string
	err := c.session(func(h windows.Handle, guid *windows.GUID) error {
		var (
			size uint32
			data unsafe.Pointer
		)
		r, _, _ := procWlanQueryInterface.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), wlanOpcodeCurrentConnection, 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
		if r != 0 {
			if syscall.Errno(r) == windows.ERROR_INVALID_STATE {
				return errWlanNotConnected
			}
			return wlanError("WlanQueryInterface", r)
		}
		defer procWlanFreeMemory.Call(uintptr(data))
		ssid = wlanCurrentSSID(unsafe.Slice((*byte)(data), size))
		return nil
	})
	if errors.Is(err, errWlanNotConnected) {
		return "", nil
	}
	return ssid, err
}

// Forget deletes the profile for ssid. A missing profile is not an error.
func (c *WlanClient) Forget(_ context.Context, ssid string) error {
	return c.session(func(h windows.Handle, guid *windows.GUID) error {
		name, err := windows.UTF16PtrFromString(ssid)
		if err != nil {
			return err
		}
		r, _, _ := procWlanDeleteProfile.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(name)), 0)
		if r != 0 && syscall.Errno(r) != windows.ERROR_NOT_FOUND {
			return wlanError("WlanDeleteProfile", r)
		}
		return nil
	})
}

// Disassociate disconnects the adapter from its current network.
func (c *WlanClient) Disassociate(context.Context) error {
	return c.session(func(h windows.Handle, guid *windows.GUID) error {
		if r, _, _ := procWlanDisconnect.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), 0); r != 0 {
			return wlanError("WlanDisconnect", r)
		}
		return nil
	})
}

// waitAssociated polls until the adapter reports ssid. WlanConnect only
// starts the connection, and a network that isn't in range fails silently.
func (c *WlanClient) waitAssociated(ctx context.Context, ssid string) error {
	deadline := time.Now().Add(wlanAssociateTimeout)
	for {
		cur, err := c.CurrentSSID(ctx)
		if err == nil && cur == ssid {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("scanner: wlan: did not associate with %q (current %q)", ssid, cur)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// session opens a WLAN handle, resolves the adapter and runs fn.
func (c *WlanClient) session(fn func(windows.Handle, *windows.GUID) error) error {
	var (
		negotiated uint32
		h          windows.Handle
	)
	if r, _, _ := procWlanOpenHandle.Call(wlanClientVersion, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h))); r != 0 {
		return wlanError("WlanOpenHandle", r)
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)

	var list unsafe.Pointer
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&list))); r != 0 {
		return wlanError("WlanEnumInterfaces", r)
	}
	n := int(*(*uint32)(list))
	ifs, err := parseWlanInterfaceList(unsafe.Slice((*byte)(list), wlanListHeaderSize+n*wlanInterfaceInfoSize))
	procWlanFreeMemory.Call(uintptr(list))
	if err != nil {
		return err
	}
	for _, ifc := range ifs {
		if c.iface == "" || strings.Contains(strings.ToLower(ifc.description), strings.ToLower(c.iface)) {
			guid := *(*windows.GUID)(unsafe.Pointer(&ifc.guid[0]))
			return fn(h, &guid)
		}
	}
	if c.iface != "" {
		return fmt.Errorf("scanner: no WiFi adapter matching %q", c.iface)
	}
	return errors.New("scanner: no WiFi adapter found")
}

func setProfile(h windows.Handle, guid *windows.GUID, profileXML string) error {
	x, err := windows.UTF16PtrFromString(profileXML)
	if err != nil {
		return err
	}
	var reason uint32
	r, _, _ := procWlanSetProfile.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), 0, uintptr(unsafe.Pointer(x)), 0, 1, 0, uintptr(unsafe.Pointer(&reason)))
	if r != 0 {
		return fmt.Errorf("WlanSetProfile: %w (reason %d)", syscall.Errno(r), reason)
	}
	return nil
}

func profileExists(h windows.Handle, guid *windows.GUID, name string) (bool, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	var xmlOut unsafe.Pointer
	r, _, _ := procWlanGetProfile.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(n)), 0, uintptr(unsafe.Pointer(&xmlOut)), 0, 0)
	switch {
	case r == 0:
		procWlanFreeMemory.Call(uintptr(xmlOut))
		return true, nil
	case syscall.Errno(r) == windows.ERROR_NOT_FOUND:
		return false, nil
	default:
		return false, wlanError("WlanGetProfile", r)
	}
}

// wlanConnectionParameters mirrors WLAN_CONNECTION_PARAMETERS; Go's natural
// alignment matches the C layout on 32- and 64-bit Windows.
type wlanConnectionParameters struct {
	mode      uint32
	profile   *uint16
	ssid      unsafe.Pointer
	bssidList unsafe.Pointer
	bssType   uint32
	flags     uint32
}

func connectProfile(h windows.Handle, guid *windows.GUID, profile string) error {
	p, err := windows.UTF16PtrFromString(profile)
	if err != nil {
		return err
	}
	params := wlanConnectionParameters{mode: wlanConnectionModeProfile, profile: p, bssType: dot11BSSTypeInfrastructure}
	if r, _, _ := procWlanConnect.Call(uintptr(h), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&params)), 0); r != 0 {
		return wlanError("WlanConnect", r)
	}
	return nil
}

func wlanError(call string, r uintptr) error {
	return fmt.Errorf("%s: %w", call, syscall.Errno(r))
}
