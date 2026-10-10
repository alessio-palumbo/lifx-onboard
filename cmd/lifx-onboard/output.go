package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	onboard "github.com/alessio-palumbo/lifx-onboard"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// printer renders events, results and scan output either as human-readable
// text or as NDJSON records (one object per line).
type printer struct {
	mu   sync.Mutex
	w    io.Writer
	json bool
	now  func() time.Time
}

func newPrinter(w io.Writer, asJSON bool) *printer {
	return &printer{w: w, json: asJSON, now: time.Now}
}

// record is the NDJSON shape shared by every line the CLI emits. Durations
// are seconds so consumers don't have to parse Go duration strings.
type record struct {
	Time      time.Time  `json:"time"`
	Type      string     `json:"type"`
	Serial    string     `json:"serial,omitempty"`
	SSID      string     `json:"ssid,omitempty"`
	BSSID     string     `json:"bssid,omitempty"`
	RSSI      float64    `json:"rssi,omitempty"`
	Addr      string     `json:"addr,omitempty"`
	Interface string     `json:"interface,omitempty"`
	TimeoutS  float64    `json:"timeout_s,omitempty"`
	TookS     float64    `json:"took_s,omitempty"`
	Phase     string     `json:"phase,omitempty"`
	Error     string     `json:"error,omitempty"`
	Verified  *bool      `json:"verified,omitempty"`
	APs       []apRecord `json:"aps,omitempty"`
}

type apRecord struct {
	Serial string  `json:"serial,omitempty"`
	SSID   string  `json:"ssid"`
	BSSID  string  `json:"bssid,omitempty"`
	RSSI   float64 `json:"rssi,omitempty"`
}

func serialString(s device.Serial) string {
	if s.IsNil() {
		return ""
	}
	return s.String()
}

func bssidString(b [6]byte) string {
	if b == [6]byte{} {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func toAPRecord(ap scanner.AP) apRecord {
	return apRecord{Serial: serialString(ap.Serial), SSID: ap.SSID, BSSID: bssidString(ap.BSSID), RSSI: ap.RSSI}
}

// eventRecord converts a library event into its NDJSON record. ok is false
// for event types the CLI doesn't know about.
func eventRecord(e onboard.Event) (r record, ok bool) {
	switch v := e.(type) {
	case onboard.EventScanning:
		return record{Type: "scanning", Interface: v.Interface}, true
	case onboard.EventDiscovered:
		r := record{Type: "discovered"}
		for _, ap := range v.APs {
			r.APs = append(r.APs, toAPRecord(ap))
		}
		return r, true
	case onboard.EventJoining:
		return record{Type: "joining", Serial: serialString(v.Serial), SSID: v.SSID}, true
	case onboard.EventJoined:
		return record{Type: "joined", Serial: serialString(v.Serial)}, true
	case onboard.EventWaitingForSoftAP:
		return record{Type: "waiting_for_softap", Serial: serialString(v.Serial), Addr: v.Addr, TimeoutS: v.Timeout.Seconds()}, true
	case onboard.EventOnSoftAP:
		return record{Type: "on_softap", Serial: serialString(v.Serial), Addr: v.Addr, TookS: v.Took.Seconds()}, true
	case onboard.EventDialing:
		return record{Type: "dialing", Serial: serialString(v.Serial), Addr: v.Addr}, true
	case onboard.EventConfigured:
		return record{Type: "configured", Serial: serialString(v.Serial)}, true
	case onboard.EventRejoining:
		return record{Type: "rejoining", Serial: serialString(v.Serial), SSID: v.SSID}, true
	case onboard.EventRejoined:
		return record{Type: "rejoined", Serial: serialString(v.Serial), SSID: v.SSID}, true
	case onboard.EventVerifying:
		return record{Type: "verifying", Serial: serialString(v.Serial), TimeoutS: v.Timeout.Seconds()}, true
	case onboard.EventVerified:
		return record{Type: "verified", Serial: serialString(v.Serial), TookS: v.Took.Seconds()}, true
	case onboard.EventFailed:
		return record{Type: "failed", Serial: serialString(v.Serial), Phase: v.Phase, Error: errString(v.Err)}, true
	}
	return record{}, false
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (p *printer) event(e onboard.Event) {
	if p.json {
		if r, ok := eventRecord(e); ok {
			p.emit(r)
		}
		return
	}
	switch v := e.(type) {
	case onboard.EventScanning:
		if v.Interface != "" {
			p.printf("[scan] scanning on %s\n", v.Interface)
		} else {
			p.printf("[scan] scanning\n")
		}
	case onboard.EventDiscovered:
		p.printf("[scan] found %d SoftAP(s)\n", len(v.APs))
	case onboard.EventJoining:
		p.printf("[join] joining %q (%s)\n", v.SSID, v.Serial)
	case onboard.EventJoined:
		p.printf("[join] joined %s\n", v.Serial)
	case onboard.EventWaitingForSoftAP:
		p.printf("[wait] waiting up to %s for %s\n", v.Timeout, v.Addr)
	case onboard.EventOnSoftAP:
		p.printf("[wait] %s reachable after %s\n", v.Addr, v.Took.Round(time.Millisecond))
	case onboard.EventDialing:
		p.printf("[dial] %s -> %s\n", v.Serial, v.Addr)
	case onboard.EventConfigured:
		p.printf("[send] credentials delivered to %s\n", v.Serial)
	case onboard.EventRejoining:
		p.printf("[rejoin] joining %q\n", v.SSID)
	case onboard.EventRejoined:
		p.printf("[rejoin] back on %q\n", v.SSID)
	case onboard.EventVerifying:
		p.printf("[verify] waiting up to %s for %s on the LAN\n", v.Timeout, v.Serial)
	case onboard.EventVerified:
		p.printf("[verify] %s back on the LAN after %s\n", v.Serial, v.Took.Round(time.Millisecond))
	case onboard.EventFailed:
		p.printf("[FAIL] %s phase=%s: %v\n", serialOrDash(v.Serial), v.Phase, v.Err)
	}
}

func (p *printer) result(r onboard.Result) {
	if p.json {
		verified := r.Verified
		p.emit(record{
			Type:     "result",
			Serial:   serialString(r.Serial),
			TookS:    r.Took.Seconds(),
			Phase:    r.Phase,
			Error:    errString(r.Err),
			Verified: &verified,
		})
		return
	}
	took := r.Took.Round(time.Millisecond)
	if r.Err != nil {
		p.printf("FAILED %s at phase %q after %s: %v\n", serialOrDash(r.Serial), r.Phase, took, r.Err)
		return
	}
	if r.Verified {
		p.printf("OK %s onboarded and verified on the LAN (%s)\n", r.Serial, took)
	} else {
		p.printf("OK %s onboarded, not verified (%s)\n", r.Serial, took)
	}
}

func (p *printer) ap(ap scanner.AP) {
	if p.json {
		a := toAPRecord(ap)
		p.emit(record{Type: "ap", Serial: a.Serial, SSID: a.SSID, BSSID: a.BSSID, RSSI: a.RSSI})
		return
	}
	p.printf("%-32q %-17s %6.1f  %s\n", ap.SSID, bssidString(ap.BSSID), ap.RSSI, serialOrDash(ap.Serial))
}

func serialOrDash(s device.Serial) string {
	if s.IsNil() {
		return "-"
	}
	return s.String()
}

func (p *printer) emit(r record) {
	r.Time = p.now()
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.w.Write(append(b, '\n'))
}

func (p *printer) printf(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, format, args...)
}
