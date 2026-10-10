package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	onboard "github.com/alessio-palumbo/lifx-onboard"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no args", nil, exitUsage, "", "Usage: lifx-onboard"},
		{"help", []string{"--help"}, exitOK, "Commands:", ""},
		{"unknown", []string{"frobnicate"}, exitUsage, "", `unknown command "frobnicate"`},
		{"subcommand help", []string{"ssid", "-h"}, exitOK, "", "Usage: lifx-onboard ssid"},
		{"bad flag", []string{"ssid", "--nope"}, exitUsage, "", "flag provided but not defined"},
		{"ssid unquoted", []string{"ssid", "LIFX", "A19", "228447"}, exitUsage, "", "quote SSIDs containing spaces"},
		{"auto bad serial", []string{"auto", "zzzz"}, exitUsage, "", `invalid serial "zzzz"`},
		{"bulk bad serial", []string{"bulk", "8274eb", "extra"}, exitUsage, "", `invalid serial "extra"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envBulbSSID, "")
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", got, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunSSIDRequiresBulbSSID(t *testing.T) {
	t.Setenv(envBulbSSID, "")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"ssid", "--home-ssid", "Home"}, &stdout, &stderr); got != exitUsage {
		t.Fatalf("exit code = %d, want %d", got, exitUsage)
	}
	if !strings.Contains(stderr.String(), "bulb SSID or serial is required") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	home := fs.String("home-ssid", "", "")
	v := fs.Bool("v", false, "")

	pos, err := parseInterspersed(fs, []string{"LIFX A19 228447", "--home-ssid", "Home", "-v"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 1 || pos[0] != "LIFX A19 228447" {
		t.Errorf("positional = %q", pos)
	}
	if *home != "Home" || !*v {
		t.Errorf("flags not parsed after positional: home=%q v=%v", *home, *v)
	}
}

func TestParseSecurity(t *testing.T) {
	for _, name := range securityNames() {
		if _, err := parseSecurity(name); err != nil {
			t.Errorf("parseSecurity(%q): %v", name, err)
		}
	}
	if got, _ := parseSecurity("WPA2-AES"); got != onboard.SecurityWpa2AesPsk {
		t.Errorf("parseSecurity is case-sensitive: got %v", got)
	}
	if _, err := parseSecurity("wep"); err == nil {
		t.Error("parseSecurity(wep) succeeded, want error")
	}
}

func TestReadPassword(t *testing.T) {
	t.Run("stdin first line", func(t *testing.T) {
		t.Setenv(envPassword, "from-env")
		got, err := readPassword(strings.NewReader("s3cret\nignored\n"), io.Discard, true, "Home")
		if err != nil || got != "s3cret" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("stdin without newline", func(t *testing.T) {
		got, err := readPassword(strings.NewReader("s3cret"), io.Discard, true, "Home")
		if err != nil || got != "s3cret" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("stdin empty", func(t *testing.T) {
		if _, err := readPassword(strings.NewReader(""), io.Discard, true, "Home"); err == nil {
			t.Error("want error on empty stdin")
		}
	})
	t.Run("env", func(t *testing.T) {
		t.Setenv(envPassword, "from-env")
		got, err := readPassword(strings.NewReader(""), io.Discard, false, "Home")
		if err != nil || got != "from-env" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("no source", func(t *testing.T) {
		t.Setenv(envPassword, "")
		if _, err := readPassword(strings.NewReader(""), io.Discard, false, "Home"); err == nil {
			t.Error("want error when no password source is available")
		}
	})
}

func TestExitCodeFor(t *testing.T) {
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	boom := errors.New("boom")

	tests := []struct {
		name string
		ctx  context.Context
		res  onboard.Result
		err  error
		want int
	}{
		{"ok", live, onboard.Result{}, nil, exitOK},
		{"interrupted", cancelled, onboard.Result{Phase: onboard.PhaseJoin}, boom, exitInterrupted},
		{"missing creds", live, onboard.Result{Phase: onboard.PhaseScan}, onboard.ErrMissingCredentials, exitUsage},
		{"bad bulb ssid", live, onboard.Result{Phase: onboard.PhaseScan}, fmt.Errorf("%w: x", onboard.ErrInvalidBulbSSID), exitUsage},
		{"scan", live, onboard.Result{Phase: onboard.PhaseScan}, onboard.ErrNoDevicesFound, exitScan},
		{"join", live, onboard.Result{Phase: onboard.PhaseJoin}, boom, exitJoin},
		{"wait", live, onboard.Result{Phase: onboard.PhaseWait}, boom, exitWait},
		{"dial", live, onboard.Result{Phase: onboard.PhaseDial}, boom, exitDial},
		{"configure", live, onboard.Result{Phase: onboard.PhaseConfigure}, boom, exitConfigure},
		{"rejoin", live, onboard.Result{Phase: onboard.PhaseRejoin}, boom, exitRejoin},
		{"verify", live, onboard.Result{Phase: onboard.PhaseVerify}, boom, exitVerify},
		{"unknown phase", live, onboard.Result{}, boom, exitFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.ctx, tt.res, tt.err); got != tt.want {
				t.Errorf("exitCodeFor = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReportBulk(t *testing.T) {
	ok := onboard.Result{Serial: device.Serial{0xd0, 0x73, 0xd5, 1, 2, 3}, Verified: true}
	bad := onboard.Result{Serial: device.Serial{0xd0, 0x73, 0xd5, 4, 5, 6}, Phase: onboard.PhaseJoin, Err: errors.New("x")}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name    string
		ctx     context.Context
		results []onboard.Result
		want    int
	}{
		{"all ok", context.Background(), []onboard.Result{ok}, exitOK},
		{"some failed", context.Background(), []onboard.Result{ok, bad}, exitFailure},
		{"none found", context.Background(), nil, exitScan},
		{"interrupted", cancelled, []onboard.Result{ok}, exitInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if got := reportBulk(tt.ctx, newPrinter(&out, false), io.Discard, tt.results, nil); got != tt.want {
				t.Errorf("reportBulk = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPrinterJSON(t *testing.T) {
	serial := device.Serial{0xd0, 0x73, 0xd5, 0x22, 0x84, 0x47}
	var out bytes.Buffer
	p := newPrinter(&out, true)
	p.now = func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) }

	p.event(onboard.EventJoining{Serial: serial, SSID: "LIFX A19 228447"})
	p.event(onboard.EventWaitingForSoftAP{Serial: serial, Addr: "172.16.0.1:56700", Timeout: 30 * time.Second})
	p.event(onboard.EventFailed{Serial: serial, Phase: onboard.PhaseWait, Err: onboard.ErrSoftAPWaitTimeout})
	ap, _ := scanner.APFromSSID("LIFX A19 228447", false)
	ap.RSSI = -40
	p.event(onboard.EventDiscovered{APs: []scanner.AP{ap}})
	p.result(onboard.Result{Serial: serial, Took: 1500 * time.Millisecond, Phase: onboard.PhaseWait, Err: onboard.ErrSoftAPWaitTimeout})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5:\n%s", len(lines), out.String())
	}
	var recs []record
	for _, l := range lines {
		var r record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("invalid JSON %q: %v", l, err)
		}
		recs = append(recs, r)
	}

	if r := recs[0]; r.Type != "joining" || r.Serial != serial.String() || r.SSID != "LIFX A19 228447" {
		t.Errorf("joining record = %+v", r)
	}
	if r := recs[1]; r.Type != "waiting_for_softap" || r.TimeoutS != 30 || r.Addr != "172.16.0.1:56700" {
		t.Errorf("waiting record = %+v", r)
	}
	if r := recs[2]; r.Type != "failed" || r.Phase != onboard.PhaseWait || r.Error == "" {
		t.Errorf("failed record = %+v", r)
	}
	if r := recs[3]; r.Type != "discovered" || len(r.APs) != 1 || r.APs[0].BSSID != "d0:73:d5:22:84:47" {
		t.Errorf("discovered record = %+v", r)
	}
	if r := recs[4]; r.Type != "result" || r.Verified == nil || *r.Verified || r.TookS != 1.5 || r.Error == "" {
		t.Errorf("result record = %+v", r)
	}
	// Verified must be present (false) on results, not omitted.
	if !strings.Contains(lines[4], `"verified":false`) {
		t.Errorf("result line missing verified=false: %s", lines[4])
	}
}

func TestPrinterTextNilSerial(t *testing.T) {
	var out bytes.Buffer
	newPrinter(&out, false).event(onboard.EventFailed{Phase: onboard.PhaseScan, Err: errors.New("no wifi")})
	if got := out.String(); !strings.Contains(got, "[FAIL] - phase=scan: no wifi") {
		t.Errorf("text output = %q", got)
	}
}

type fakeSource struct {
	devs   []device.Device
	closed bool
}

func (f *fakeSource) GetDevices() []device.Device { return f.devs }
func (f *fakeSource) Close() error                { f.closed = true; return nil }

func TestLazySender(t *testing.T) {
	key := ""
	var created []*fakeSource
	fails := 1
	ls := &lazySender{
		netKey: func() string { return key },
		newCtrl: func() (devicesSource, error) {
			if fails > 0 {
				fails--
				return nil, errors.New("no broadcast-capable interface")
			}
			s := &fakeSource{devs: []device.Device{{Label: fmt.Sprint(len(created))}}}
			created = append(created, s)
			return s, nil
		},
	}

	if got := ls.GetDevices(); got != nil {
		t.Fatalf("first call with failing constructor = %v, want nil", got)
	}
	key = "en0=192.168.1.72/24"
	if got := ls.GetDevices(); len(got) != 1 || len(created) != 1 {
		t.Fatalf("creation not retried after failure: got %v, created %d", got, len(created))
	}
	ls.GetDevices()
	if len(created) != 1 {
		t.Fatalf("recreated without a network change: created %d", len(created))
	}
	key = "en0=192.168.20.5/24" // host moved to another network
	ls.GetDevices()
	if len(created) != 2 || !created[0].closed {
		t.Fatalf("not recreated after network change: created %d, first closed %v", len(created), created[0].closed)
	}
}

func TestSharedFlagsOpenNetworkNeedsNoPassword(t *testing.T) {
	t.Setenv(envPassword, "")
	sf := sharedFlags{homeSSID: "Cafe", security: "open"}
	opts, err := sf.options(strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	if opts.Password != "" || opts.Security != onboard.SecurityOpen {
		t.Errorf("password=%q security=%d, want empty / open", opts.Password, opts.Security)
	}
}
