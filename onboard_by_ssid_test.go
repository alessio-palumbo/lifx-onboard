package onboard

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// fakeWait returns either nil or err immediately, ignoring real network I/O.
func fakeWait(err error) waitFunc {
	return func(context.Context, string, time.Duration, time.Duration, *slog.Logger, func() error) error {
		return err
	}
}

func bySSIDBaseOpts() OnboardBySSIDOptions {
	return OnboardBySSIDOptions{
		Options: Options{
			SSID:         "home",
			Password:     "secret",
			FindTimeout:  30 * time.Millisecond,
			FindPoll:     time.Millisecond,
			AutoJoinWait: -1,
		},
		BulbSSID: "LIFX A19 aabbcc",
	}
}

func TestOnboardBySSID_HappyPath_NoVerify(t *testing.T) {
	jnr := &fakeJoiner{}
	conn := &fakeConn{}

	opts := bySSIDBaseOpts()
	opts.Joiner = jnr

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(conn, nil), fakeWait(nil))
	if err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}

	wantSerial := device.Serial{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc}
	if res.Serial != wantSerial {
		t.Errorf("Serial = %s, want %s", res.Serial, wantSerial)
	}
	if res.Phase != "" || res.Err != nil {
		t.Errorf("expected clean Result, got phase=%q err=%v", res.Phase, res.Err)
	}
	if len(jnr.joined) != 1 || jnr.joined[0].SSID != opts.BulbSSID {
		t.Errorf("Joiner.Join not called with bulb SSID: %+v", jnr.joined)
	}
	if conn.target != wantSerial || conn.ssid != "home" || conn.pw != "secret" {
		t.Errorf("payload mismatch: target=%s ssid=%q pw=%q", conn.target, conn.ssid, conn.pw)
	}
	if len(jnr.rejoined) != 1 || jnr.rejoined[0] != "home" {
		t.Errorf("RejoinHome SSID = %v, want [home]", jnr.rejoined)
	}
	if len(jnr.rejoinedPw) != 1 || jnr.rejoinedPw[0] != "secret" {
		t.Errorf("RejoinHome password = %v, want [secret]", jnr.rejoinedPw)
	}
}

func TestOnboardBySSID_RejoinOverride(t *testing.T) {
	jnr := &fakeJoiner{}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.RejoinSSID = "guest"
	opts.RejoinPassword = "guestpw"

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if jnr.rejoined[0] != "guest" || jnr.rejoinedPw[0] != "guestpw" {
		t.Errorf("RejoinHome (ssid=%q, pw=%q), want (guest, guestpw)", jnr.rejoined[0], jnr.rejoinedPw[0])
	}
}

func TestOnboardBySSID_InvalidBulbSSID(t *testing.T) {
	cases := []string{"", "LIFX", "LIFX Bulb zzzzzz", "no-lifx-prefix"}
	for _, ssid := range cases {
		opts := bySSIDBaseOpts()
		opts.BulbSSID = ssid
		opts.Joiner = &fakeJoiner{}

		_, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
		if !errors.Is(err, ErrInvalidBulbSSID) {
			t.Errorf("BulbSSID=%q: err = %v, want ErrInvalidBulbSSID", ssid, err)
		}
	}
}

func TestOnboardBySSID_MissingCredentials(t *testing.T) {
	opts := bySSIDBaseOpts()
	opts.SSID = ""
	opts.Joiner = &fakeJoiner{}

	_, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("err = %v, want ErrMissingCredentials", err)
	}
}

func TestOnboardBySSID_JoinFails(t *testing.T) {
	jnr := &fakeJoiner{joinErr: errors.New("networksetup kaboom")}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if !errors.Is(err, ErrJoinFailed) {
		t.Fatalf("err = %v, want wrapped ErrJoinFailed", err)
	}
	if res.Phase != PhaseJoin {
		t.Errorf("Phase = %q, want %q", res.Phase, PhaseJoin)
	}
	if len(jnr.joined) < 2 {
		t.Errorf("Join called %d time(s), want retries until FindTimeout", len(jnr.joined))
	}
}

func TestOnboardBySSID_JoinRetriesUntilSoftAPUp(t *testing.T) {
	jnr := &fakeJoiner{joinErr: errors.New("Could not find network LIFX A19 aabbcc."), joinFailures: 2}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.FindTimeout = time.Second

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if err != nil {
		t.Fatalf("OnboardBySSID: %v (phase %q)", err, res.Phase)
	}
	if len(jnr.joined) != 3 {
		t.Errorf("Join called %d time(s), want 3", len(jnr.joined))
	}
}

func TestOnboardBySSID_WaitTimeout(t *testing.T) {
	opts := bySSIDBaseOpts()
	opts.Joiner = &fakeJoiner{}

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(ErrSoftAPWaitTimeout))
	if !errors.Is(err, ErrSoftAPWaitTimeout) {
		t.Fatalf("err = %v, want ErrSoftAPWaitTimeout", err)
	}
	if res.Phase != PhaseWait {
		t.Errorf("Phase = %q, want %q", res.Phase, PhaseWait)
	}
}

func TestOnboardBySSID_DialFails(t *testing.T) {
	opts := bySSIDBaseOpts()
	opts.Joiner = &fakeJoiner{}

	dialErr := errors.New("tls refused")
	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(nil, dialErr), fakeWait(nil))
	if !errors.Is(err, dialErr) {
		t.Fatalf("err = %v, want wrapped %v", err, dialErr)
	}
	if res.Phase != PhaseDial {
		t.Errorf("Phase = %q, want %q", res.Phase, PhaseDial)
	}
}

func TestOnboardBySSID_RejoinFails(t *testing.T) {
	jnr := &fakeJoiner{rejoinErr: errors.New("network not found")}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.RejoinTimeout = 30 * time.Millisecond
	opts.RejoinPoll = 5 * time.Millisecond

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if err == nil {
		t.Fatalf("expected rejoin error, got nil")
	}
	if res.Phase != PhaseRejoin {
		t.Errorf("Phase = %q, want %q", res.Phase, PhaseRejoin)
	}
	if len(jnr.rejoined) < 2 {
		t.Errorf("RejoinHome called %d time(s), want retries", len(jnr.rejoined))
	}
}

func TestOnboardBySSID_RejoinRetriesUntilNetworkVisible(t *testing.T) {
	jnr := &fakeJoiner{rejoinErr: errors.New("Could not find network home."), rejoinFailures: 2}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.RejoinTimeout = time.Second
	opts.RejoinPoll = time.Millisecond

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if err != nil {
		t.Fatalf("OnboardBySSID: %v (phase %q)", err, res.Phase)
	}
	if len(jnr.rejoined) != 3 {
		t.Errorf("RejoinHome called %d time(s), want 3", len(jnr.rejoined))
	}
}

func TestOnboardBySSID_VerifyTimeoutReportsTried(t *testing.T) {
	opts := bySSIDBaseOpts()
	opts.Joiner = &fakeJoiner{}
	opts.Sender = &fakeSender{steps: [][]device.Device{{}}} // never live
	opts.VerifyTimeout = 30 * time.Millisecond
	opts.VerifyPoll = 5 * time.Millisecond

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if !errors.Is(err, ErrVerifyTimeout) {
		t.Fatalf("err = %v, want wrapped ErrVerifyTimeout", err)
	}
	wantSerial := device.Serial{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc}
	if res.Serial != wantSerial {
		t.Errorf("Serial = %s, want %s", res.Serial, wantSerial)
	}
	if res.Verified {
		t.Errorf("Verified = true on timeout, want false")
	}
}

func TestOnboardBySSID_EmitsWaitEvents(t *testing.T) {
	events := make(chan Event, 32)
	opts := bySSIDBaseOpts()
	opts.Joiner = &fakeJoiner{}
	opts.Events = events

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	close(events)

	var sawWaiting, sawOn bool
	for e := range events {
		switch e.(type) {
		case EventWaitingForSoftAP:
			sawWaiting = true
		case EventOnSoftAP:
			sawOn = true
		}
	}
	if !sawWaiting || !sawOn {
		t.Errorf("expected both EventWaitingForSoftAP and EventOnSoftAP; sawWaiting=%v sawOn=%v", sawWaiting, sawOn)
	}
}

// Sanity check that APFromSSID accepts the canonical "LIFX <Form> <hex>" shape
// we rely on; reachable from this test file without exporting internal helpers.
func TestAPFromSSID_DerivesSerial(t *testing.T) {
	ap, ok := scanner.APFromSSID("LIFX A19 aabbcc", false)
	if !ok {
		t.Fatalf("APFromSSID returned ok=false")
	}
	want := device.Serial{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc}
	if ap.Serial != want {
		t.Errorf("Serial = %s, want %s", ap.Serial, want)
	}
}

func TestSerialFromInput(t *testing.T) {
	want := device.Serial{0xd0, 0x73, 0xd5, 0x82, 0x74, 0xeb}
	for _, in := range []string{"8274eb", "8274EB", "d073d58274eb", "D0:73:D5:82:74:EB", "d0-73-d5-82-74-eb", " 8274eb "} {
		got, ok := ParseSerial(in)
		if !ok || got != want {
			t.Errorf("ParseSerial(%q) = %s, %v; want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "8274e", "8274ebb", "zzzzzz", "aabbcc8274eb", "LIFX Candle Color"} {
		if got, ok := ParseSerial(in); ok {
			t.Errorf("ParseSerial(%q) = %s, want rejection", in, got)
		}
	}
}

func TestOnboardBySSID_ResolvesSerialByScanning(t *testing.T) {
	bulb, _ := scanner.APFromSSID("LIFX Candle Color 8274eb", false)
	other, _ := scanner.APFromSSID("LIFX A19 aabbcc", false)

	for _, input := range []string{"8274eb", "d073d58274eb", "D0:73:D5:82:74:EB"} {
		t.Run(input, func(t *testing.T) {
			jnr := &fakeJoiner{}
			opts := bySSIDBaseOpts()
			opts.BulbSSID = input
			opts.Joiner = jnr
			// The bulb only shows up on the second scan.
			opts.Scanner = &fakeScanner{aps: []scanner.AP{other, bulb}, emptyScans: 1}

			res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
			if err != nil {
				t.Fatalf("OnboardBySSID: %v (phase %q)", err, res.Phase)
			}
			if len(jnr.joined) != 1 || jnr.joined[0].SSID != "LIFX Candle Color 8274eb" {
				t.Errorf("joined %+v, want the full SSID of the matching SoftAP", jnr.joined)
			}
			if res.Serial != bulb.Serial {
				t.Errorf("Serial = %s, want %s", res.Serial, bulb.Serial)
			}
		})
	}
}

func TestOnboardBySSID_SerialNotFound(t *testing.T) {
	other, _ := scanner.APFromSSID("LIFX A19 aabbcc", false)
	jnr := &fakeJoiner{}
	opts := bySSIDBaseOpts()
	opts.BulbSSID = "8274eb"
	opts.Joiner = jnr
	opts.Scanner = &fakeScanner{aps: []scanner.AP{other}}

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil))
	if !errors.Is(err, ErrNoDevicesFound) {
		t.Fatalf("err = %v, want ErrNoDevicesFound", err)
	}
	if res.Phase != PhaseScan {
		t.Errorf("Phase = %q, want %q", res.Phase, PhaseScan)
	}
	if len(jnr.joined) != 0 {
		t.Errorf("joined %+v, want no join attempt", jnr.joined)
	}
}

func TestOnboardBySSID_OpenNetwork(t *testing.T) {
	conn := &fakeConn{}
	opts := bySSIDBaseOpts()
	opts.Password = ""
	opts.Joiner = &fakeJoiner{}

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(conn, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if conn.sec != SecurityOpen || conn.pw != "" {
		t.Errorf("sent security=%d pw=%q, want SecurityOpen and no password", conn.sec, conn.pw)
	}

	// A secured mode without a password is a caller error.
	opts.Security = SecurityWpa2AesPsk
	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); !errors.Is(err, ErrMissingCredentials) {
		t.Errorf("err = %v, want ErrMissingCredentials", err)
	}
}
