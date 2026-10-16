package onboard

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/internal/wire"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifx-onboard/softap"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// fakeScanner returns a fixed slice and optional error.
type fakeScanner struct {
	aps []scanner.AP
	err error
	hit int
	// emptyScans makes the first N scans return no APs, simulating a
	// device that hasn't brought its SoftAP up yet.
	emptyScans int
}

func (f *fakeScanner) Scan(context.Context, scanner.ScanOptions) ([]scanner.AP, error) {
	f.hit++
	if f.hit <= f.emptyScans {
		return nil, nil
	}
	return f.aps, f.err
}
func (f *fakeScanner) Interface() string { return "fake0" }

// fakeJoiner records calls and optionally fails.
type fakeJoiner struct {
	joinErr   error
	rejoinErr error
	// joinFailures, when > 0, makes the first N Join calls fail with
	// joinErr before succeeding.
	joinFailures int
	// rejoinFailures, when > 0, makes the first N RejoinHome calls fail
	// with rejoinErr before succeeding.
	rejoinFailures int
	joined         []scanner.AP
	rejoined       []string
	rejoinedPw     []string
}

func (j *fakeJoiner) Join(_ context.Context, ap scanner.AP) error {
	j.joined = append(j.joined, ap)
	if j.joinFailures > 0 && len(j.joined) > j.joinFailures {
		return nil
	}
	return j.joinErr
}
func (j *fakeJoiner) RejoinHome(_ context.Context, ssid, password string) error {
	j.rejoined = append(j.rejoined, ssid)
	j.rejoinedPw = append(j.rejoinedPw, password)
	if j.rejoinFailures > 0 && len(j.rejoined) > j.rejoinFailures {
		return nil
	}
	return j.rejoinErr
}

// fakeSender mutates its device list over time. It returns devs[step] each
// time GetDevices is called, advancing step until devs is exhausted.
type fakeSender struct {
	mu    sync.Mutex
	steps [][]device.Device
	calls int
}

func (s *fakeSender) GetDevices() []device.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.steps[0]
	s.calls++
	if len(s.steps) > 1 {
		s.steps = s.steps[1:]
	}
	return out
}

// fakeConn records the bytes sent and can fail at Send.
type fakeConn struct {
	sendErr error
	target  device.Serial
	ssid    string
	pw      string
	sec     wire.WifiSecurity
	closed  bool
}

func (c *fakeConn) SendSetAccessPoint(target device.Serial, ssid, pw string, sec wire.WifiSecurity) error {
	c.target, c.ssid, c.pw, c.sec = target, ssid, pw, sec
	return c.sendErr
}
func (c *fakeConn) Close() error { c.closed = true; return nil }

func newDialer(conn *fakeConn, dialErr error) dialFunc {
	return func(softap.Options) (softAPConn, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return conn, nil
	}
}

// makeAP builds a scanner.AP with the canonical LIFX OUI + the given 3-byte suffix.
func makeAP(suffix [3]byte, ssid string) scanner.AP {
	return scanner.AP{
		Serial: device.Serial{0xd0, 0x73, 0xd5, suffix[0], suffix[1], suffix[2]},
		SSID:   ssid,
		BSSID:  [6]byte{0xd0, 0x73, 0xd5, suffix[0], suffix[1], suffix[2]},
		RSSI:   -50,
	}
}

func baseOpts() Options {
	return Options{
		SSID:          "home",
		Password:      "secret",
		VerifyTimeout: 0,              // skip verify by default
		Scanner:       &fakeScanner{}, // never the platform scanner in tests
		FindTimeout:   30 * time.Millisecond,
		FindPoll:      time.Millisecond,
		AutoJoinWait:  -1,
	}
}

func TestOnboard_HappyPath_NoVerify(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	scn := &fakeScanner{aps: []scanner.AP{ap}}
	jnr := &fakeJoiner{}
	conn := &fakeConn{}

	opts := baseOpts()
	opts.Scanner = scn
	opts.Joiner = jnr

	res, err := onboardWithDial(context.Background(), opts, newDialer(conn, nil))
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	if res.Serial != ap.Serial {
		t.Errorf("Serial = %s, want %s", res.Serial, ap.Serial)
	}
	if res.Verified {
		t.Errorf("Verified = true with VerifyTimeout=0, want false")
	}
	if len(jnr.joined) != 1 || jnr.joined[0].Serial != ap.Serial {
		t.Errorf("Joiner.Join not called with target AP: %+v", jnr.joined)
	}
	if conn.target != ap.Serial || conn.ssid != "home" || conn.pw != "secret" || conn.sec != SecurityWpa2AesPsk {
		t.Errorf("payload mismatch: target=%s ssid=%q pw=%q sec=%d", conn.target, conn.ssid, conn.pw, conn.sec)
	}
	if !conn.closed {
		t.Errorf("Conn.Close not called")
	}
	if len(jnr.rejoined) != 1 {
		t.Errorf("RejoinHome not called")
	}
}

func TestOnboard_VerifySucceedsAfterPoll(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	scn := &fakeScanner{aps: []scanner.AP{ap}}
	jnr := &fakeJoiner{}
	conn := &fakeConn{}

	// First two polls return empty, third returns the device.
	sender := &fakeSender{steps: [][]device.Device{
		{},
		{},
		{{Serial: ap.Serial}},
	}}

	opts := baseOpts()
	opts.Scanner = scn
	opts.Joiner = jnr
	opts.Sender = sender
	opts.VerifyTimeout = 5 * time.Second
	opts.VerifyPoll = 10 * time.Millisecond

	res, err := onboardWithDial(context.Background(), opts, newDialer(conn, nil))
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	if !res.Verified {
		t.Errorf("Verified = false, want true")
	}
	if sender.calls < 2 {
		t.Errorf("GetDevices calls = %d, want >= 2 (initial + at least 1 tick)", sender.calls)
	}
}

func TestOnboard_VerifyTimeout(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	scn := &fakeScanner{aps: []scanner.AP{ap}}
	jnr := &fakeJoiner{}
	conn := &fakeConn{}
	sender := &fakeSender{steps: [][]device.Device{{}}} // always empty

	opts := baseOpts()
	opts.Scanner = scn
	opts.Joiner = jnr
	opts.Sender = sender
	opts.VerifyTimeout = 30 * time.Millisecond
	opts.VerifyPoll = 5 * time.Millisecond

	res, err := onboardWithDial(context.Background(), opts, newDialer(conn, nil))
	if !errors.Is(err, ErrVerifyTimeout) {
		t.Fatalf("err = %v, want wrapped ErrVerifyTimeout", err)
	}
	if res.Verified {
		t.Errorf("Verified = true on timeout, want false")
	}
	if res.Serial != ap.Serial {
		t.Errorf("Serial = %s, want %s (should still report which device we tried)", res.Serial, ap.Serial)
	}
}

func TestOnboard_MissingCredentials(t *testing.T) {
	opts := Options{SSID: "", Password: ""}
	_, err := onboardWithDial(context.Background(), opts, newDialer(nil, nil))
	if !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("err = %v, want ErrMissingCredentials", err)
	}
}

func TestOnboard_NoDevicesFound(t *testing.T) {
	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: nil}
	opts.Joiner = &fakeJoiner{}

	_, err := onboardWithDial(context.Background(), opts, newDialer(nil, nil))
	if !errors.Is(err, ErrNoDevicesFound) {
		t.Fatalf("err = %v, want ErrNoDevicesFound", err)
	}
	if hits := opts.Scanner.(*fakeScanner).hit; hits < 2 {
		t.Errorf("scanned %d time(s), want retries until FindTimeout", hits)
	}
}

func TestOnboard_ScanRetriesUntilSoftAPAppears(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	scn := &fakeScanner{aps: []scanner.AP{ap}, emptyScans: 3}
	opts := baseOpts()
	opts.Scanner = scn
	opts.Joiner = &fakeJoiner{}
	opts.FindTimeout = time.Second

	res, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("Onboard: %v (phase %q)", err, res.Phase)
	}
	if res.Serial != ap.Serial || scn.hit != 4 {
		t.Errorf("serial=%s scans=%d, want %s after 4 scans", res.Serial, scn.hit, ap.Serial)
	}
}

func TestOnboard_TargetNotInScan(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
	opts.Joiner = &fakeJoiner{}
	opts.Target = device.Serial{0xd0, 0x73, 0xd5, 0xff, 0xff, 0xff}

	_, err := onboardWithDial(context.Background(), opts, newDialer(nil, nil))
	if !errors.Is(err, ErrNoDevicesFound) {
		t.Fatalf("err = %v, want wrapped ErrNoDevicesFound", err)
	}
}

func TestOnboard_JoinFails(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
	opts.Joiner = &fakeJoiner{joinErr: errors.New("nmcli kaboom")}

	_, err := onboardWithDial(context.Background(), opts, newDialer(nil, nil))
	if !errors.Is(err, ErrJoinFailed) {
		t.Fatalf("err = %v, want wrapped ErrJoinFailed", err)
	}
}

func TestOnboard_DialFails(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
	opts.Joiner = &fakeJoiner{}

	dialErr := errors.New("connection refused")
	_, err := onboardWithDial(context.Background(), opts, newDialer(nil, dialErr))
	if !errors.Is(err, dialErr) {
		t.Fatalf("err = %v, want wrapped dialErr", err)
	}
}

func TestOnboard_EmitsEventsInOrder(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	events := make(chan Event, 16)

	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
	opts.Joiner = &fakeJoiner{}
	opts.Events = events
	opts.Sender = &fakeSender{steps: [][]device.Device{{{Serial: ap.Serial}}}}
	opts.VerifyTimeout = 100 * time.Millisecond
	opts.VerifyPoll = 5 * time.Millisecond

	if _, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil)); err != nil {
		t.Fatalf("Onboard: %v", err)
	}
	close(events)

	var got []string
	for e := range events {
		switch e.(type) {
		case EventScanning:
			got = append(got, "scanning")
		case EventDiscovered:
			got = append(got, "discovered")
		case EventJoining:
			got = append(got, "joining")
		case EventJoined:
			got = append(got, "joined")
		case EventDialing:
			got = append(got, "dialing")
		case EventConfigured:
			got = append(got, "configured")
		case EventVerifying:
			got = append(got, "verifying")
		case EventVerified:
			got = append(got, "verified")
		}
	}

	want := []string{"scanning", "discovered", "joining", "joined", "dialing", "configured", "verifying", "verified"}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("event[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// seqScanner returns one scripted result per Scan call, repeating the last.
type seqScanner struct {
	results []struct {
		aps []scanner.AP
		err error
	}
	calls int
}

func (s *seqScanner) Scan(context.Context, scanner.ScanOptions) ([]scanner.AP, error) {
	r := s.results[min(s.calls, len(s.results)-1)]
	s.calls++
	return r.aps, r.err
}
func (s *seqScanner) Interface() string { return "fake0" }

func TestOnboard_TransientScanErrorDoesNotMaskNotFound(t *testing.T) {
	other := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	busy := errors.New("CoreWLAN scan: Resource busy")
	scn := &seqScanner{results: []struct {
		aps []scanner.AP
		err error
	}{
		{aps: []scanner.AP{other}}, // scanned fine, target absent
		{err: busy},                // last attempt fails transiently
	}}
	opts := baseOpts()
	opts.Scanner = scn
	opts.Joiner = &fakeJoiner{}
	opts.Target = device.Serial{0xd0, 0x73, 0xd5, 0x82, 0x74, 0xeb}

	_, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if !errors.Is(err, ErrNoDevicesFound) {
		t.Fatalf("err = %v, want ErrNoDevicesFound rather than the transient scan error", err)
	}
}

func TestOnboard_VerifyIgnoresDeviceSeenOnSoftAP(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	onSoftAP := device.Device{Serial: ap.Serial, Address: &net.UDPAddr{IP: net.IPv4(172, 16, 0, 1), Port: 56700}}
	onHome := device.Device{Serial: ap.Serial, Address: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 56700}}

	t.Run("only seen on SoftAP", func(t *testing.T) {
		opts := baseOpts()
		opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
		opts.Joiner = &fakeJoiner{}
		opts.Sender = &fakeSender{steps: [][]device.Device{{onSoftAP}}}
		opts.VerifyTimeout = 30 * time.Millisecond
		opts.VerifyPoll = 5 * time.Millisecond

		_, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
		if !errors.Is(err, ErrVerifyTimeout) {
			t.Fatalf("err = %v, want ErrVerifyTimeout (SoftAP sighting must not verify)", err)
		}
	})
	t.Run("then seen on home LAN", func(t *testing.T) {
		opts := baseOpts()
		opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
		opts.Joiner = &fakeJoiner{}
		opts.Sender = &fakeSender{steps: [][]device.Device{{onSoftAP}, {onHome}}}
		opts.VerifyTimeout = time.Second
		opts.VerifyPoll = 5 * time.Millisecond

		res, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
		if err != nil || !res.Verified {
			t.Fatalf("Verified=%v err=%v, want verified once seen on the home LAN", res.Verified, err)
		}
	})
}
