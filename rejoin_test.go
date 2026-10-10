package onboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
)

// networkJoiner is a Joiner that tracks and reports the host's current
// network (current → SoftAP after Join → target after a successful
// RejoinHome) and can fail RejoinHome for specific SSIDs.
type networkJoiner struct {
	fakeJoiner
	current       string
	on            string
	failSSIDs     map[string]bool
	forgotten     []string
	disassociated int
}

func (j *networkJoiner) Disassociate(context.Context) error {
	j.disassociated++
	j.on = "-" // associated with nothing
	return nil
}

func (j *networkJoiner) Forget(_ context.Context, ssid string) error {
	j.forgotten = append(j.forgotten, ssid)
	return nil
}

func (j *networkJoiner) CurrentSSID(context.Context) (string, error) {
	if j.on == "" {
		return j.current, nil
	}
	return j.on, nil
}

func (j *networkJoiner) Join(ctx context.Context, ap scanner.AP) error {
	j.on = ap.SSID
	return j.fakeJoiner.Join(ctx, ap)
}

func (j *networkJoiner) RejoinHome(ctx context.Context, ssid, password string) error {
	_ = j.fakeJoiner.RejoinHome(ctx, ssid, password)
	if j.failSSIDs[ssid] {
		return errors.New("Could not find network " + ssid)
	}
	j.on = ssid
	return nil
}

func TestRejoinTargets(t *testing.T) {
	opts := &Options{SSID: "My_IoT_Network", Password: "devpw"}
	home := rejoinTarget{ssid: "My_IoT_Network", password: "devpw"}

	tests := []struct {
		name                 string
		explicitSSID, explPW string
		original             string
		want                 []rejoinTarget
	}{
		{"original first, home fallback", "", "", "My_Network", []rejoinTarget{{ssid: "My_Network", autoJoin: true}, home}},
		{"original unknown", "", "", "", []rejoinTarget{home}},
		{"original is home", "", "", "My_IoT_Network", []rejoinTarget{home}},
		{"explicit wins", "Guest", "guestpw", "My_Network", []rejoinTarget{{ssid: "Guest", password: "guestpw"}}},
		{"explicit home reuses password", "My_IoT_Network", "", "My_Network", []rejoinTarget{home}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rejoinTargets(opts, tt.explicitSSID, tt.explPW, tt.original)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestOnboardBySSID_RejoinsOriginalNetwork(t *testing.T) {
	jnr := &networkJoiner{current: "My_Network"}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if !reflect.DeepEqual(jnr.rejoined, []string{"My_Network"}) || jnr.rejoinedPw[0] != "" {
		t.Errorf("rejoined %v (pw %q), want [My_Network] with the saved password (empty)", jnr.rejoined, jnr.rejoinedPw)
	}
}

func TestOnboardBySSID_RejoinFallsBackToHome(t *testing.T) {
	jnr := &networkJoiner{current: "My_Network", failSSIDs: map[string]bool{"My_Network": true}}
	events := make(chan Event, 64)
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.Events = events
	opts.RejoinTimeout = 20 * time.Millisecond
	opts.RejoinPoll = 5 * time.Millisecond

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	last := jnr.rejoined[len(jnr.rejoined)-1]
	if jnr.rejoined[0] != "My_Network" || last != "home" || jnr.rejoinedPw[len(jnr.rejoinedPw)-1] != "secret" {
		t.Errorf("rejoined %v, want My_Network attempts then home with its password", jnr.rejoined)
	}
	close(events)
	var rejoining []string
	var rejoined string
	for e := range events {
		switch v := e.(type) {
		case EventRejoining:
			rejoining = append(rejoining, v.SSID)
		case EventRejoined:
			rejoined = v.SSID
		}
	}
	if !reflect.DeepEqual(rejoining, []string{"My_Network", "home"}) || rejoined != "home" {
		t.Errorf("events: rejoining=%v rejoined=%q", rejoining, rejoined)
	}
}

func TestDetectOriginalSSID_IgnoresSoftAP(t *testing.T) {
	opts := &Options{Scanner: &fakeScanner{}, Joiner: &networkJoiner{current: "LIFX A19 aabbcc"}}
	if got := detectOriginalSSID(context.Background(), opts); got != "" {
		t.Errorf("got %q, want empty when already on a SoftAP", got)
	}
	var _ scanner.CurrentNetworkReporter = &networkJoiner{}
}

// autoJoiningJoiner simulates the OS auto-joining the original network while
// our explicit RejoinHome fails with a transient error.
type autoJoiningJoiner struct {
	networkJoiner
	autoJoinAfter int // RejoinHome calls before the OS is on `current`
}

func (j *autoJoiningJoiner) CurrentSSID(context.Context) (string, error) {
	if len(j.rejoined) == 0 {
		return j.current, nil // before onboarding
	}
	if len(j.rejoined) >= j.autoJoinAfter {
		return j.current, nil
	}
	return "LIFX Candle Color 8274eb", nil // still reported as the SoftAP
}

func (j *autoJoiningJoiner) RejoinHome(ctx context.Context, ssid, password string) error {
	_ = j.fakeJoiner.RejoinHome(ctx, ssid, password)
	return errors.New("Failed to join network " + ssid + ". Error: -3900 tmpErr")
}

func TestOnboardBySSID_RejoinSucceedsWhenOSAutoJoins(t *testing.T) {
	jnr := &autoJoiningJoiner{networkJoiner: networkJoiner{current: "My_Network_5G"}, autoJoinAfter: 2}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.RejoinTimeout = time.Second
	opts.RejoinPoll = time.Millisecond

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	for _, s := range jnr.rejoined {
		if s != "My_Network_5G" {
			t.Fatalf("rejoined %v: fell back to %q although the host was back on My_Network_5G", jnr.rejoined, s)
		}
	}
}

// laggingAutoJoiner reports the SoftAP for the first few CurrentSSID polls
// after Join, then the original network — the OS auto-joining by itself.
type laggingAutoJoiner struct {
	networkJoiner
	pollsUntilAutoJoin int
}

func (j *laggingAutoJoiner) CurrentSSID(ctx context.Context) (string, error) {
	if j.on != "" && j.on != j.current {
		if j.pollsUntilAutoJoin > 0 {
			j.pollsUntilAutoJoin--
		} else {
			j.on = j.current
		}
	}
	return j.networkJoiner.CurrentSSID(ctx)
}

func TestOnboardBySSID_WaitsForOSAutoJoin(t *testing.T) {
	jnr := &laggingAutoJoiner{networkJoiner: networkJoiner{current: "My_Network_5G"}, pollsUntilAutoJoin: 1}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.AutoJoinWait = 5 * time.Second

	start := time.Now()
	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if len(jnr.rejoined) != 0 {
		t.Errorf("RejoinHome called %v; want none when the OS auto-joins", jnr.rejoined)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %s, want it to return as soon as the OS is back on the network", took)
	}
}

func TestOnboardBySSID_ForgetsSoftAP(t *testing.T) {
	jnr := &networkJoiner{current: "My_Network_5G"}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if !reflect.DeepEqual(jnr.forgotten, []string{opts.BulbSSID}) {
		t.Errorf("forgotten %v, want [%s]", jnr.forgotten, opts.BulbSSID)
	}

	// Also forgotten when onboarding fails after the join.
	jnr = &networkJoiner{current: "My_Network_5G"}
	opts.Joiner = jnr
	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(nil, errors.New("tls refused")), fakeWait(nil)); err == nil {
		t.Fatal("want dial error")
	}
	if !reflect.DeepEqual(jnr.forgotten, []string{opts.BulbSSID}) {
		t.Errorf("after failure: forgotten %v, want [%s]", jnr.forgotten, opts.BulbSSID)
	}
}

func TestOnboardBySSID_AutoJoinBudgetStartsAfterLeavingSoftAP(t *testing.T) {
	// Stays on the SoftAP for ~1s (two 500ms polls), longer than the
	// AutoJoinWait budget, then the OS auto-joins.
	jnr := &laggingAutoJoiner{networkJoiner: networkJoiner{current: "My_Network_5G"}, pollsUntilAutoJoin: 2}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.AutoJoinWait = 300 * time.Millisecond
	opts.RejoinTimeout = 5 * time.Second

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if len(jnr.rejoined) != 0 {
		t.Errorf("RejoinHome called %v; the wait must not expire while still on the SoftAP", jnr.rejoined)
	}
}

func TestOnboardBySSID_LeavesSoftAPAfterHandoff(t *testing.T) {
	jnr := &networkJoiner{current: "My_Network_5G"}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if jnr.disassociated != 1 {
		t.Errorf("Disassociate called %d times, want 1", jnr.disassociated)
	}

}

func TestOnboardBySSID_FailureReturnsHostToItsNetwork(t *testing.T) {
	for name, tc := range map[string]struct {
		dial dialFunc
		wait waitFunc
	}{
		"wait fails": {newDialer(&fakeConn{}, nil), fakeWait(ErrSoftAPWaitTimeout)},
		"dial fails": {newDialer(nil, errors.New("tls refused")), fakeWait(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			jnr := &networkJoiner{current: "My_Network_5G"}
			opts := bySSIDBaseOpts()
			opts.Joiner = jnr

			if _, err := onboardBySSIDWith(context.Background(), opts, tc.dial, tc.wait); err == nil {
				t.Fatal("want an error")
			}
			if on, _ := jnr.CurrentSSID(context.Background()); on != "My_Network_5G" {
				t.Errorf("host left on %q, want back on My_Network_5G", on)
			}
			if !reflect.DeepEqual(jnr.forgotten, []string{opts.BulbSSID}) || jnr.disassociated != 1 {
				t.Errorf("forgotten=%v disassociated=%d, want SoftAP forgotten and left", jnr.forgotten, jnr.disassociated)
			}
		})
	}
}

func TestOnboard_ConfigureFailureReturnsHostToItsNetwork(t *testing.T) {
	ap := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	jnr := &networkJoiner{current: "My_Network_5G"}
	opts := baseOpts()
	opts.Scanner = &fakeScanner{aps: []scanner.AP{ap}}
	opts.Joiner = jnr

	if _, err := onboardWithDial(context.Background(), opts, newDialer(&fakeConn{sendErr: errors.New("write failed")}, nil)); err == nil {
		t.Fatal("want an error")
	}
	if on, _ := jnr.CurrentSSID(context.Background()); on != "My_Network_5G" {
		t.Errorf("host left on %q, want back on My_Network_5G", on)
	}
}

func TestRealWait_StopsWhenHostLeavesSoftAP(t *testing.T) {
	left := fmt.Errorf("%w (now on %q)", ErrLeftSoftAP, "My_Network_5G")
	start := time.Now()
	// 127.0.0.1:1 refuses connections, so without the check this would run
	// for the full timeout.
	err := realWait(context.Background(), "127.0.0.1:1", 5*time.Second, 10*time.Millisecond, nil, func() error { return left })
	if !errors.Is(err, ErrLeftSoftAP) {
		t.Fatalf("err = %v, want ErrLeftSoftAP", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %s, want an immediate stop", took)
	}
}

// Reproduces a failed onboarding where the device disappears during the
// wait and the OS puts the host back on its original network by itself.
func TestOnboardBySSID_DeviceGoneDuringWait(t *testing.T) {
	jnr := &networkJoiner{current: "My_Network_5G"}
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	wait := func(_ context.Context, _ string, _, _ time.Duration, _ *slog.Logger, check func() error) error {
		jnr.on = "My_Network_5G" // OS auto-joined after the SoftAP vanished
		return check()
	}

	res, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), wait)
	if !errors.Is(err, ErrLeftSoftAP) || res.Phase != PhaseWait {
		t.Fatalf("phase=%q err=%v, want wait / ErrLeftSoftAP", res.Phase, err)
	}
	if jnr.disassociated != 0 {
		t.Errorf("disconnected the host %d time(s) although it was back on its own network", jnr.disassociated)
	}
	if len(jnr.rejoined) != 0 {
		t.Errorf("forced joins %v although the host was already back", jnr.rejoined)
	}
	if on, _ := jnr.CurrentSSID(context.Background()); on != "My_Network_5G" {
		t.Errorf("host on %q, want My_Network_5G", on)
	}
}

// otherNetworkJoiner simulates the OS auto-joining a different known network
// once the host leaves the SoftAP.
type otherNetworkJoiner struct{ networkJoiner }

func (j *otherNetworkJoiner) Disassociate(context.Context) error {
	j.disassociated++
	j.on = "Other_Known_Network"
	return nil
}

func TestOnboardBySSID_KeepsNetworkTheOSChose(t *testing.T) {
	jnr := &otherNetworkJoiner{networkJoiner{current: "My_Network_5G"}}
	events := make(chan Event, 64)
	opts := bySSIDBaseOpts()
	opts.Joiner = jnr
	opts.Events = events
	opts.AutoJoinWait = 50 * time.Millisecond

	if _, err := onboardBySSIDWith(context.Background(), opts, newDialer(&fakeConn{}, nil), fakeWait(nil)); err != nil {
		t.Fatalf("OnboardBySSID: %v", err)
	}
	if len(jnr.rejoined) != 0 {
		t.Errorf("forced joins %v; want the OS's choice kept", jnr.rejoined)
	}
	close(events)
	var rejoined string
	for e := range events {
		if v, ok := e.(EventRejoined); ok {
			rejoined = v.SSID
		}
	}
	if rejoined != "Other_Known_Network" {
		t.Errorf("EventRejoined SSID = %q, want Other_Known_Network", rejoined)
	}
}
