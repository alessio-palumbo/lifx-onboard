package onboard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// queuedScanner returns successive scan results from a queue. Once exhausted
// it keeps returning the last result indefinitely (so an "AP disappears"
// scenario should append an empty entry to the queue).
type queuedScanner struct {
	mu    sync.Mutex
	queue [][]scanner.AP
	err   error
	hits  int
}

func (q *queuedScanner) Scan(context.Context, scanner.ScanOptions) ([]scanner.AP, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.hits++
	if q.err != nil {
		return nil, q.err
	}
	if len(q.queue) == 0 {
		return nil, nil
	}
	out := q.queue[0]
	if len(q.queue) > 1 {
		q.queue = q.queue[1:]
	}
	return out, nil
}
func (q *queuedScanner) Interface() string { return "fake0" }

// liveSender reports a fixed set of serials as "online".
type liveSender struct {
	mu      sync.Mutex
	serials map[device.Serial]bool
}

func newLiveSender(initial ...device.Serial) *liveSender {
	s := &liveSender{serials: map[device.Serial]bool{}}
	for _, x := range initial {
		s.serials[x] = true
	}
	return s
}
func (s *liveSender) GetDevices() []device.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]device.Device, 0, len(s.serials))
	for k := range s.serials {
		out = append(out, device.Device{Serial: k})
	}
	return out
}

func bulkBaseOpts() BulkOptions {
	return BulkOptions{
		Options: Options{
			SSID:         "home",
			Password:     "secret",
			FindTimeout:  30 * time.Millisecond,
			FindPoll:     time.Millisecond,
			AutoJoinWait: -1,
		},
		ScanInterval: 5 * time.Millisecond,
	}
}

func TestBulkOnboard_TwoDevices_NoVerify(t *testing.T) {
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	b := makeAP([3]byte{0x11, 0x22, 0x33}, "LIFX-A19-112233")

	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{a, b}}}
	opts.Joiner = &fakeJoiner{}
	opts.StopWhenIdleFor = 30 * time.Millisecond

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(results), results)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("result %s: unexpected Err %v", r.Serial, r.Err)
		}
		if r.Verified {
			t.Errorf("result %s: Verified should be false with VerifyTimeout=0", r.Serial)
		}
	}
}

func TestBulkOnboard_VerifySucceedsForAll(t *testing.T) {
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	b := makeAP([3]byte{0x11, 0x22, 0x33}, "LIFX-A19-112233")

	sender := newLiveSender(a.Serial, b.Serial) // both already live

	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{a, b}}}
	opts.Joiner = &fakeJoiner{}
	opts.Sender = sender
	opts.VerifyTimeout = 200 * time.Millisecond
	opts.VerifyPoll = 5 * time.Millisecond
	opts.StopWhenIdleFor = 30 * time.Millisecond

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(results), results)
	}
	for _, r := range results {
		if !r.Verified {
			t.Errorf("result %s: Verified=false, want true", r.Serial)
		}
		if r.Err != nil {
			t.Errorf("result %s: unexpected Err %v", r.Serial, r.Err)
		}
	}
}

func TestBulkOnboard_DedupesRecurringSerial(t *testing.T) {
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX Bulb aabbcc")
	// Same AP on every scan.
	scn := &queuedScanner{queue: [][]scanner.AP{{a}, {a}, {a}, {a}}}

	opts := bulkBaseOpts()
	opts.Scanner = scn
	opts.Joiner = &fakeJoiner{}
	opts.StopWhenIdleFor = 30 * time.Millisecond
	opts.ScanInterval = 3 * time.Millisecond

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1 (dedup): %+v", len(results), results)
	}
	if scn.hits < 2 {
		t.Errorf("scanner.hits = %d, want >= 2 (proves we kept scanning)", scn.hits)
	}
}

func TestBulkOnboard_MaxDevicesCap(t *testing.T) {
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX A")
	b := makeAP([3]byte{0x11, 0x22, 0x33}, "LIFX B")
	c := makeAP([3]byte{0x44, 0x55, 0x66}, "LIFX C")

	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{a, b, c}}}
	opts.Joiner = &fakeJoiner{}
	opts.MaxDevices = 2

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 (MaxDevices=2)", len(results))
	}
}

func TestBulkOnboard_StopWhenIdleFor(t *testing.T) {
	// First scan returns one AP, every subsequent scan returns nothing.
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX A")
	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{a}, {}}}
	opts.Joiner = &fakeJoiner{}
	opts.StopWhenIdleFor = 25 * time.Millisecond
	opts.ScanInterval = 5 * time.Millisecond

	start := time.Now()
	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("StopWhenIdleFor did not trigger: took %v", elapsed)
	}
}

func TestBulkOnboard_ContextCancel(t *testing.T) {
	// Scanner blocks pretending to scan forever.
	scn := &queuedScanner{queue: [][]scanner.AP{}}
	opts := bulkBaseOpts()
	opts.Scanner = scn
	opts.Joiner = &fakeJoiner{}
	opts.ScanInterval = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := bulkWithDial(ctx, opts, newDialer(&fakeConn{}, nil))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestBulkOnboard_MixedSuccessAndFailure(t *testing.T) {
	a := makeAP([3]byte{0xaa, 0xbb, 0xcc}, "LIFX A")
	b := makeAP([3]byte{0x11, 0x22, 0x33}, "LIFX B")

	// Join always fails for device a (even across retries) and succeeds for b.
	joiner := &selectiveJoiner{failSSIDs: map[string]bool{a.SSID: true}}

	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{a, b}}}
	opts.Joiner = joiner
	opts.StopWhenIdleFor = 30 * time.Millisecond

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}

	var failed, succeeded int
	for _, r := range results {
		if r.Err != nil {
			failed++
			if !errors.Is(r.Err, ErrJoinFailed) {
				t.Errorf("failed result Err = %v, want wrapped ErrJoinFailed", r.Err)
			}
			if r.Phase != PhaseJoin {
				t.Errorf("failed result Phase = %q, want %q", r.Phase, PhaseJoin)
			}
		} else {
			succeeded++
		}
	}
	if failed != 1 || succeeded != 1 {
		t.Errorf("counts: failed=%d succeeded=%d, want 1 + 1", failed, succeeded)
	}
}

// selectiveJoiner is a fakeJoiner whose Join always fails for specific SSIDs.
type selectiveJoiner struct {
	failSSIDs map[string]bool
}

func (j *selectiveJoiner) Join(_ context.Context, ap scanner.AP) error {
	if j.failSSIDs[ap.SSID] {
		return errors.New("simulated join failure")
	}
	return nil
}
func (j *selectiveJoiner) RejoinHome(_ context.Context, _, _ string) error { return nil }

func TestBulkOnboard_TargetsAllowList(t *testing.T) {
	mine := makeAP([3]byte{0x82, 0x74, 0xeb}, "LIFX Candle Color 8274eb")
	theirs := makeAP([3]byte{0x11, 0x22, 0x33}, "LIFX A19 112233")
	missing := device.Serial{0xd0, 0x73, 0xd5, 0xaa, 0xbb, 0xcc}

	jnr := &fakeJoiner{}
	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{theirs, mine}}}
	opts.Joiner = jnr
	opts.Targets = []device.Serial{mine.Serial, missing}
	opts.StopWhenIdleFor = 50 * time.Millisecond

	results, err := bulkWithDial(context.Background(), opts, newDialer(&fakeConn{}, nil))
	if err != nil {
		t.Fatalf("BulkOnboard: %v", err)
	}
	for _, ap := range jnr.joined {
		if ap.Serial == theirs.Serial {
			t.Fatalf("joined %s, which is not in Targets", ap.SSID)
		}
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want one per target", results)
	}
	bySerial := map[device.Serial]Result{}
	for _, r := range results {
		bySerial[r.Serial] = r
	}
	if r := bySerial[mine.Serial]; r.Err != nil {
		t.Errorf("target %s: %v", mine.Serial, r.Err)
	}
	if r := bySerial[missing]; !errors.Is(r.Err, ErrNoDevicesFound) || r.Phase != PhaseScan {
		t.Errorf("missing target: phase=%q err=%v, want scan / ErrNoDevicesFound", r.Phase, r.Err)
	}
}

func TestBulkOnboard_TargetsStopsOnceAllAttempted(t *testing.T) {
	mine := makeAP([3]byte{0x82, 0x74, 0xeb}, "LIFX Candle Color 8274eb")
	opts := bulkBaseOpts()
	opts.Scanner = &queuedScanner{queue: [][]scanner.AP{{mine}}}
	opts.Joiner = &fakeJoiner{}
	opts.Targets = []device.Serial{mine.Serial}
	opts.StopWhenIdleFor = time.Hour // must not be what ends the run

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results, err := bulkWithDial(ctx, opts, newDialer(&fakeConn{}, nil))
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results=%+v err=%v, want one success without waiting for idle", results, err)
	}
}
