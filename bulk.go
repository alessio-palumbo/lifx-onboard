package onboard

import (
	"context"
	"fmt"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// Default cadence for BulkOnboard.
const (
	DefaultScanInterval = 2 * time.Second
)

// BulkOptions configures a BulkOnboard run.
type BulkOptions struct {
	// Options carries the single-device parameters applied to every device
	// found. Options.Target is ignored — use Targets.
	Options

	// Targets, when non-empty, is an allow-list: only SoftAPs of these
	// devices are onboarded and every other visible SoftAP is ignored (e.g.
	// other people's test devices). The run ends once every target has been
	// attempted, and a target never seen gets a Result with Phase PhaseScan
	// and ErrNoDevicesFound. Empty onboards every visible LIFX SoftAP.
	Targets []device.Serial

	// MaxDevices caps the number of attempts (successful or not). Zero
	// disables the cap.
	MaxDevices int

	// ScanInterval between scan passes. Defaults to DefaultScanInterval.
	ScanInterval time.Duration

	// StopWhenIdleFor stops the loop once this much wall-clock time has
	// passed with no newly-discovered serial. Zero disables the idle exit
	// (the loop runs until ctx is cancelled or MaxDevices is hit).
	StopWhenIdleFor time.Duration
}

func (b *BulkOptions) bulkDefaults() error {
	if err := b.Options.defaults(); err != nil {
		return err
	}
	if b.ScanInterval <= 0 {
		b.ScanInterval = DefaultScanInterval
	}
	return nil
}

// pendingVerify tracks one in-flight verification.
type pendingVerify struct {
	ap       scanner.AP
	deadline time.Time
	started  time.Time
}

// BulkOnboard repeatedly scans for LIFX SoftAPs and onboards each new one.
// Onboarding itself is serial (joining a SoftAP changes the host's global
// WiFi state) but verification of previously-onboarded devices is
// interleaved between SoftAP visits and drained after the scan loop exits.
//
// Returns one Result per attempted device. The Err field on each Result
// distinguishes success from failure. The outer error is non-nil only for
// catastrophic loop-setup problems (currently: missing credentials).
func BulkOnboard(ctx context.Context, opts BulkOptions) ([]Result, error) {
	return bulkWithDial(ctx, opts, realDial)
}

func bulkWithDial(ctx context.Context, opts BulkOptions, dial dialFunc) ([]Result, error) {
	if err := opts.bulkDefaults(); err != nil {
		return nil, err
	}
	start := time.Now()
	targets := map[device.Serial]bool{}
	for _, s := range opts.Targets {
		targets[s] = true
	}

	results, err := bulkLoop(ctx, opts, dial, targets)

	// Report allow-listed devices that never showed up.
	attempted := map[device.Serial]bool{}
	for _, r := range results {
		attempted[r.Serial] = true
	}
	for _, s := range opts.Targets {
		if attempted[s] {
			continue
		}
		attempted[s] = true
		nerr := fmt.Errorf("%w: target serial %s not seen", ErrNoDevicesFound, s)
		emit(opts.Events, EventFailed{Serial: s, Phase: PhaseScan, Err: nerr})
		results = append(results, Result{Serial: s, Took: time.Since(start), Phase: PhaseScan, Err: nerr})
	}
	return results, err
}

func bulkLoop(ctx context.Context, opts BulkOptions, dial dialFunc, targets map[device.Serial]bool) ([]Result, error) {
	rejoin := rejoinTargets(&opts.Options, opts.RejoinSSID, opts.RejoinPassword, detectOriginalSSID(ctx, &opts.Options))

	var (
		results       []Result
		pending       = map[device.Serial]*pendingVerify{}
		seen          = map[device.Serial]bool{}
		lastDiscovery = time.Now()
	)

	finalize := func(serial device.Serial, verified bool, err error, phase string, started time.Time) {
		r := Result{
			Serial:   serial,
			Verified: verified,
			Took:     time.Since(started),
			Phase:    phase,
			Err:      err,
		}
		results = append(results, r)
	}

	pollPending := func() {
		if len(pending) == 0 || opts.Sender == nil {
			return
		}
		live := map[device.Serial]bool{}
		for _, d := range opts.Sender.GetDevices() {
			if !onHomeLAN(d, opts.SoftAPAddr) {
				continue
			}
			live[d.Serial] = true
		}
		now := time.Now()
		for s, pv := range pending {
			switch {
			case live[s]:
				emit(opts.Events, EventVerified{Serial: s, Took: now.Sub(pv.started)})
				finalize(s, true, nil, "", pv.started)
				delete(pending, s)
			case !now.Before(pv.deadline):
				emit(opts.Events, EventFailed{Serial: s, Phase: PhaseVerify, Err: ErrVerifyTimeout})
				finalize(s, false, ErrVerifyTimeout, PhaseVerify, pv.started)
				delete(pending, s)
			}
		}
	}

	attemptsRemaining := func() bool {
		if len(targets) > 0 && len(seen) >= len(targets) {
			return false // every allow-listed device attempted
		}
		return opts.MaxDevices == 0 || len(results)+len(pending) < opts.MaxDevices
	}

	idleExpired := func() bool {
		return opts.StopWhenIdleFor > 0 && time.Since(lastDiscovery) >= opts.StopWhenIdleFor
	}

	// --- scan loop ---
	for {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if !attemptsRemaining() && len(pending) == 0 {
			return results, nil
		}

		if attemptsRemaining() {
			aps, err := opts.Scanner.Scan(ctx, scanner.ScanOptions{
				MinRSSI:        opts.MinRSSI,
				IncludeNonLIFX: opts.IncludeNonLIFX,
			})
			if err != nil {
				emit(opts.Events, EventFailed{Phase: PhaseScan, Err: err})
			} else if len(aps) > 0 {
				emit(opts.Events, EventDiscovered{APs: aps})
			}

			for _, ap := range aps {
				if !attemptsRemaining() {
					break
				}
				if ap.Serial.IsNil() || seen[ap.Serial] {
					continue
				}
				if len(targets) > 0 && !targets[ap.Serial] {
					continue
				}
				seen[ap.Serial] = true
				lastDiscovery = time.Now()

				started := time.Now()
				if err := onboardOneNoVerify(ctx, &opts.Options, ap, dial, started, rejoin); err != nil {
					// onboardOneNoVerify already appended the failure Result via its return value.
					// Capture it from the helper.
					finalize(err.serial, false, err.err, err.phase, err.started)
					continue
				}

				if opts.VerifyTimeout > 0 && opts.Sender != nil {
					emit(opts.Events, EventVerifying{Serial: ap.Serial, Timeout: opts.VerifyTimeout})
					pending[ap.Serial] = &pendingVerify{
						ap:       ap,
						deadline: time.Now().Add(opts.VerifyTimeout),
						started:  started,
					}
				} else {
					finalize(ap.Serial, false, nil, "", started)
				}
			}
		}

		pollPending()

		if !attemptsRemaining() && len(pending) == 0 {
			return results, nil
		}
		if idleExpired() && len(pending) == 0 {
			return results, nil
		}

		sleep := opts.ScanInterval
		if len(pending) > 0 && opts.VerifyPoll < sleep {
			sleep = opts.VerifyPoll
		}
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// onboardErr is a typed error carrying the bits BulkOnboard needs to build
// the per-device Result on a failure path. It is not returned from any
// public function.
type onboardErr struct {
	err     error
	phase   string
	serial  device.Serial
	started time.Time
}

func (e *onboardErr) Error() string { return e.err.Error() }
func (e *onboardErr) Unwrap() error { return e.err }

// onboardOneNoVerify performs the scan-already-done, Join → Dial → Configure
// → RejoinHome sequence for one AP and returns nil on success. On failure
// it returns an *onboardErr with phase tagging.
func onboardOneNoVerify(ctx context.Context, opts *Options, ap scanner.AP, dial dialFunc, started time.Time, rejoin []rejoinTarget) *onboardErr {
	if err := joinAP(ctx, opts, ap); err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseJoin, Err: err})
		return &onboardErr{err: err, phase: PhaseJoin, serial: ap.Serial, started: started}
	}
	if phase, err := configure(opts, ap, dial); err != nil {
		recoverHost(ctx, opts, ap, rejoin)
		return &onboardErr{err: err, phase: phase, serial: ap.Serial, started: started}
	}
	forgetSoftAP(ctx, opts, ap)
	leaveSoftAP(ctx, opts, ap)
	if err := rejoinHome(ctx, opts, ap, rejoin); err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseRejoin, Err: err})
		return &onboardErr{err: err, phase: PhaseRejoin, serial: ap.Serial, started: started}
	}
	return nil
}
