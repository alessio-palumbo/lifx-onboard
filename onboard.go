package onboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/internal/wire"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifx-onboard/softap"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// emptyScanHint is logged when Scanner.Scan returns zero APs. On macOS the
// usual cause is redaction: names are only revealed to a process launched
// by LaunchServices as an app with Location Services granted.
var emptyScanHint = func() string {
	base := "scanner returned no APs — is a LIFX device in SoftAP mode within range?"
	if runtime.GOOS == "darwin" {
		return base + " On macOS this also happens when scan results are redacted: run from an app bundle launched by LaunchServices with Location Services allowed (the CLI does this via scripts/bundle.sh)."
	}
	return base
}()

// Phase names used in EventFailed and error messages.
const (
	PhaseScan      = "scan"
	PhaseJoin      = "join"
	PhaseWait      = "wait"
	PhaseDial      = "dial"
	PhaseConfigure = "configure"
	PhaseRejoin    = "rejoin"
	PhaseVerify    = "verify"
)

// Result describes the outcome of an onboarding attempt — success or failure.
// Single Onboard also returns its error directly; BulkOnboard reports
// per-device outcomes only through this struct.
type Result struct {
	// Serial of the device that was configured. May be zero if the failure
	// happened before any AP was selected.
	Serial device.Serial
	// Verified is true when the device reappeared on the home LAN within
	// VerifyTimeout. Always false when VerifyTimeout was zero or when the
	// attempt failed.
	Verified bool
	// Took is the wall-clock duration from the start of the attempt to its
	// return.
	Took time.Duration
	// Phase is the FSM phase name on failure (one of PhaseScan, PhaseJoin,
	// PhaseDial, PhaseConfigure, PhaseRejoin, PhaseVerify). Empty on success.
	Phase string
	// Err is the failure cause; nil on success.
	Err error
}

// softAPConn is the subset of *softap.Conn the FSM uses. Defined as an
// interface so tests can substitute a fake.
type softAPConn interface {
	SendSetAccessPoint(target device.Serial, ssid, password string, security wire.WifiSecurity) error
	Close() error
}

// dialFunc returns a softAPConn. Replaced in tests to bypass real TLS.
type dialFunc func(softap.Options) (softAPConn, error)

func realDial(o softap.Options) (softAPConn, error) {
	c, err := softap.Dial(o)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Onboard runs the full onboarding sequence for a single device. The call is
// strictly sequential: it returns when the device is verified, when a phase
// fails, or when ctx is cancelled.
func Onboard(ctx context.Context, opts Options) (Result, error) {
	return onboardWithDial(ctx, opts, realDial)
}

// onboardWithDial is the test seam.
func onboardWithDial(ctx context.Context, opts Options, dial dialFunc) (Result, error) {
	start := time.Now()
	if err := opts.defaults(); err != nil {
		return Result{Took: time.Since(start), Phase: PhaseScan, Err: err}, err
	}

	rejoin := rejoinTargets(&opts, opts.RejoinSSID, opts.RejoinPassword, detectOriginalSSID(ctx, &opts))

	ap, err := findAP(ctx, &opts)
	if err != nil {
		emit(opts.Events, EventFailed{Serial: opts.Target, Phase: PhaseScan, Err: err})
		return Result{Serial: opts.Target, Took: time.Since(start), Phase: PhaseScan, Err: err}, err
	}

	if oerr := onboardOneNoVerify(ctx, &opts, ap, dial, start, rejoin); oerr != nil {
		return Result{
			Serial: oerr.serial,
			Took:   time.Since(start),
			Phase:  oerr.phase,
			Err:    oerr.err,
		}, oerr.err
	}

	verified := false
	if opts.VerifyTimeout > 0 {
		v, err := verify(ctx, &opts, ap)
		if err != nil {
			emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseVerify, Err: err})
			return Result{Serial: ap.Serial, Took: time.Since(start), Phase: PhaseVerify, Err: err}, err
		}
		verified = v
	}

	return Result{Serial: ap.Serial, Verified: verified, Took: time.Since(start)}, nil
}

// stopRetry wraps an error that retry returns immediately instead of
// retrying.
type stopRetry struct{ err error }

func (s stopRetry) Error() string { return s.err.Error() }
func (s stopRetry) Unwrap() error { return s.err }

// retry calls fn until it succeeds or timeout elapses, sleeping poll between
// attempts. Returns the last attempt's error, or ctx's error if cancelled.
// fn can end the retries early by returning a stopRetry.
func retry(ctx context.Context, timeout, poll time.Duration, lg *slog.Logger, what string, fn func() error) error {
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if stop := (stopRetry{}); errors.As(err, &stop) {
			return stop.err
		}
		logger(lg).Debug(what+" attempt failed", "attempt", attempt, "err", err.Error())
		if ctx.Err() != nil {
			return ctx.Err()
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(poll, remaining)):
		}
	}
}

// findAP scans until a matching SoftAP shows up or FindTimeout elapses.
func findAP(ctx context.Context, opts *Options) (scanner.AP, error) {
	var (
		ap       scanner.AP
		notFound error // last "scanned fine, target not there" result
	)
	err := retry(ctx, opts.FindTimeout, opts.FindPoll, opts.Logger, "scan", func() error {
		var err error
		ap, err = scanOnce(ctx, opts)
		if errors.Is(err, ErrNoDevicesFound) {
			notFound = err
		}
		return err
	})
	// A transient scan failure on the last attempt (e.g. CoreWLAN "Resource
	// busy" from back-to-back scans) shouldn't mask that earlier scans
	// completed without finding the device.
	if err != nil && notFound != nil && !errors.Is(err, ErrNoDevicesFound) && ctx.Err() == nil {
		err = notFound
	}
	if errors.Is(err, errEmptyScan) {
		logger(opts.Logger).Warn(emptyScanHint)
		err = ErrNoDevicesFound
	}
	return ap, err
}

// errEmptyScan marks a scan pass that returned no APs at all, as opposed
// to APs that didn't match the target.
var errEmptyScan = fmt.Errorf("%w: scan returned no APs", ErrNoDevicesFound)

func scanOnce(ctx context.Context, opts *Options) (scanner.AP, error) {
	emit(opts.Events, EventScanning{Interface: opts.Scanner.Interface()})

	aps, err := opts.Scanner.Scan(ctx, scanner.ScanOptions{
		MinRSSI:        opts.MinRSSI,
		IncludeNonLIFX: opts.IncludeNonLIFX,
	})
	if err != nil {
		return scanner.AP{}, fmt.Errorf("%s: %w", PhaseScan, err)
	}
	if len(aps) == 0 {
		return scanner.AP{}, errEmptyScan
	}
	emit(opts.Events, EventDiscovered{APs: aps})

	if !opts.Target.IsNil() {
		for _, a := range aps {
			if a.Serial == opts.Target {
				return a, nil
			}
		}
		return scanner.AP{}, fmt.Errorf("%w: target serial %s not seen", ErrNoDevicesFound, opts.Target)
	}
	for _, a := range aps {
		if !a.Serial.IsNil() {
			return a, nil
		}
	}
	return scanner.AP{}, ErrNoDevicesFound
}

func joinAP(ctx context.Context, opts *Options, ap scanner.AP) error {
	emit(opts.Events, EventJoining{Serial: ap.Serial, SSID: ap.SSID})
	// Retried because a freshly reset device may not be advertising its
	// SoftAP yet ("Could not find network").
	err := retry(ctx, opts.FindTimeout, opts.FindPoll, opts.Logger, "join", func() error {
		return opts.Joiner.Join(ctx, ap)
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJoinFailed, err)
	}
	emit(opts.Events, EventJoined{Serial: ap.Serial})
	return nil
}

func configure(opts *Options, ap scanner.AP, dial dialFunc) (string, error) {
	emit(opts.Events, EventDialing{Serial: ap.Serial, Addr: opts.SoftAPAddr})

	conn, err := dial(softap.Options{
		Addr:        opts.SoftAPAddr,
		DialTimeout: opts.DialTimeout,
		LegacyTLS:   opts.LegacyTLS,
	})
	if err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseDial, Err: err})
		return PhaseDial, err
	}
	defer conn.Close()

	if err := conn.SendSetAccessPoint(ap.Serial, opts.SSID, opts.Password, opts.Security); err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseConfigure, Err: err})
		return PhaseConfigure, err
	}
	emit(opts.Events, EventConfigured{Serial: ap.Serial})
	return "", nil
}

// onHomeLAN reports whether d was seen somewhere other than the SoftAP. The
// LAN transport keeps discovering while the host sits on the device's
// SoftAP, so it can record the device at the SoftAP address (172.16.0.1)
// before the device has joined the home network; that must not count as
// verified.
func onHomeLAN(d device.Device, softAPAddr string) bool {
	if d.Address == nil {
		return true
	}
	host, _, err := net.SplitHostPort(softAPAddr)
	if err != nil {
		return true
	}
	return !d.Address.IP.Equal(net.ParseIP(host))
}

func verify(ctx context.Context, opts *Options, ap scanner.AP) (bool, error) {
	if opts.Sender == nil {
		return false, fmt.Errorf("%w: opts.Sender is required when VerifyTimeout > 0", ErrVerifyTimeout)
	}
	emit(opts.Events, EventVerifying{Serial: ap.Serial, Timeout: opts.VerifyTimeout})

	start := time.Now()
	deadline := start.Add(opts.VerifyTimeout)
	ticker := time.NewTicker(opts.VerifyPoll)
	defer ticker.Stop()

	check := func() bool {
		for _, d := range opts.Sender.GetDevices() {
			if d.Serial == ap.Serial && onHomeLAN(d, opts.SoftAPAddr) {
				return true
			}
		}
		return false
	}

	if check() {
		emit(opts.Events, EventVerified{Serial: ap.Serial, Took: time.Since(start)})
		return true, nil
	}

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			if check() {
				emit(opts.Events, EventVerified{Serial: ap.Serial, Took: time.Since(start)})
				return true, nil
			}
			if !time.Now().Before(deadline) {
				return false, ErrVerifyTimeout
			}
		}
	}
}
