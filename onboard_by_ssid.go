package onboard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

// OnboardBySSIDOptions configures OnboardBySSID. It embeds Options so the
// shared fields (home SSID/password, Sender, VerifyTimeout, Interface,
// Logger, Events, ...) carry across unchanged.
//
// Joins go through `networksetup -setairportnetwork` (macOS) / `nmcli`
// (Linux) by SSID, so a full SSID works even where the OS redacts scan
// results; a serial needs an unredacted scan first (see BulbSSID).
type OnboardBySSIDOptions struct {
	Options

	// BulbSSID identifies the device's SoftAP. Required. Accepts:
	//   - the full SSID, e.g. "LIFX A19 228447" — joined directly;
	//   - the device serial, e.g. "d073d5228447" (separators and case are
	//     ignored), or just its last 6 hex chars, e.g. "228447" — the
	//     SoftAP is found by scanning (Options.Scanner, retried for
	//     Options.FindTimeout) for the "LIFX …" SSID ending in those chars.
	//     Scanning needs unredacted results, i.e. Location Services on
	//     macOS.
	// The device serial (from the SSID's trailing 6 hex chars) is used for
	// post-onboard verification.
	BulbSSID string
}

// waitFunc polls addr until it accepts a TCP connection or timeout elapses.
// check runs before each attempt; a non-nil error from it ends the wait
// immediately. Replaced in tests.
type waitFunc func(ctx context.Context, addr string, timeout, poll time.Duration, lg *slog.Logger, check func() error) error

func realWait(ctx context.Context, addr string, timeout, poll time.Duration, lg *slog.Logger, check func() error) error {
	err := retry(ctx, timeout, poll, lg, "softap dial", func() error {
		if err := check(); err != nil {
			return stopRetry{err}
		}
		dctx, cancel := context.WithTimeout(ctx, poll)
		defer cancel()
		var d net.Dialer
		conn, err := d.DialContext(dctx, "tcp4", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, ErrLeftSoftAP) {
		return fmt.Errorf("%w (last dial error: %v)", ErrSoftAPWaitTimeout, err)
	}
	return err
}

// onSoftAPCheck returns a wait check that fails once the host is reported on
// a network other than the device's SoftAP — no point waiting out the
// timeout for a device that has gone away. Never fails when the current
// network can't be read, or while the host is between networks.
func onSoftAPCheck(ctx context.Context, opts *Options, ap scanner.AP) func() error {
	return func() error {
		if cur := currentSSID(ctx, opts); cur != "" && cur != ap.SSID {
			return fmt.Errorf("%w (now on %q)", ErrLeftSoftAP, cur)
		}
		return nil
	}
}

// OnboardBySSID configures a single LIFX device when the caller already
// knows the SoftAP's SSID — i.e. the user picked it from a list or copied
// it off the bulb. Given a full SSID the library does not scan (given a
// serial or its last 6 hex chars it scans to find the SSID first); it joins
// via the platform Joiner, waits for the bulb's TLS socket to come up, pushes
// WifiSetAccessPoint, removes the SoftAP from the host's saved networks and
// disconnects from it, rejoins the network the host was on before (else
// Options.SSID), and (optionally) verifies the device reappeared on the LAN.
//
// On macOS, scanning and reading the current network require a process
// launched by LaunchServices with Location Services granted; without them
// a full SSID still works and the host rejoins Options.SSID.
func OnboardBySSID(ctx context.Context, opts OnboardBySSIDOptions) (Result, error) {
	return onboardBySSIDWith(ctx, opts, realDial, realWait)
}

func onboardBySSIDWith(ctx context.Context, opts OnboardBySSIDOptions, dial dialFunc, wait waitFunc) (Result, error) {
	start := time.Now()

	if err := opts.Options.defaults(); err != nil {
		return Result{Took: time.Since(start), Phase: PhaseScan, Err: err}, err
	}
	if opts.BulbSSID == "" {
		err := fmt.Errorf("%w: BulbSSID is required", ErrInvalidBulbSSID)
		return Result{Took: time.Since(start), Phase: PhaseScan, Err: err}, err
	}

	ap, ok := scanner.APFromSSID(opts.BulbSSID, false)
	if !ok || ap.Serial.IsNil() {
		serial, isSerial := ParseSerial(opts.BulbSSID)
		if !isSerial {
			err := fmt.Errorf("%w: %q (expected a LIFX SoftAP SSID, a serial, or its last 6 hex chars)", ErrInvalidBulbSSID, opts.BulbSSID)
			return Result{Took: time.Since(start), Phase: PhaseScan, Err: err}, err
		}
		opts.Target = serial
		found, err := findAP(ctx, &opts.Options)
		if err != nil {
			emit(opts.Events, EventFailed{Serial: serial, Phase: PhaseScan, Err: err})
			return Result{Serial: serial, Took: time.Since(start), Phase: PhaseScan, Err: err}, err
		}
		ap = found
	}

	targets := rejoinTargets(&opts.Options, opts.RejoinSSID, opts.RejoinPassword, detectOriginalSSID(ctx, &opts.Options))

	if err := joinAP(ctx, &opts.Options, ap); err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseJoin, Err: err})
		return Result{Serial: ap.Serial, Took: time.Since(start), Phase: PhaseJoin, Err: err}, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			recoverHost(ctx, &opts.Options, ap, targets)
		}
	}()

	emit(opts.Events, EventWaitingForSoftAP{
		Serial:  ap.Serial,
		Addr:    opts.SoftAPAddr,
		Timeout: opts.WaitTimeout,
	})
	waitStart := time.Now()
	if err := wait(ctx, opts.SoftAPAddr, opts.WaitTimeout, opts.WaitPoll, opts.Logger, onSoftAPCheck(ctx, &opts.Options, ap)); err != nil {
		werr := err
		if !errors.Is(err, ErrSoftAPWaitTimeout) &&
			!errors.Is(err, ErrLeftSoftAP) &&
			!errors.Is(err, context.DeadlineExceeded) &&
			!errors.Is(err, context.Canceled) {
			werr = fmt.Errorf("%w: %v", ErrSoftAPWaitTimeout, err)
		}
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseWait, Err: werr})
		return Result{Serial: ap.Serial, Took: time.Since(start), Phase: PhaseWait, Err: werr}, werr
	}
	emit(opts.Events, EventOnSoftAP{Serial: ap.Serial, Addr: opts.SoftAPAddr, Took: time.Since(waitStart)})

	if phase, err := configure(&opts.Options, ap, dial); err != nil {
		return Result{Serial: ap.Serial, Took: time.Since(start), Phase: phase, Err: err}, err
	}

	handedOff = true // from here the normal path rejoins
	forgetSoftAP(ctx, &opts.Options, ap)
	leaveSoftAP(ctx, &opts.Options, ap)

	if err := rejoinHome(ctx, &opts.Options, ap, targets); err != nil {
		emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseRejoin, Err: err})
		return Result{Serial: ap.Serial, Took: time.Since(start), Phase: PhaseRejoin, Err: err}, err
	}

	verified := false
	if opts.VerifyTimeout > 0 {
		v, err := verify(ctx, &opts.Options, ap)
		if err != nil {
			emit(opts.Events, EventFailed{Serial: ap.Serial, Phase: PhaseVerify, Err: err})
			return Result{Serial: ap.Serial, Took: time.Since(start), Phase: PhaseVerify, Err: err}, err
		}
		verified = v
	}

	return Result{Serial: ap.Serial, Verified: verified, Took: time.Since(start)}, nil
}

// ParseSerial parses a device serial ("d073d5228447", "D0:73:D5:22:84:47")
// or just its last 6 hex chars ("228447") into a LIFX serial — the forms a
// user is likely to type. The LIFX OUI prefix is stripped when present,
// since SoftAP SSIDs only carry the last three bytes.
func ParseSerial(s string) (device.Serial, bool) {
	clean := strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(strings.TrimSpace(s)))
	oui := hex.EncodeToString(scanner.LIFXOUI[:])
	if len(clean) == 12 && strings.HasPrefix(clean, oui) {
		clean = clean[len(oui):]
	}
	if len(clean) != 6 {
		return device.Serial{}, false
	}
	var suffix [3]byte
	if _, err := hex.Decode(suffix[:], []byte(clean)); err != nil {
		return device.Serial{}, false
	}
	o := scanner.LIFXOUI
	return device.Serial{o[0], o[1], o[2], suffix[0], suffix[1], suffix[2], 0, 0}, true
}
