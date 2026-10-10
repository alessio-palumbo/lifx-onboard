package onboard

import (
	"context"
	"time"

	"github.com/alessio-palumbo/lifx-onboard/scanner"
)

// rejoinTarget is a network the host can rejoin after the handoff.
type rejoinTarget struct {
	ssid, password string
	// autoJoin marks the host's original network, which the OS reconnects
	// to by itself once the SoftAP disappears.
	autoJoin bool
}

// canReadCurrentSSID reports whether the Scanner or Joiner can report the
// host's current network.
func canReadCurrentSSID(opts *Options) bool {
	for _, c := range []any{opts.Scanner, opts.Joiner} {
		if _, ok := c.(scanner.CurrentNetworkReporter); ok {
			return true
		}
	}
	return false
}

// waitForAutoJoin waits for the OS to reconnect the host to ssid by itself.
// It returns the host's network when it gave up waiting (or ssid on
// success) and whether that is ssid. The device keeps its SoftAP up for a
// while after receiving credentials and the OS won't auto-join while still
// associated, so the AutoJoinWait budget only starts once the host has left
// softAP (bounded by RejoinTimeout in case it never does).
func waitForAutoJoin(ctx context.Context, opts *Options, ssid, softAP string) (string, bool) {
	if opts.AutoJoinWait <= 0 || !canReadCurrentSSID(opts) {
		return "", false
	}
	leaveBy := time.Now().Add(opts.RejoinTimeout)
	var deadline time.Time // set once the host is off the SoftAP
	for {
		cur := currentSSID(ctx, opts)
		if cur == ssid {
			return cur, true
		}
		now := time.Now()
		if deadline.IsZero() && cur != softAP {
			logger(opts.Logger).Debug("left device SoftAP, waiting for OS auto-join", "ssid", ssid)
			deadline = now.Add(opts.AutoJoinWait)
		}
		if (deadline.IsZero() && now.After(leaveBy)) || (!deadline.IsZero() && now.After(deadline)) {
			return cur, false
		}
		select {
		case <-ctx.Done():
			return cur, false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// currentSSID asks whichever of Scanner / Joiner implements
// scanner.CurrentNetworkReporter for the host's current network. Returns ""
// when unknown.
func currentSSID(ctx context.Context, opts *Options) string {
	for _, c := range []any{opts.Scanner, opts.Joiner} {
		r, ok := c.(scanner.CurrentNetworkReporter)
		if !ok {
			continue
		}
		ssid, err := r.CurrentSSID(ctx)
		if err != nil {
			logger(opts.Logger).Debug("current network lookup failed", "err", err.Error())
			continue
		}
		if ssid != "" {
			return ssid
		}
	}
	return ""
}

// detectOriginalSSID returns the network the host is on before it joins a
// SoftAP, using whichever of Scanner / Joiner implements
// scanner.CurrentNetworkReporter. Returns "" when unknown, or when the host
// is already sitting on a LIFX SoftAP.
func detectOriginalSSID(ctx context.Context, opts *Options) string {
	ssid := currentSSID(ctx, opts)
	if ssid == "" {
		return ""
	}
	if ap, ok := scanner.APFromSSID(ssid, false); ok && !ap.Serial.IsNil() {
		return ""
	}
	logger(opts.Logger).Debug("host network before onboarding", "ssid", ssid)
	return ssid
}

// rejoinTargets lists the networks to try after the handoff, best first:
//  1. an explicit override (explicitSSID / explicitPassword);
//  2. the network the host was on before (original), using the password
//     the OS already has saved for it;
//  3. the home network handed to the device (Options.SSID / Password).
//
// The home network doubles as the fallback when rejoining the original
// network fails (e.g. the OS wants interactive keychain approval).
func rejoinTargets(opts *Options, explicitSSID, explicitPassword, original string) []rejoinTarget {
	if explicitSSID != "" {
		if explicitPassword == "" && explicitSSID == opts.SSID {
			explicitPassword = opts.Password
		}
		return []rejoinTarget{{ssid: explicitSSID, password: explicitPassword}}
	}
	home := rejoinTarget{ssid: opts.SSID, password: opts.Password}
	if original == "" || original == opts.SSID {
		return []rejoinTarget{home}
	}
	return []rejoinTarget{{ssid: original, autoJoin: true}, home}
}

// forgetSoftAP removes the device's SoftAP from the host's saved networks,
// when the Joiner supports it. Joining the SoftAP saved it near the top of
// the preferred list; left there, the OS's auto-join keeps waiting for it
// instead of returning to the original network. Best effort: failures are
// logged, not returned.
func forgetSoftAP(ctx context.Context, opts *Options, ap scanner.AP) {
	f, ok := opts.Joiner.(scanner.NetworkForgetter)
	if !ok {
		return
	}
	if err := f.Forget(ctx, ap.SSID); err != nil {
		logger(opts.Logger).Warn("could not remove device SoftAP from saved networks", "ssid", ap.SSID, "err", err.Error())
		return
	}
	logger(opts.Logger).Debug("removed device SoftAP from saved networks", "ssid", ap.SSID)
}

// leaveSoftAP drops the host's association with the device's SoftAP right
// after the handoff, when the Scanner or Joiner supports it, so the OS can
// auto-join the original network immediately instead of waiting for the
// device to take its SoftAP down. Best effort.
func leaveSoftAP(ctx context.Context, opts *Options, ap scanner.AP) {
	// Only drop an association with the SoftAP itself: after a failure the
	// OS may already have moved the host back to a good network.
	if cur := currentSSID(ctx, opts); cur != ap.SSID {
		logger(opts.Logger).Debug("not on device SoftAP, not disconnecting", "ssid", ap.SSID, "current", cur)
		return
	}
	for _, c := range []any{opts.Scanner, opts.Joiner} {
		d, ok := c.(scanner.Disassociator)
		if !ok {
			continue
		}
		if err := d.Disassociate(ctx); err != nil {
			logger(opts.Logger).Warn("could not leave device SoftAP", "ssid", ap.SSID, "err", err.Error())
			return
		}
		logger(opts.Logger).Debug("left device SoftAP", "ssid", ap.SSID, "now", currentSSID(ctx, opts))
		return
	}
}

// recoverHost returns the host to its network after a failure past the
// SoftAP join, so a failed onboarding doesn't strand it on the device's
// SoftAP. It still runs after ctx is cancelled (e.g. Ctrl-C) — restoring
// connectivity matters more than exiting instantly — bounded by the rejoin
// timeouts. Best effort: failures are logged.
func recoverHost(ctx context.Context, opts *Options, ap scanner.AP, targets []rejoinTarget) {
	budget := opts.RejoinTimeout*time.Duration(len(targets)) + max(opts.AutoJoinWait, 0)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	defer cancel()
	forgetSoftAP(rctx, opts, ap)
	leaveSoftAP(rctx, opts, ap)
	if err := rejoinHome(rctx, opts, ap, targets); err != nil {
		logger(opts.Logger).Warn("could not return the host to its network after a failed onboarding", "err", err.Error())
	}
}

// rejoinHome reconnects the host to the first target that works. Each
// target is retried for up to RejoinTimeout: right after the device drops
// its SoftAP the host's WiFi takes a few seconds to see networks again, so
// early attempts commonly fail with "Could not find network".
//
// The OS's own auto-join often reconnects to the original network at the
// same moment, making our explicit join fail ("tmpErr") even though the host
// ends up where we wanted. So when the current network can be read, being
// on the target counts as success regardless of what the Joiner returned.
func rejoinHome(ctx context.Context, opts *Options, ap scanner.AP, targets []rejoinTarget) error {
	serial := ap.Serial
	var err error
	for i, t := range targets {
		emit(opts.Events, EventRejoining{Serial: serial, SSID: t.ssid})
		if t.autoJoin {
			cur, ok := waitForAutoJoin(ctx, opts, t.ssid, ap.SSID)
			if ok {
				emit(opts.Events, EventRejoined{Serial: serial, SSID: t.ssid})
				return nil
			}
			// The OS auto-joined another known network: keep its choice.
			// Forcing a join without the password is unreliable on macOS
			// (-3900 tmpErr) and every forced join raises that network's
			// auto-join priority.
			if cur != "" && cur != ap.SSID {
				logger(opts.Logger).Warn("OS rejoined a different network; keeping it", "wanted", t.ssid, "current", cur)
				emit(opts.Events, EventRejoined{Serial: serial, SSID: cur})
				return nil
			}
			logger(opts.Logger).Debug("OS did not auto-join, joining explicitly", "ssid", t.ssid)
		}
		tctx, cancel := context.WithTimeout(ctx, opts.RejoinTimeout)
		err = retry(ctx, opts.RejoinTimeout, opts.RejoinPoll, opts.Logger, "rejoin", func() error {
			if currentSSID(ctx, opts) == t.ssid {
				return nil
			}
			jerr := opts.Joiner.RejoinHome(tctx, t.ssid, t.password)
			if jerr != nil && currentSSID(ctx, opts) == t.ssid {
				logger(opts.Logger).Debug("rejoin reported failure but host is on the target network", "ssid", t.ssid, "err", jerr.Error())
				return nil
			}
			return jerr
		})
		cancel()
		if err == nil {
			emit(opts.Events, EventRejoined{Serial: serial, SSID: t.ssid})
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if i < len(targets)-1 {
			logger(opts.Logger).Warn("rejoin failed, trying next network", "ssid", t.ssid, "err", err.Error())
		}
	}
	return err
}
