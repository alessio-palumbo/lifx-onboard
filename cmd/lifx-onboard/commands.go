package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	onboard "github.com/alessio-palumbo/lifx-onboard"
	"github.com/alessio-palumbo/lifx-onboard/scanner"
	"github.com/alessio-palumbo/lifxlan-go/pkg/device"
)

func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: lifx-onboard %s %s\n\nFlags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseOrExit parses args into fs. done is true when the caller should
// return code immediately (help requested or bad flags).
func parseOrExit(fs *flag.FlagSet, args []string) (positional []string, code int, done bool) {
	positional, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return nil, exitOK, true
	}
	if err != nil {
		return nil, exitUsage, true
	}
	return positional, 0, false
}

// rejoinOverride returns --rejoin-ssid with its env password. When empty,
// the library rejoins the network the host was on before, falling back to
// --home-ssid.
func rejoinOverride(sf *sharedFlags) (ssid, password string) {
	if sf.rejoinSSID == "" {
		return "", ""
	}
	return sf.rejoinSSID, os.Getenv(envRejoinPassword)
}

func runSSID(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("ssid", "[flags] <bulb-ssid | serial | last-6-hex>", stderr)
	var sf sharedFlags
	sf.register(fs)
	waitTimeout := fs.Duration("wait-timeout", onboard.DefaultWaitTimeout, "how long to wait for the SoftAP at 172.16.0.1 after joining")

	pos, code, done := parseOrExit(fs, args)
	if done {
		return code
	}
	var bulbSSID string
	switch len(pos) {
	case 0:
		bulbSSID = os.Getenv(envBulbSSID)
	case 1:
		bulbSSID = pos[0]
	default:
		return usageError(fs, stderr, fmt.Sprintf("expected one bulb SSID, got %d arguments — quote SSIDs containing spaces", len(pos)))
	}
	if bulbSSID == "" {
		return usageError(fs, stderr, "bulb SSID or serial is required (e.g. \"LIFX A19 228447\", d073d5228447 or 228447; or set "+envBulbSSID+")")
	}
	if !strings.HasPrefix(bulbSSID, "LIFX") {
		// A serial / suffix is resolved to the full SSID by scanning.
		warnLocationAccess(stderr)
	}

	opts, err := sf.options(os.Stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard ssid: %v\n", err)
		return exitUsage
	}
	opts.WaitTimeout = *waitTimeout
	opts.RejoinSSID, opts.RejoinPassword = rejoinOverride(&sf)

	closeSender, err := attachSender(&opts)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard ssid: %v\n", err)
		return exitFailure
	}
	defer closeSender()

	ctx, cancel := signalContext()
	defer cancel()

	p := newPrinter(stdout, sf.json)
	events, stop := streamEvents(p)
	opts.Events = events

	res, err := onboard.OnboardBySSID(ctx, onboard.OnboardBySSIDOptions{
		Options:  opts,
		BulbSSID: bulbSSID,
	})
	stop()
	if res.Err == nil {
		res.Err = err
	}
	p.result(res)
	return exitCodeFor(ctx, res, err)
}

func runAuto(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("auto", "[flags] [serial]", stderr)
	var sf sharedFlags
	sf.register(fs)
	minRSSI := fs.Float64("min-rssi", 0, "ignore SoftAPs weaker than this RSSI (e.g. -70); 0 disables")

	pos, code, done := parseOrExit(fs, args)
	if done {
		return code
	}
	var target device.Serial
	switch len(pos) {
	case 0:
	case 1:
		s, err := device.SerialFromHex(pos[0])
		if err != nil {
			return usageError(fs, stderr, fmt.Sprintf("invalid serial %q: %v", pos[0], err))
		}
		target = s
	default:
		return usageError(fs, stderr, "expected at most one serial")
	}

	warnLocationAccess(stderr)

	opts, err := sf.options(os.Stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard auto: %v\n", err)
		return exitUsage
	}
	opts.Target = target
	opts.MinRSSI = *minRSSI
	opts.RejoinSSID, opts.RejoinPassword = rejoinOverride(&sf)

	closeSender, err := attachSender(&opts)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard auto: %v\n", err)
		return exitFailure
	}
	defer closeSender()

	ctx, cancel := signalContext()
	defer cancel()

	p := newPrinter(stdout, sf.json)
	events, stop := streamEvents(p)
	opts.Events = events

	res, err := onboard.Onboard(ctx, opts)
	stop()
	if res.Err == nil {
		res.Err = err
	}
	p.result(res)
	return exitCodeFor(ctx, res, err)
}

func runBulk(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("bulk", "[flags] [serial | last-6-hex ...]", stderr)
	var sf sharedFlags
	sf.register(fs)
	maxDevices := fs.Int("max", 0, "stop after this many attempts; 0 means no cap")
	idle := fs.Duration("idle", 2*time.Minute, "stop after this long without discovering a new device; 0 runs until interrupted")
	scanInterval := fs.Duration("scan-interval", onboard.DefaultScanInterval, "delay between scan passes")
	minRSSI := fs.Float64("min-rssi", 0, "ignore SoftAPs weaker than this RSSI (e.g. -70); 0 disables")

	pos, code, done := parseOrExit(fs, args)
	if done {
		return code
	}
	// Optional allow-list: only these devices are onboarded.
	var targets []device.Serial
	for _, arg := range pos {
		s, ok := onboard.ParseSerial(arg)
		if !ok {
			return usageError(fs, stderr, fmt.Sprintf("invalid serial %q (want d073d5xxxxxx or the last 6 hex chars)", arg))
		}
		targets = append(targets, s)
	}

	warnLocationAccess(stderr)

	opts, err := sf.options(os.Stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard bulk: %v\n", err)
		return exitUsage
	}
	opts.MinRSSI = *minRSSI
	opts.RejoinSSID, opts.RejoinPassword = rejoinOverride(&sf)

	closeSender, err := attachSender(&opts)
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard bulk: %v\n", err)
		return exitFailure
	}
	defer closeSender()

	ctx, cancel := signalContext()
	defer cancel()

	p := newPrinter(stdout, sf.json)
	events, stop := streamEvents(p)
	opts.Events = events

	results, err := onboard.BulkOnboard(ctx, onboard.BulkOptions{
		Options:         opts,
		Targets:         targets,
		MaxDevices:      *maxDevices,
		ScanInterval:    *scanInterval,
		StopWhenIdleFor: *idle,
	})
	stop()
	return reportBulk(ctx, p, stderr, results, err)
}

// reportBulk prints per-device results and a summary, then picks the exit
// code: interrupted, failure if any device failed, scan if none were found.
func reportBulk(ctx context.Context, p *printer, stderr io.Writer, results []onboard.Result, err error) int {
	failed := 0
	for _, r := range results {
		p.result(r)
		if r.Err != nil {
			failed++
		}
	}
	if !p.json {
		p.printf("%d attempted, %d succeeded, %d failed\n", len(results), len(results)-failed, failed)
	}
	switch {
	case ctx.Err() != nil:
		return exitInterrupted
	case err != nil:
		fmt.Fprintf(stderr, "lifx-onboard bulk: %v\n", err)
		if errors.Is(err, onboard.ErrMissingCredentials) {
			return exitUsage
		}
		return exitFailure
	case failed > 0:
		return exitFailure
	case len(results) == 0:
		return exitScan
	}
	return exitOK
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan", "[flags]", stderr)
	all := fs.Bool("all", false, "include non-LIFX networks")
	iface := fs.String("iface", "", "host WiFi interface (auto-detected when empty)")
	timeout := fs.Duration("timeout", 15*time.Second, "scan timeout")
	asJSON := fs.Bool("json", false, "emit one NDJSON record per AP")

	pos, code, done := parseOrExit(fs, args)
	if done {
		return code
	}
	if len(pos) > 0 {
		return usageError(fs, stderr, "scan takes no positional arguments")
	}

	warnLocationAccess(stderr)

	ctx, cancel := signalContext()
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	aps, err := scanner.NewDefaultScanner(*iface).Scan(ctx, scanner.ScanOptions{IncludeNonLIFX: *all})
	if err != nil {
		fmt.Fprintf(stderr, "lifx-onboard scan: %v\n", err)
		if errors.Is(err, scanner.ErrUnsupportedPlatform) {
			return exitFailure
		}
		return exitScan
	}
	sort.Slice(aps, func(i, j int) bool { return aps[i].RSSI > aps[j].RSSI })

	p := newPrinter(stdout, *asJSON)
	for _, ap := range aps {
		p.ap(ap)
	}
	if len(aps) == 0 {
		fmt.Fprintln(stderr, "no SoftAPs found")
		return exitScan
	}
	return exitOK
}
