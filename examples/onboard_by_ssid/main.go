// onboard_by_ssid is the minimal library example: onboard one LIFX device
// with OnboardBySSID and print progress events. For day-to-day use and
// hardware testing, use the CLI in cmd/lifx-onboard instead.
//
// Usage:
//
//	export LIFX_ONBOARD_SSID='YourHomeNetwork'
//	export LIFX_ONBOARD_PASSWORD='secret'
//	go run ./examples/onboard_by_ssid 'LIFX A19 228447'   # by SoftAP SSID
//	go run ./examples/onboard_by_ssid d073d5228447        # by serial (scans for the SSID)
//
// macOS: onboarding by serial needs unredacted WiFi scans, which macOS only
// gives to a process launched by LaunchServices with Location Services
// granted — see the README. Connecting to the SoftAP can also be blocked
// for binaries started from some terminals (seen with iTerm2); run from
// Terminal.app, or use the CLI bundle.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	onboard "github.com/alessio-palumbo/lifx-onboard"
	"github.com/alessio-palumbo/lifxlan-go/pkg/controller"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: onboard_by_ssid <bulb SSID | serial | last 6 hex chars>")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Any LANSender works for verification; lifxlan-go's Controller does.
	ctrl, err := controller.New()
	if err != nil {
		log.Fatalf("controller: %v", err)
	}
	defer ctrl.Close()

	events := make(chan onboard.Event, 32)
	go func() {
		for e := range events {
			fmt.Printf("%T %+v\n", e, e)
		}
	}()

	res, err := onboard.OnboardBySSID(ctx, onboard.OnboardBySSIDOptions{
		Options: onboard.Options{
			SSID:          os.Getenv("LIFX_ONBOARD_SSID"),
			Password:      os.Getenv("LIFX_ONBOARD_PASSWORD"),
			Sender:        ctrl,
			VerifyTimeout: onboard.DefaultVerifyTimeout,
			Events:        events,
		},
		BulbSSID: os.Args[1],
	})
	if err != nil {
		log.Fatalf("onboard %s failed at phase %q: %v", res.Serial, res.Phase, err)
	}
	fmt.Printf("onboarded %s (verified=%v, took=%s)\n", res.Serial, res.Verified, res.Took)
}
