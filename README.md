# lifx-onboard

Put LIFX lights on your WiFi from the command line or from your own Go
program.

A new or reset LIFX light broadcasts its own setup network, named like
`LIFX Candle Color 8274eb`. lifx-onboard connects to it, hands the light
your WiFi details, puts your computer back on its usual network, and checks
that the light has come online.

> **Status:** pre-1.0. The API may still change.

## Install

Download the archive for your system from the
[latest release](https://github.com/alessio-palumbo/lifx-onboard/releases/latest)
and verify it against `SHA256SUMS`:

- **macOS** — `darwin_universal.zip` contains `LifxOnboard.app`; see
  [macOS setup](#macos-setup).
- **Linux** — `linux_amd64`, `linux_arm64` or `linux_armv7` (32-bit
  Raspberry Pi OS); put `lifx-onboard` on your `PATH`.
- **Windows** — `windows_amd64` or `windows_arm64`; run `lifx-onboard.exe`.

Or with Go 1.27+:

```sh
go install github.com/alessio-palumbo/lifx-onboard/cmd/lifx-onboard@latest   # CLI (Linux, Windows)
go get github.com/alessio-palumbo/lifx-onboard                               # library
```

## Usage

Reset the light so it shows up as a `LIFX …` WiFi network, then:

```sh
lifx-onboard ssid 8274eb --home-ssid MyNetwork
```

`8274eb` is the end of the light's serial (also the end of its setup
network's name). The full serial `d073d58274eb` or the full network name
`"LIFX Candle Color 8274eb"` work too.

The WiFi password is read from `LIFX_ONBOARD_PASSWORD`, or asked for
interactively (`--password-stdin` reads it from a pipe). For a network
without a password use `--security open`.

Other commands:

```sh
lifx-onboard bulk 8274eb 826a68 --home-ssid MyNetwork   # several lights
lifx-onboard bulk --home-ssid MyNetwork                 # every light in setup mode nearby
lifx-onboard scan                                       # list lights in setup mode
lifx-onboard <command> -h                               # all options
```

Good to know:

- Your computer briefly leaves its WiFi while a light is being set up, then
  returns to the network it was on — even if that's a different one from
  the light's (e.g. you're on `MyNetwork`, the lights go on `MyNetwork_IoT`).
  Use `--rejoin-ssid` to choose another.
- With `bulk` and a list of serials, only those lights are touched — handy
  when other people's lights are in setup mode nearby.
- `--json` prints machine-readable progress; the exit code says which step
  failed (`lifx-onboard -h`).

## macOS setup

macOS only shows WiFi network names to apps it launched itself and that
you've allowed to use Location Services, so on macOS lifx-onboard runs from
its app bundle. Move `LifxOnboard.app` from the release zip to
`/Applications` and link the command onto your `PATH`:

```sh
ln -s /Applications/LifxOnboard.app/Contents/MacOS/lifx-onboard /usr/local/bin/lifx-onboard
```

To build the bundle from source instead: `scripts/bundle.sh` (creates
`build/LifxOnboard.app`; `ARCHS="arm64 amd64"` for a universal build).

You can still run it from your terminal as usual — it starts itself through
the app behind the scenes. On first use, allow **LifxOnboard** when macOS
asks for Location access (or enable it in System Settings → Privacy &
Security → Location Services).

### Troubleshooting

- **"scan results are redacted"** — Location access is missing, or the
  binary isn't running from the app bundle.
- **`no route to host` while connecting to the light** — macOS blocked the
  connection. Run from the app bundle, or as a fallback from Terminal.app
  or with `sudo`.
- **The light isn't found** — make sure it's in setup mode (it shows up in
  the WiFi menu as `LIFX …`); it can take a few seconds after a reset.

## Linux

Requires NetworkManager (`nmcli`), the default on most desktop distributions
and on Raspberry Pi OS Bookworm and later. No root needed.

## Windows

Uses the native Windows WiFi API, no extra tools. On Windows 11 24H2 and
later, scanning needs Location access: Settings → Privacy & security →
Location → turn on Location services and "Let desktop apps access your
location". Allow the Windows Firewall prompt on first run so the light can
be found on your network afterwards.

## Using the library

```go
ctrl, _ := controller.New() // github.com/alessio-palumbo/lifxlan-go/pkg/controller
defer ctrl.Close()

res, err := onboard.OnboardBySSID(ctx, onboard.OnboardBySSIDOptions{
    Options: onboard.Options{
        SSID:          "MyNetwork",
        Password:      "secret",
        Sender:        ctrl, // used to confirm the light came online
        VerifyTimeout: onboard.DefaultVerifyTimeout,
        Events:        events, // optional: chan onboard.Event for progress
    },
    BulbSSID: "8274eb", // setup network name, serial, or its last 6 hex chars
})
if err != nil {
    log.Fatalf("failed at %s: %v", res.Phase, err)
}
```

`BulkOnboard` sets up several lights (`BulkOptions.Targets` limits it to
specific serials), and `Onboard` scans and sets up the first one it finds.
See [`examples/onboard_by_ssid`](examples/onboard_by_ssid) for a runnable
example.

Any LAN client that can list devices works for confirmation:

```go
type LANSender interface {
    GetDevices() []device.Device
}
```

[lifxlan-go](https://github.com/alessio-palumbo/lifxlan-go)'s `Controller`
satisfies it as-is.

**macOS apps** using the library need what the CLI's bundle has (see
`scripts/bundle.sh` and `scripts/entitlements.plist`):

- `NSLocationWhenInUseUsageDescription` and `NSLocalNetworkUsageDescription`
  in `Info.plist`;
- the `com.apple.security.personal-information.location` entitlement when
  signed with the hardened runtime (required for notarization) — without it
  scans stay redacted even after the user allows Location;
- a build with `-tags corewlan`, calling `onboard.RequestMacOSLocationAccess()`
  at startup.

Sandboxed apps also need the `com.apple.security.network.client` and
`com.apple.security.network.server` entitlements.

## Protocol

Onboarding uses one message that isn't in the official LIFX LAN protocol
docs: "set access point" (type 305 / `0x131`). Its 98-byte payload —
interface, SSID, password, security mode — is documented publicly by third
parties, e.g. [lifxjs](https://github.com/magicmonkey/lifxjs/blob/master/Protocol.md)
and [lifx-hacks](https://github.com/tserong/lifx-hacks/blob/master/onboard.py),
and is implemented here in `internal/wire/`.

## License

MIT
