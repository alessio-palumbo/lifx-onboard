//go:build !darwin

package main

// relaunchViaLaunchServices is macOS-only; see launch_darwin.go.
func relaunchViaLaunchServices() (code int, ok bool) { return 0, false }

func reportExit(int) {}
