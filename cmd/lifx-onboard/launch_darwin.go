//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// macOS only lets a process see WiFi SSIDs/BSSIDs (Location Services) — and
// gives it its own Local Network rule — when LaunchServices launched it as
// an app. A binary exec'd from a shell, even from inside the .app bundle, is
// attributed to the terminal and gets redacted scan results.
//
// So when the CLI runs from inside LifxOnboard.app and wasn't launched by
// LaunchServices, it re-runs itself with `open -W -n`, relaying stdio
// through FIFOs and the environment, working directory, pid and exit code
// through a private state directory.

const (
	envLaunchState = "LIFX_ONBOARD_LAUNCH_STATE"
	envNoRelaunch  = "LIFX_ONBOARD_NO_RELAUNCH"

	stateEnv    = "env"
	stateCwd    = "cwd"
	statePid    = "pid"
	stateExit   = "exit"
	stateStdin  = "stdin"
	stateStdout = "stdout"
	stateStderr = "stderr"
)

// childStateDir is set when this process is the LaunchServices-launched
// child; reportExit writes the exit code there for the parent.
var childStateDir string

// relaunchViaLaunchServices either prepares this process as the launched
// child (returns ok=false so main carries on), or relaunches through
// LaunchServices and returns the child's exit code with ok=true.
func relaunchViaLaunchServices() (code int, ok bool) {
	if dir := os.Getenv(envLaunchState); dir != "" {
		enterChild(dir)
		return 0, false
	}
	if os.Getenv(envNoRelaunch) != "" || os.Geteuid() == 0 {
		return 0, false
	}
	bundle, ok := bundlePath()
	if !ok {
		return 0, false
	}
	code, err := runViaOpen(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lifx-onboard: relaunch via LaunchServices failed (%v), running in-process\n", err)
		return 0, false
	}
	return code, true
}

// bundlePath returns the enclosing .app when the executable lives in one.
func bundlePath() (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	i := strings.Index(exe, ".app/Contents/MacOS/")
	if i < 0 {
		return "", false
	}
	return exe[:i+len(".app")], true
}

func runViaOpen(bundle string) (int, error) {
	dir, err := os.MkdirTemp("", "lifx-onboard-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	path := func(name string) string { return filepath.Join(dir, name) }

	// Environment (may hold LIFX_ONBOARD_PASSWORD) goes through a 0600 file
	// rather than `open --env`, which would expose it in `ps`.
	if err := os.WriteFile(path(stateEnv), []byte(strings.Join(os.Environ(), "\x00")), 0o600); err != nil {
		return 0, err
	}
	if cwd, err := os.Getwd(); err == nil {
		_ = os.WriteFile(path(stateCwd), []byte(cwd), 0o600)
	}
	for _, name := range []string{stateStdout, stateStderr} {
		if err := syscall.Mkfifo(path(name), 0o600); err != nil {
			return 0, err
		}
	}

	// A terminal stdin is handed over as the tty device itself so the child
	// can prompt for the password with echo off; otherwise relay via FIFO.
	stdinPath, stdinTTY := ttyPath(os.Stdin)
	if !stdinTTY {
		stdinPath = path(stateStdin)
		if err := syscall.Mkfifo(stdinPath, 0o600); err != nil {
			return 0, err
		}
	}

	args := []string{"-W", "-n", "-g",
		"--env", envLaunchState + "=" + dir,
		"--stdin", stdinPath, "--stdout", path(stateStdout), "--stderr", path(stateStderr),
		bundle, "--args"}
	cmd := exec.Command("open", append(args, os.Args[1:]...)...)
	var openErr bytes.Buffer
	cmd.Stderr = &openErr

	var restoreTTY func()
	if stdinTTY {
		if st, err := term.GetState(int(os.Stdin.Fd())); err == nil {
			restoreTTY = func() { _ = term.Restore(int(os.Stdin.Fd()), st) }
		}
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	copied := make(chan struct{}, 2)
	relay := func(name string, w io.Writer) {
		defer func() { copied <- struct{}{} }()
		f, err := os.Open(path(name)) // blocks until the child opens it
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = io.Copy(w, f)
	}
	go relay(stateStdout, os.Stdout)
	go relay(stateStderr, os.Stderr)
	if !stdinTTY {
		go func() {
			f, err := os.OpenFile(stdinPath, os.O_WRONLY, 0)
			if err != nil {
				return
			}
			_, _ = io.Copy(f, os.Stdin)
			f.Close()
		}()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
wait:
	for {
		select {
		case s := <-sigs:
			if pid := readInt(path(statePid)); pid > 0 {
				_ = syscall.Kill(pid, s.(syscall.Signal))
			}
		case waitErr = <-done:
			break wait
		}
	}

	// If the child never opened a FIFO (launch failure), opening the write
	// end ourselves unblocks the relay goroutine, which then sees EOF.
	for _, name := range []string{stateStdout, stateStderr} {
		if f, err := os.OpenFile(path(name), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	}
	for range 2 {
		select {
		case <-copied:
		case <-time.After(2 * time.Second):
		}
	}
	if restoreTTY != nil {
		restoreTTY()
	}

	if b, err := os.ReadFile(path(stateExit)); err == nil {
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if waitErr != nil {
		return 0, fmt.Errorf("%v: %s", waitErr, strings.TrimSpace(openErr.String()))
	}
	if readInt(path(statePid)) > 0 {
		// The child started but died without reporting (crash or signal).
		return exitFailure, nil
	}
	return 0, errors.New("launched app did not start")
}

// enterChild restores the parent's environment and working directory and
// records our pid so the parent can forward signals.
func enterChild(dir string) {
	childStateDir = dir
	if b, err := os.ReadFile(filepath.Join(dir, stateEnv)); err == nil {
		os.Clearenv()
		for _, kv := range strings.Split(string(b), "\x00") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				_ = os.Setenv(k, v)
			}
		}
		_ = os.Remove(filepath.Join(dir, stateEnv))
	}
	_ = os.Setenv(envLaunchState, dir)
	if b, err := os.ReadFile(filepath.Join(dir, stateCwd)); err == nil {
		_ = os.Chdir(string(b))
	}
	_ = os.WriteFile(filepath.Join(dir, statePid), []byte(strconv.Itoa(os.Getpid())), 0o600)
}

// reportExit hands the exit code back to the parent when running as the
// launched child. No-op otherwise.
func reportExit(code int) {
	if childStateDir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(childStateDir, stateExit), []byte(strconv.Itoa(code)), 0o600)
}

// ttyPath returns the device path of f when it is a terminal.
func ttyPath(f *os.File) (string, bool) {
	if !term.IsTerminal(int(f.Fd())) {
		return "", false
	}
	cmd := exec.Command("tty")
	cmd.Stdin = f
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	p := strings.TrimSpace(string(out))
	return p, strings.HasPrefix(p, "/dev/")
}

func readInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
