package onboard

import (
	"io"
	"log/slog"
)

// discardLogger is used when the caller does not supply a Logger.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// logger returns l if non-nil, otherwise a no-op slog.Logger.
func logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return discardLogger
	}
	return l
}

// emit safely sends e on ch. If ch is nil or full the event is dropped — the
// library never blocks on a slow event consumer.
func emit(ch chan<- Event, e Event) {
	if ch == nil {
		return
	}
	select {
	case ch <- e:
	default:
	}
}
