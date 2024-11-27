package logging

// The following code implements slog.Handler.
import (
	"context"
	"log/slog"
)

// BlackholeHandler implements slog.Handler and discards all log messages.
type BlackholeHandler struct{}

func (h BlackholeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return false
}

func (h BlackholeHandler) Handle(ctx context.Context, record slog.Record) error {
	return nil
}

func (h BlackholeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h BlackholeHandler) WithGroup(name string) slog.Handler {
	return h
}
