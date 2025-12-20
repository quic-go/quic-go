package slog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LogLevelNone is a log level that disables all logging.
const LogLevelNone slog.Level = slog.LevelError + 1

// ComponentKey is the slog attribute key used to identify the component.
const ComponentKey = "component"

type logLevels struct {
	Level      slog.Level            // top-level log level
	Components map[string]slog.Level // nil if no component-specific levels
}

// parseLogLevel parses a log level string into a slog.Level.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "none":
		return LogLevelNone, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level: %s", s)
	}
}

// parseLogConfig parses the QUIC_GO_LOG_LEVEL environment variable format.
// Returns a logLevels struct with top-level (LogLevelNone if not set) and component levels
// (nil map if no component-specific levels are defined).
//
// Valid formats:
//   - "info"                                    - top-level only
//   - "debug,ackhandler=info"                   - top-level + component
//   - "debug,ackhandler=info,flowcontrol=error" - top-level + multiple components
//   - "ackhandler=info,flowcontrol=error"       - components only (no top-level)
func parseLogConfig(config string) (logLevels, error) {
	levels := logLevels{Level: LogLevelNone}

	if config == "" {
		return levels, nil
	}

	for part := range strings.SplitSeq(config, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "=") {
			// Component-specific level: e.g. "component=info"
			kv := strings.SplitN(part, "=", 2)
			component := strings.TrimSpace(kv[0])
			levelStr := strings.TrimSpace(kv[1])
			level, err := parseLogLevel(levelStr)
			if err != nil {
				return logLevels{}, fmt.Errorf("component %s: %w", component, err)
			}
			if levels.Components == nil {
				levels.Components = make(map[string]slog.Level)
			}
			levels.Components[component] = level
		} else {
			// top-level: e.g. "debug"
			level, err := parseLogLevel(part)
			if err != nil {
				return logLevels{}, err
			}
			levels.Level = level
		}
	}

	return levels, nil
}

type levelFilterHandler struct {
	Component string // component attribute value for this handler, empty for top-level

	slog.Handler
	Levels logLevels
}

var _ slog.Handler = &levelFilterHandler{}

func (h *levelFilterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.Levels.Components != nil {
		if minLevel, ok := h.Levels.Components[h.Component]; ok {
			return level >= minLevel
		}
	}
	// Fall back to top-level
	return level >= h.Levels.Level
}

func (h *levelFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.Handler.Handle(ctx, r)
}

func (h *levelFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newComponent := h.Component
	for _, attr := range attrs {
		if attr.Key == ComponentKey {
			newComponent = attr.Value.String()
			break
		}
	}
	return &levelFilterHandler{
		Handler:   h.Handler.WithAttrs(attrs),
		Levels:    h.Levels,
		Component: newComponent,
	}
}

func (h *levelFilterHandler) WithGroup(name string) slog.Handler {
	return &levelFilterHandler{
		Handler:   h.Handler.WithGroup(name),
		Levels:    h.Levels,
		Component: h.Component,
	}
}

// msgLastHandler wraps a handler to shift the message to the end.
type msgLastHandler struct {
	slog.Handler
}

var _ slog.Handler = &msgLastHandler{}

func (h *msgLastHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Handler.Enabled(ctx, level)
}

func (h *msgLastHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String(slog.MessageKey, r.Message))
	r.Message = ""
	return h.Handler.Handle(ctx, r)
}

func (h *msgLastHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &msgLastHandler{h.Handler.WithAttrs(attrs)}
}

func (h *msgLastHandler) WithGroup(name string) slog.Handler {
	return &msgLastHandler{h.Handler.WithGroup(name)}
}

func newMsgLastTextHandler(w io.Writer, levels logLevels) slog.Handler {
	return &msgLastHandler{
		Handler: &levelFilterHandler{
			Handler: slog.NewTextHandler(w, &slog.HandlerOptions{
				Level: slog.LevelDebug, // allow all levels through, filtering is done by levelFilterHandler
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if len(groups) == 0 && a.Key == slog.MessageKey && a.Value.String() == "" {
						return slog.Attr{}
					}
					return a
				},
			}),
			Levels: levels,
		},
	}
}

func NewLogger(w io.Writer) *slog.Logger {
	logConfig := os.Getenv("QUIC_GO_LOG_LEVEL")
	levels, err := parseLogConfig(logConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse QUIC_GO_LOG_LEVEL: %v\n", err)
		os.Exit(1)
	}

	return slog.New(newMsgLastTextHandler(w, levels))
}
