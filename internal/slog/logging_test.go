package logging

import (
	"bytes"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/internal/synctest"

	"github.com/stretchr/testify/require"
)

func TestLogger(t *testing.T) {
	const (
		topInfo   = `level=INFO msg="top-level info"`
		topDebug  = `level=DEBUG msg="top-level debug"`
		topError  = `level=ERROR msg="top-level error"`
		ackInfo   = `level=INFO component=ackhandler msg="ackhandler info"`
		ackDebug  = `level=DEBUG component=ackhandler msg="ackhandler debug"`
		ackError  = `level=ERROR component=ackhandler msg="ackhandler error"`
		congInfo  = `level=INFO component=congestion msg="congestion info"`
		congDebug = `level=DEBUG component=congestion msg="congestion debug"`
		congError = `level=ERROR component=congestion msg="congestion error"`
	)

	testCases := []struct {
		name     string
		env      string
		expected []string
	}{
		{
			name:     "no env set",
			env:      "",
			expected: nil,
		},
		{
			name:     "info level",
			env:      "info",
			expected: []string{topInfo, topError, ackInfo, ackError, congInfo, congError},
		},
		{
			name:     "debug level",
			env:      "debug",
			expected: []string{topInfo, topDebug, topError, ackInfo, ackDebug, ackError, congInfo, congDebug, congError},
		},
		{
			name:     "error level",
			env:      "error",
			expected: []string{topError, ackError, congError},
		},
		{
			name:     "top-level debug, ackhandler error only",
			env:      "debug,ackhandler=error",
			expected: []string{topInfo, topDebug, topError, ackError, congInfo, congDebug, congError},
		},
		{
			name:     "top-level error, ackhandler debug",
			env:      "error,ackhandler=debug",
			expected: []string{topError, ackInfo, ackDebug, ackError, congError},
		},
		{
			name:     "different levels for each component",
			env:      "info,ackhandler=debug,congestion=error",
			expected: []string{topInfo, topError, ackInfo, ackDebug, ackError, congError},
		},
		{
			name:     "no top-level, only components specified",
			env:      "ackhandler=info,congestion=debug",
			expected: []string{ackInfo, ackError, congInfo, congDebug, congError},
		},
		{
			name:     "none disables all logging",
			env:      "none",
			expected: nil,
		},
		{
			name:     "top-level debug, ackhandler none",
			env:      "debug,ackhandler=none",
			expected: []string{topInfo, topDebug, topError, congInfo, congDebug, congError},
		},
		{
			name:     "top-level info, all components none",
			env:      "info,ackhandler=none,congestion=none",
			expected: []string{topInfo, topError},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				t.Setenv("QUIC_GO_LOG_LEVEL", tc.env)
				b := &bytes.Buffer{}
				logger := NewLogger(b)

				logger.Info("top-level info")
				logger.Debug("top-level debug")
				logger.Error("top-level error")

				ackLogger := logger.With(ComponentKey, "ackhandler")
				ackLogger.Info("ackhandler info")
				ackLogger.Debug("ackhandler debug")
				ackLogger.Error("ackhandler error")

				congLogger := logger.With(ComponentKey, "congestion")
				congLogger.Info("congestion info")
				congLogger.Debug("congestion debug")
				congLogger.Error("congestion error")

				var suffixes []string
				if s := strings.TrimSuffix(b.String(), "\n"); s != "" {
					for line := range strings.SplitSeq(s, "\n") {
						// Strip the "time=..." prefix, keep everything after the first space
						require.Equal(t, line[:5], "time=")
						if idx := strings.Index(line, " "); idx != -1 {
							suffixes = append(suffixes, line[idx+1:])
						}
					}
				}
				require.Equal(t, tc.expected, suffixes)
			})
		})
	}
}
