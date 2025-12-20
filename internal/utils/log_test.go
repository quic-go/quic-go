package utils

import (
	"bytes"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogLevelNothing(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	DefaultLogger.SetLogLevel(LogLevelNothing)
	DefaultLogger.Debugf("debug")
	DefaultLogger.Infof("info")
	DefaultLogger.Errorf("err")
	require.Empty(t, b.String())
}

func TestLogLevelError(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	DefaultLogger.SetLogLevel(LogLevelError)
	DefaultLogger.Debugf("debug")
	DefaultLogger.Infof("info")
	DefaultLogger.Errorf("err")
	require.Contains(t, b.String(), "err\n")
	require.NotContains(t, b.String(), "info")
	require.NotContains(t, b.String(), "debug")
}

func TestLogLevelInfo(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	DefaultLogger.SetLogLevel(LogLevelInfo)
	DefaultLogger.Debugf("debug")
	DefaultLogger.Infof("info")
	DefaultLogger.Errorf("err")
	require.Contains(t, b.String(), "err\n")
	require.Contains(t, b.String(), "info\n")
	require.NotContains(t, b.String(), "debug")
}

func TestLogLevelDebug(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	require.False(t, DefaultLogger.Debug())
	DefaultLogger.SetLogLevel(LogLevelDebug)
	require.True(t, DefaultLogger.Debug())
	DefaultLogger.Debugf("debug")
	DefaultLogger.Infof("info")
	DefaultLogger.Errorf("err")
	require.Contains(t, b.String(), "err\n")
	require.Contains(t, b.String(), "info\n")
	require.Contains(t, b.String(), "debug\n")
}

func TestNoTimestampWithEmptyFormat(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	DefaultLogger.SetLogLevel(LogLevelDebug)
	DefaultLogger.SetLogTimeFormat("")
	DefaultLogger.Debugf("debug")
	require.Equal(t, "debug\n", b.String())
}

func TestAddTimestamp(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	format := "Jan 2, 2006"
	DefaultLogger.SetLogTimeFormat(format)
	DefaultLogger.SetLogLevel(LogLevelInfo)
	DefaultLogger.Infof("info")
	timestamp := b.String()[:b.Len()-6]
	parsedTime, err := time.ParseInLocation(format, timestamp, time.Local)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), parsedTime, 25*time.Hour)
}

func TestLogAddPrefixes(t *testing.T) {
	b := &bytes.Buffer{}
	log.SetOutput(b)
	defer log.SetOutput(os.Stdout)
	defer DefaultLogger.SetLogLevel(LogLevelNothing)

	DefaultLogger.SetLogLevel(LogLevelDebug)

	// single prefix
	prefixLogger := DefaultLogger.WithPrefix("prefix")
	prefixLogger.Debugf("debug1")
	require.Contains(t, b.String(), "prefix")
	require.Contains(t, b.String(), "debug1")

	// multiple prefixes
	b.Reset()
	prefixLogger1 := DefaultLogger.WithPrefix("prefix1")
	prefixLogger2 := prefixLogger1.WithPrefix("prefix2")
	prefixLogger2.Debugf("debug2")
	require.Contains(t, b.String(), "prefix1")
	require.Contains(t, b.String(), "prefix2")
	require.Contains(t, b.String(), "debug2")
}

func TestLogLevelFromEnv(t *testing.T) {
	testCases := []struct {
		envValue string
		expected LogLevel
	}{
		{"DEBUG", LogLevelDebug},
		{"debug", LogLevelDebug},
		{"INFO", LogLevelInfo},
		{"ERROR", LogLevelError},
	}

	for _, tc := range testCases {
		t.Setenv(logEnv, tc.envValue)
		require.Equal(t, tc.expected, readLoggingEnv())
	}

	// invalid values
	t.Setenv(logEnv, "")
	require.Equal(t, LogLevelNothing, readLoggingEnv())
	t.Setenv(logEnv, "asdf")
	require.Equal(t, LogLevelNothing, readLoggingEnv())
}
