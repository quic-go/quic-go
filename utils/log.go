package utils

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// LogLevel of quic-go
type LogLevel uint8

const (
	logEnv = "QUIC_GO_LOG_LEVEL"

	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug LogLevel = iota
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelNothing disables
	LogLevelNothing
)

var (
	logLevel             = LogLevelNothing
	out        io.Writer = os.Stdout
	timeFormat           = "15:04:05.000"

	mutex sync.Mutex
)

// SetLogWriter sets the log writer.
func SetLogWriter(w io.Writer) {
	out = w
}

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// SetLogTimeFormat sets the format of the timestamp
// an empty string disables the logging of timestamps
func SetLogTimeFormat(format string) {
	timeFormat = format
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		mutex.Lock()
		logTimestamp()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel <= LogLevelInfo {
		mutex.Lock()
		logTimestamp()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel <= LogLevelError {
		mutex.Lock()
		logTimestamp()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

func logTimestamp() {
	if len(timeFormat) > 0 {
		fmt.Fprintf(out, time.Now().Format(timeFormat)+" ")
	}
}

// Debug returns true if the log level is LogLevelDebug
func Debug() bool {
	return logLevel == LogLevelDebug
}

func init() {
	readLoggingEnv()
}

func readLoggingEnv() {
	env := os.Getenv(logEnv)
	if env == "" {
		return
	}
	level, err := strconv.Atoi(env)
	if err != nil {
		return
	}
	logLevel = LogLevel(level)
}
