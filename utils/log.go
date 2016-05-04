package utils

import "fmt"

// LogLevel of quic-go
type LogLevel uint8

const (
	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug LogLevel = iota
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelNothing disables
	LogLevelNothing
)

var logLevel = LogLevelNothing

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		fmt.Printf(format+"\n", args...)
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel <= LogLevelInfo {
		fmt.Printf(format+"\n", args...)
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel <= LogLevelError {
		fmt.Printf(format+"\n", args...)
	}
}
