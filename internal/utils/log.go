package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel of quic-go
type LogLevel uint8

const logEnvLvl = "QUIC_GO_LOG_LEVEL"
const logEnvPrefix = "QUIC_GO_LOG_PREFIX"

const (
	// LogLevelNothing disables
	LogLevelNothing LogLevel = iota
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug
)

var (
	logLevel   = LogLevelNothing
	timeFormat = ""
	logPrefix  = ""
)

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// SetLogTimeFormat sets the format of the timestamp
// an empty string disables the logging of timestamps
func SetLogTimeFormat(format string) {
	log.SetFlags(0) // disable timestamp logging done by the log package
	timeFormat = format
}

// SetLogPrefix adds a prefix to each log (after the timestamp)
func SetLogPrefix(prefix string) {
	logPrefix = prefix
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		logMessage(format, args...)
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel >= LogLevelInfo {
		logMessage(format, args...)
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel >= LogLevelError {
		logMessage(format, args...)
	}
}

func logMessage(format string, args ...interface{}) {
	logFormat := ""
	if len(timeFormat) > 0 {
		logFormat += time.Now().Format(timeFormat) + " "
	}
	if len(logPrefix) > 0 {
		logFormat += logPrefix + " "
	}
	log.Printf(logFormat+format, args...)
}

// Debug returns true if the log level is LogLevelDebug
func Debug() bool {
	return logLevel == LogLevelDebug
}

func init() {
	readLoggingEnv()
}

func readLoggingEnv() {
	// Level
	switch os.Getenv(logEnvLvl) {
	case "":
		return
	case "DEBUG":
		logLevel = LogLevelDebug
	case "INFO":
		logLevel = LogLevelInfo
	case "ERROR":
		logLevel = LogLevelError
	default:
		fmt.Fprintln(os.Stderr, "invalid quic-go log level, see https://github.com/lucas-clemente/quic-go/wiki/Logging")
	}
	// Prefix
	SetLogPrefix(os.Getenv(logEnvPrefix))
}
