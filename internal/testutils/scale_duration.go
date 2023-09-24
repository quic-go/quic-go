package testutils

import (
	"log"
	"os"
	"strconv"
	"time"
)

const TimescaleFactorEnv = "TIMESCALE_FACTOR"

// ScaleDuration multiplies a given duration with a constant factor read from the TIMESCALE_FACTOR environment variable.
// This is useful when testing timing on CI, where  timing is a lot less precise.
func ScaleDuration(t time.Duration) time.Duration {
	scaleFactor := int64(1)
	f, err := strconv.ParseInt(os.Getenv(TimescaleFactorEnv), 10, 64)
	if err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		log.Fatal("duration scaling set to 0")
	}
	return time.Duration(scaleFactor) * t
}
