//go:build !go1.25 && !goexperiment.synctest

package synctest

import (
	"testing"
)

// Test runs the test function without synctest support (fallback for Go <1.25 without GOEXPERIMENT=synctest)
func Test(t *testing.T, f func(t *testing.T)) {
	f(t)
}

// Wait is a no-op when synctest is not available
func Wait() {
	// no-op: synctest not available
}
