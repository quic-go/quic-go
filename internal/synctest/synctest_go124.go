//go:build go1.24 && !go1.25

package synctest

import (
	"testing"
	"testing/synctest"
)

func Test(t *testing.T, f func(t *testing.T)) {
	synctest.Run(func() {
		f(t)
	})
}

func Wait() {
	//nolint:govet // the CI configuration sets the GOEXPERIMENT=synctest flag
	synctest.Wait()
}
