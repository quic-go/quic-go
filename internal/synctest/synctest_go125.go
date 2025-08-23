//go:build go1.25

package synctest

import (
	"testing"
	"testing/synctest"
)

func Test(t *testing.T, f func(t *testing.T)) {
	synctest.Test(t, f)
}

func Wait() {
	synctest.Wait()
}
