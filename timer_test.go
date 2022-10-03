package quic

import (
	"time"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("Timer", func() {
	It("doesn't reset the timer for the same time multiple times", func() {
		t := newTimer()
		d := time.Now()
		t.MaybeReset(timerModePacing, d)
		select {
		case <-t.Chan():
			return
		case <-time.After(100 * time.Millisecond):
			Fail("timer didn't fire")
		}

		// reset in the same mode for the same deadline, won't actually reset the timer
		t.MaybeReset(timerModePacing, d)
		select {
		case <-t.Chan():
			Fail("timer fired")
		case <-time.After(50 * time.Millisecond):
		}

		// reset in a different mode, this will actually reset the timer
		t.MaybeReset(timerModeLossDetection, d)
		select {
		case <-t.Chan():
			return
		case <-time.After(100 * time.Millisecond):
			Fail("timer didn't fire")
		}
	})
})
