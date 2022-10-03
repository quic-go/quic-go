package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

type timerMode uint8

const (
	timerModeHandshakeIdleTimeout timerMode = 1 + iota
	timerModeIdleTimeout
	timerModeKeepAlive
	timerModeAckAlarm
	timerModeLossDetection
	timerModePacing
)

type timer struct {
	timer    utils.Timer
	lastMode timerMode
}

func newTimer() *timer {
	return &timer{
		timer: *utils.NewTimer(),
	}
}

func (t *timer) Chan() <-chan time.Time { return t.timer.Chan() }
func (t *timer) SetRead()               { t.timer.SetRead() }
func (t *timer) Stop()                  { t.timer.Stop() }

// MaybeReset (re-) sets the timer.
// If the timer was already set in the same mode to the same deadline, it is not reset.
// This prevents busy-looping when we're not able to act upon firing of the timer for any reason.
// Possible cases where this might happen include:
// * the send queue is backed up, which prevents us from sending any new packets
// * we have reached the maximum number of outstanding packets that we're willing to keep track of
func (t *timer) MaybeReset(m timerMode, d time.Time) {
	if m == t.lastMode && t.timer.Deadline() == d {
		return
	}
	t.lastMode = m
	t.timer.Reset(d)
}
