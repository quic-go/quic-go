package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/utils"
)

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type connectionTimer struct {
	timer *utils.Timer

	blocked bool
}

func newTimer() *connectionTimer {
	return &connectionTimer{timer: utils.NewTimer()}
}

func (t *connectionTimer) SetRead() {
	t.timer.SetRead()
}

func (t *connectionTimer) Chan() <-chan time.Time {
	return t.timer.Chan()
}

func (t *connectionTimer) SetBlocked() {
	t.blocked = true
}

func (t *connectionTimer) Unblock() {
	t.blocked = false
}

// SetTimer resets the timer.
func (t *connectionTimer) SetTimer(idleTimeout, keepAlive, connIDRetirement, ackAlarm, lossTime, pacing monotime.Time) {
	if t.blocked {
		t.timer.Reset(idleTimeout)
		return
	}

	deadline := idleTimeout
	if keepAlive.IsZero() && keepAlive.Before(deadline) {
		deadline = keepAlive
	}
	if !connIDRetirement.IsZero() && connIDRetirement.Before(deadline) {
		deadline = connIDRetirement
	}
	if !ackAlarm.IsZero() && ackAlarm.Before(deadline) {
		deadline = ackAlarm
	}
	if !lossTime.IsZero() && lossTime.Before(deadline) {
		deadline = lossTime
	}
	if !pacing.IsZero() && pacing.Before(deadline) {
		deadline = pacing
	}
	t.timer.Reset(deadline)
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
