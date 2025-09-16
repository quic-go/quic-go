package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
)

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type connectionTimer struct {
	timer *time.Timer
	last  monotime.Time
}

func newTimer() *connectionTimer {
	// TODO: think about initializing the timer with a better default value
	return &connectionTimer{timer: time.NewTimer(time.Hour)}
}

func (t *connectionTimer) Chan() <-chan time.Time {
	return t.timer.C
}

// SetTimer resets the timer.
// It makes sure that the deadline is strictly increasing.
// This prevents busy-looping in cases where the timer fires, but we can't actually send out a packet.
// This doesn't apply to the pacing deadline, which can be set multiple times to deadlineSendImmediately.
func (t *connectionTimer) SetTimer(idleTimeoutOrKeepAlive, connIDRetirement, ackAlarm, lossTime, pacing monotime.Time) {
	deadline := idleTimeoutOrKeepAlive
	if !connIDRetirement.IsZero() && connIDRetirement.Before(deadline) && connIDRetirement.After(t.last) {
		deadline = connIDRetirement
	}
	if !ackAlarm.IsZero() && ackAlarm.Before(deadline) && ackAlarm.After(t.last) {
		deadline = ackAlarm
	}
	if !lossTime.IsZero() && lossTime.Before(deadline) && lossTime.After(t.last) {
		deadline = lossTime
	}
	if !pacing.IsZero() && pacing.Before(deadline) {
		deadline = pacing
	}
	t.last = deadline
	t.timer.Reset(monotime.Until(deadline))
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
