package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/utils"
)

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type connectionTimer struct {
	timer *utils.Timer
	last  monotime.Time
}

func newTimer() *connectionTimer {
	return &connectionTimer{timer: utils.NewTimer()}
}

func (t *connectionTimer) SetRead() {
	if deadline := t.timer.Deadline(); deadline != deadlineSendImmediately {
		t.last = deadline
	}
	t.timer.SetRead()
}

func (t *connectionTimer) Chan() <-chan time.Time {
	return t.timer.Chan()
}

// SetTimer resets the timer.
// It doesn't reset the timer if the deadline is the same as the last one.
// This prevents busy-looping in cases where the timer fires, but we can't actually send out a packet.
// This doesn't apply to the pacing deadline, which can be set multiple times to deadlineSendImmediately.
func (t *connectionTimer) SetTimer(idleTimeoutOrKeepAlive, connIDRetirement, ackAlarm, lossTime, pacing monotime.Time) {
	deadline := idleTimeoutOrKeepAlive
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
	if !deadline.Equal(deadlineSendImmediately) && deadline.Equal(t.last) {
		return
	}
	t.timer.Reset(deadline)
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
