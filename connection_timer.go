package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

var deadlineSendImmediately = time.Time{}.Add(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type connectionTimer struct {
	timer  *utils.Timer
	last   time.Time
	tracer *logging.ConnectionTracer
}

func newTimer(tracer *logging.ConnectionTracer) *connectionTimer {
	return &connectionTimer{
		timer:  utils.NewTimer(),
		tracer: tracer,
	}
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
// It makes sure that the deadline is strictly increasing.
// This prevents busy-looping in cases where the timer fires, but we can't actually send out a packet.
// This doesn't apply to the pacing deadline, which can be set multiple times to deadlineSendImmediately.
func (t *connectionTimer) SetTimer(idleTimeoutOrKeepAlive, ackAlarm, lossTime, pacing time.Time) {
	typ := logging.ConnectionTimerIdleTimeoutOrKeepAlive
	deadline := idleTimeoutOrKeepAlive
	if !ackAlarm.IsZero() && ackAlarm.Before(deadline) && ackAlarm.After(t.last) {
		deadline = ackAlarm
		typ = logging.ConnectionTimerAckAlarm
	}
	if !lossTime.IsZero() && lossTime.Before(deadline) && lossTime.After(t.last) {
		deadline = lossTime
		typ = logging.ConnectionTimerLossTime
	}
	if !pacing.IsZero() && pacing.Before(deadline) {
		deadline = pacing
		typ = logging.ConnectionTimerPacing
	}
	if deadline == deadlineSendImmediately {
		panic("connection BUG: deadlineSendImmediately should not be set as a timer deadline")
	}
	duration, wasReset := t.timer.Reset(deadline)
	if t.tracer != nil && t.tracer.ConnectionTimerReset != nil {
		if !wasReset {
			duration = time.Until(deadline)
		}
		t.tracer.ConnectionTimerReset(typ, duration, wasReset)
	}
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
