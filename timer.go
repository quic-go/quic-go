package quic

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/logging"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

var deadlineSendImmediately = time.Time{}.Add(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type timer struct {
	timer *utils.Timer
	last  time.Time

	tracer logging.ConnectionTracer
}

func newTimer(tracer logging.ConnectionTracer) *timer {
	return &timer{
		timer:  utils.NewTimer(),
		tracer: tracer,
	}
}

func (t *timer) SetRead() {
	if deadline := t.timer.Deadline(); deadline != deadlineSendImmediately {
		t.last = deadline
	}
	t.timer.SetRead()
}

func (t *timer) Chan() <-chan time.Time {
	return t.timer.Chan()
}

// SetTimer resets the timer.
// It makes sure that the deadline is strictly increasing.
// This prevents busy-looping in cases where the timer fires, but we can't actually send out a packet.
// This doesn't apply to the pacing deadline, which can be set multiple times to deadlineSendImmediately.
func (t *timer) SetTimer(idleTimeoutOrKeepAlive, ackAlarm, lossTime, pacing time.Time) {
	deadline := idleTimeoutOrKeepAlive
	reason := "idle_timeout_or_keep_alive"
	if !ackAlarm.IsZero() && ackAlarm.Before(deadline) && ackAlarm.After(t.last) {
		deadline = ackAlarm
		reason = "ack_alarm"
	}
	if !lossTime.IsZero() && lossTime.Before(deadline) && lossTime.After(t.last) {
		deadline = lossTime
		reason = "loss_time"
	}
	if !pacing.IsZero() && pacing.Before(deadline) {
		deadline = pacing
		reason = "pacing"
	}

	if t.tracer != nil {
		t.tracer.Debug("timer_set", fmt.Sprintf("reason: %s, deadline: %s, in: %s", reason, deadline, time.Until(deadline)))
	}

	t.timer.Reset(deadline)
}

func (t *timer) Stop() {
	t.timer.Stop()
}
