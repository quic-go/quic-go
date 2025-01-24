package quic

import (
	"fmt"
	"strings"
	"sync/atomic"
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
		if typ == logging.ConnectionTimerPacing {
			countPacingTimerReset(duration, wasReset)
		} else {
			t.tracer.ConnectionTimerReset(typ, duration, wasReset)
		}
	}
}

var (
	positiveBelow100mus, positiveBelow200mus, positiveBelow500mus, positiveBelow1ms, positiveBelow2ms, positiveBelow5ms, positiveBelow10ms, positiveBelow100ms, positiveAbove100ms atomic.Uint64
	negativeBelow100mus, negativeBelow200mus, negativeBelow500mus, negativeBelow1ms, negativeBelow2ms, negativeBelow5ms, negativeBelow10ms, negativeBelow100ms, negativeAbove100ms atomic.Uint64
)

func init() {
	go func() {
		for {
			time.Sleep(15 * time.Second)
			fmt.Printf("\nPacing Timer Reset Statistics %s:\n", time.Now().Format(time.RFC3339))
			fmt.Printf("%-20s | %-12s | %-12s\n", "Duration", "Positive", "Negative")
			fmt.Printf("%-20s-+-%-12s-+-%-12s\n", strings.Repeat("-", 20), strings.Repeat("-", 12), strings.Repeat("-", 12))
			fmt.Printf("%-20s | %-12d | %-12d\n", "< 100us", positiveBelow100mus.Load(), negativeBelow100mus.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "100us - 200us", positiveBelow200mus.Load(), negativeBelow200mus.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "200us - 500us", positiveBelow500mus.Load(), negativeBelow500mus.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "500us - 1ms", positiveBelow1ms.Load(), negativeBelow1ms.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "1ms - 2ms", positiveBelow2ms.Load(), negativeBelow2ms.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "2ms - 5ms", positiveBelow5ms.Load(), negativeBelow5ms.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "5ms - 10ms", positiveBelow10ms.Load(), negativeBelow10ms.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "10ms - 100ms", positiveBelow100ms.Load(), negativeBelow100ms.Load())
			fmt.Printf("%-20s | %-12d | %-12d\n", "> 100ms", positiveAbove100ms.Load(), negativeAbove100ms.Load())
		}
	}()
}

func countPacingTimerReset(duration time.Duration, _ bool) {
	if duration > 0 {
		switch {
		case duration < 100*time.Microsecond:
			positiveBelow100mus.Add(1)
		case duration < 200*time.Microsecond:
			positiveBelow200mus.Add(1)
		case duration < 500*time.Microsecond:
			positiveBelow500mus.Add(1)
		case duration < 1*time.Millisecond:
			positiveBelow1ms.Add(1)
		case duration < 2*time.Millisecond:
			positiveBelow2ms.Add(1)
		case duration < 5*time.Millisecond:
			positiveBelow5ms.Add(1)
		case duration < 10*time.Millisecond:
			positiveBelow10ms.Add(1)
		case duration < 100*time.Millisecond:
			positiveBelow100ms.Add(1)
		default:
			positiveAbove100ms.Add(1)
		}
	} else {
		duration = -duration
		switch {
		case duration < 100*time.Microsecond:
			negativeBelow100mus.Add(1)
		case duration < 200*time.Microsecond:
			negativeBelow200mus.Add(1)
		case duration < 500*time.Microsecond:
			negativeBelow500mus.Add(1)
		case duration < 1*time.Millisecond:
			negativeBelow1ms.Add(1)
		case duration < 2*time.Millisecond:
			negativeBelow2ms.Add(1)
		case duration < 5*time.Millisecond:
			negativeBelow5ms.Add(1)
		case duration < 10*time.Millisecond:
			negativeBelow10ms.Add(1)
		case duration < 100*time.Millisecond:
			negativeBelow100ms.Add(1)
		default:
			negativeAbove100ms.Add(1)
		}
	}
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
