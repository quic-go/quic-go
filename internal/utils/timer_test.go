package utils

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/synctest"

	"github.com/stretchr/testify/require"
)

func TestTimerResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timer := NewTimer()

		select {
		case <-timer.Chan():
			t.Fatal("timer should not have fired")
		default:
		}

		start := monotime.Now()

		// timer fires immediately for a deadline in the past
		timer.Reset(monotime.Now().Add(-time.Second))
		select {
		case <-timer.Chan():
			require.Zero(t, monotime.Since(start))
			timer.SetRead()
		case <-time.After(time.Hour): // this can be replaced with a default once we drop support for Go 1.24
			t.Fatal("timer should have fired")
		}

		// timer reset without getting read
		for range 10 {
			time.Sleep(time.Second)
			timer.Reset(monotime.Now().Add(time.Hour))
		}
		select {
		case <-timer.Chan():
			require.Equal(t, monotime.Since(start), time.Hour+10*time.Second)
			timer.SetRead()
		case <-time.After(2 * time.Hour):
			t.Fatal("timer should have fired")
		}

		const d = 10 * time.Minute
		for i := range 10 {
			start := monotime.Now()
			timer.Reset(monotime.Now().Add(d))
			if i%2 == 0 {
				select {
				case <-timer.Chan():
					require.Equal(t, monotime.Since(start), d)
				case <-time.After(2 * d):
					t.Fatal("timer should have fired")
				}
				timer.SetRead()
			} else {
				time.Sleep(2 * d)
			}
		}

		select {
		case <-timer.Chan():
		default:
			t.Fatal("timer should have fired")
		}
	})
}

func TestTimerClearDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timer := NewTimer()
		timer.Reset(0)

		// we don't expect the timer to be set for a zero deadline
		select {
		case <-timer.Chan():
			t.Fatal("timer should not have fired")
		case <-time.After(time.Hour):
		}
	})
}

func TestTimerSameDeadline(t *testing.T) {
	t.Run("timer read in between", func(t *testing.T) {
		deadline := monotime.Now().Add(-time.Millisecond)
		timer := NewTimer()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		default:
			t.Fatal("timer should have fired")
		}

		timer.SetRead()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		default:
			t.Fatal("timer should have fired")
		}
	})

	t.Run("timer not read in between", func(t *testing.T) {
		deadline := monotime.Now().Add(-time.Millisecond)
		timer := NewTimer()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		default:
			t.Fatal("timer should have fired")
		}

		select {
		case <-timer.Chan():
			t.Fatal("timer should not have fired again")
		default:
		}
	})
}

func TestTimerStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timer := NewTimer()
		timer.Reset(monotime.Now().Add(time.Second))
		timer.Stop()

		select {
		case <-timer.Chan():
			t.Fatal("timer should not have fired")
		case <-time.After(time.Hour):
		}
	})
}
