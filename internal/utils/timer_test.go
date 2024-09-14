package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testDuration = 10 * time.Millisecond

func TestTimerCreateAndReset(t *testing.T) {
	timer := NewTimer()
	select {
	case <-timer.Chan():
		t.Fatal("timer should not have fired")
	default:
	}

	deadline := time.Now().Add(testDuration)
	timer.Reset(deadline)
	require.Equal(t, deadline, timer.Deadline())

	select {
	case <-timer.Chan():
	case <-time.After(2 * testDuration):
		t.Fatal("timer should have fired")
	}

	timer.SetRead()
	timer.Reset(time.Now().Add(testDuration))

	select {
	case <-timer.Chan():
	case <-time.After(2 * testDuration):
		t.Fatal("timer should have fired")
	}
}

func TestTimerMultipleResets(t *testing.T) {
	timer := NewTimer()
	for i := 0; i < 10; i++ {
		timer.Reset(time.Now().Add(testDuration))
		if i%2 == 0 {
			select {
			case <-timer.Chan():
			case <-time.After(2 * testDuration):
				t.Fatal("timer should have fired")
			}
			timer.SetRead()
		} else {
			time.Sleep(testDuration * 2)
		}
	}

	select {
	case <-timer.Chan():
	case <-time.After(2 * testDuration):
		t.Fatal("timer should have fired")
	}
}

func TestTimerResetWithoutExpiration(t *testing.T) {
	timer := NewTimer()
	for i := 0; i < 10; i++ {
		timer.Reset(time.Now().Add(time.Hour))
	}
	timer.Reset(time.Now().Add(testDuration))

	select {
	case <-timer.Chan():
	case <-time.After(2 * testDuration):
		t.Fatal("timer should have fired")
	}
}

func TestTimerPastDeadline(t *testing.T) {
	timer := NewTimer()
	timer.Reset(time.Now().Add(-time.Second))

	select {
	case <-timer.Chan():
	case <-time.After(testDuration):
		t.Fatal("timer should have fired immediately")
	}
}

func TestTimerZeroDeadline(t *testing.T) {
	timer := NewTimer()
	timer.Reset(time.Time{})

	// we don't expect the timer to be set for a zero deadline
	select {
	case <-timer.Chan():
		t.Fatal("timer should not have fired")
	case <-time.After(testDuration):
	}
}

func TestTimerSameDeadline(t *testing.T) {
	t.Run("timer read in between", func(t *testing.T) {
		deadline := time.Now().Add(-time.Millisecond)
		timer := NewTimer()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		case <-time.After(testDuration):
			t.Fatal("timer should have fired")
		}

		timer.SetRead()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		case <-time.After(testDuration):
			t.Fatal("timer should have fired")
		}
	})

	t.Run("timer not read in between", func(t *testing.T) {
		deadline := time.Now().Add(-time.Millisecond)
		timer := NewTimer()
		timer.Reset(deadline)

		select {
		case <-timer.Chan():
		case <-time.After(testDuration):
			t.Fatal("timer should have fired")
		}

		select {
		case <-timer.Chan():
			t.Fatal("timer should not have fired again")
		case <-time.After(testDuration):
		}
	})
}

func TestTimerStopping(t *testing.T) {
	timer := NewTimer()
	timer.Reset(time.Now().Add(testDuration))
	timer.Stop()

	select {
	case <-timer.Chan():
		t.Fatal("timer should not have fired")
	case <-time.After(2 * testDuration):
	}
}
