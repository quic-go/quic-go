package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (t *connectionTimer) Deadline() time.Time { return t.timer.Deadline() }

func TestConnectionTimerModes(t *testing.T) {
	now := time.Now()

	t.Run("idle timeout", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), time.Time{}, time.Time{}, time.Time{})
		require.Equal(t, now.Add(time.Hour), timer.Deadline())
	})

	t.Run("ACK timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
		require.Equal(t, now.Add(time.Minute), timer.Deadline())
	})

	t.Run("loss timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), now.Add(time.Second), time.Time{})
		require.Equal(t, now.Add(time.Second), timer.Deadline())
	})

	t.Run("pacing timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), now.Add(time.Second), now.Add(time.Millisecond))
		require.Equal(t, now.Add(time.Millisecond), timer.Deadline())
	})
}

func TestConnectionTimerReset(t *testing.T) {
	now := time.Now()
	timer := newTimer()
	timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
	require.Equal(t, now.Add(time.Minute), timer.Deadline())
	timer.SetRead()

	timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), time.Time{}, time.Time{})
	require.Equal(t, now.Add(time.Hour), timer.Deadline())
}
