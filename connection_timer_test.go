package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/stretchr/testify/require"
)

func (t *connectionTimer) Deadline() monotime.Time { return t.timer.Deadline() }

func TestConnectionTimerModes(t *testing.T) {
	now := monotime.Now()

	t.Run("idle timeout", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), 0, 0, 0, 0)
		require.Equal(t, now.Add(time.Hour), timer.Deadline())
	})

	t.Run("connection ID expiry", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), now.Add(time.Minute), 0, 0, 0)
		require.Equal(t, now.Add(time.Minute), timer.Deadline())
	})

	t.Run("ACK timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), 0, now.Add(time.Minute), 0, 0)
		require.Equal(t, now.Add(time.Minute), timer.Deadline())
	})

	t.Run("loss timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), 0, now.Add(time.Minute), now.Add(time.Second), 0)
		require.Equal(t, now.Add(time.Second), timer.Deadline())
	})

	t.Run("pacing timer", func(t *testing.T) {
		timer := newTimer()
		timer.SetTimer(now.Add(time.Hour), 0, now.Add(time.Minute), now.Add(time.Second), now.Add(time.Millisecond))
		require.Equal(t, now.Add(time.Millisecond), timer.Deadline())
	})
}

func TestConnectionTimerReset(t *testing.T) {
	now := monotime.Now()
	timer := newTimer()
	timer.SetTimer(now.Add(time.Hour), 0, now.Add(time.Minute), 0, 0)
	require.Equal(t, now.Add(time.Minute), timer.Deadline())
	timer.SetRead()

	timer.SetTimer(now.Add(time.Hour), 0, now.Add(2*time.Minute), 0, 0)
	require.Equal(t, now.Add(2*time.Minute), timer.Deadline())
}
