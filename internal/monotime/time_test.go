package monotime

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/synctest"

	"github.com/stretchr/testify/require"
)

func TestTimeRelations(t *testing.T) {
	t1 := Now()
	require.Equal(t, t1, t1)
	require.False(t, t1.IsZero())

	t2 := t1.Add(time.Second)

	require.False(t, t1.Equal(t2))
	require.False(t, t2.Equal(t1))

	require.True(t, t2.After(t1))
	require.False(t, t1.After(t2))
	require.False(t, t2.Before(t1))

	require.Equal(t, t2.Sub(t1), time.Second)
	require.Equal(t, t1.Sub(t2), -time.Second)
}

func TestSince(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t1 := Now()
		time.Sleep(time.Second)
		require.Equal(t, Since(t1), time.Second)
		require.Equal(t, Now().Sub(t1), time.Second)
		time.Sleep(time.Minute)
		require.Equal(t, Since(t1), time.Minute+time.Second)
		require.Equal(t, Now().Sub(t1), time.Minute+time.Second)
	})
}

func TestUntil(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t1 := Now().Add(time.Minute)
		require.Equal(t, Until(t1), time.Minute)
		require.Equal(t, t1.Sub(Now()), time.Minute)
		time.Sleep(15 * time.Second)
		require.Equal(t, Until(t1), 45*time.Second)
		require.Equal(t, t1.Sub(Now()), 45*time.Second)
	})
}

func TestConversions(t *testing.T) {
	t1 := Now()
	t1Time := t1.ToTime()
	require.Equal(t, FromTime(t1Time), t1)
	require.Zero(t, t1Time.Sub(t1.ToTime()))

	var zeroTime time.Time
	require.Zero(t, FromTime(zeroTime))
	require.Zero(t, FromTime(zeroTime))

	var zero Time
	require.True(t, zero.ToTime().IsZero())
}

func BenchmarkNow(b *testing.B) {
	b.Run("Now", func(b *testing.B) {
		for b.Loop() {
			_ = Now()
		}
	})

	b.Run("time.Now", func(b *testing.B) {
		for b.Loop() {
			_ = time.Now()
		}
	})
}
