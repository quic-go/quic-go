package congestion

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestPacerPacing(t *testing.T) {
	bandwidth := 50 * Bandwidth(initialMaxDatagramSize) * BytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	require.Zero(t, p.TimeUntilSend(bandwidth))
	budget := p.Budget(now, bandwidth)
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, budget)

	// consume the initial budget by sending packets
	for budget > 0 {
		require.Zero(t, p.TimeUntilSend(bandwidth))
		require.Equal(t, budget, p.Budget(now, bandwidth))
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
		budget -= initialMaxDatagramSize
	}

	// now packets are being paced
	for range 5 {
		require.Zero(t, p.Budget(now, bandwidth))
		nextPacket := p.TimeUntilSend(bandwidth)
		require.NotZero(t, nextPacket)
		require.Equal(t, time.Second/50, nextPacket.Sub(now))
		now = nextPacket
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	}

	nextPacket := p.TimeUntilSend(bandwidth)
	require.Equal(t, time.Second/50, nextPacket.Sub(now))
	// send this packet a bit later, simulating timer delay
	p.SentPacket(nextPacket.Add(time.Millisecond), initialMaxDatagramSize, bandwidth)
	// the next packet should be paced again, without a delay
	require.Equal(t, time.Second/50, p.TimeUntilSend(bandwidth).Sub(nextPacket))

	// now send a half-size packet
	now = p.TimeUntilSend(bandwidth)
	p.SentPacket(now, initialMaxDatagramSize/2, bandwidth)
	require.Equal(t, initialMaxDatagramSize/2, p.Budget(now, bandwidth))
	require.Equal(t, time.Second/100, p.TimeUntilSend(bandwidth).Sub(now))
	p.SentPacket(p.TimeUntilSend(bandwidth), initialMaxDatagramSize/2, bandwidth)

	now = p.TimeUntilSend(bandwidth)
	// budget accumulates if no packets are sent for a while
	// we should have accumulated budget to send a burst now
	require.Equal(t, 5*initialMaxDatagramSize, p.Budget(now.Add(4*time.Second/50), bandwidth))
	// but the budget is capped at the max burst size
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, p.Budget(now.Add(time.Hour), bandwidth))
	p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	require.Zero(t, p.Budget(now, bandwidth))

	// reduce the bandwidth
	bandwidth = 10 * Bandwidth(initialMaxDatagramSize) * BytesPerSecond // 10 full-size packets per second
	require.Equal(t, time.Second/10, p.TimeUntilSend(bandwidth).Sub(now))
}

func TestPacerUpdatePacketSize(t *testing.T) {
	const bandwidth = 50 * Bandwidth(initialMaxDatagramSize) * BytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	// consume the initial budget by sending packets
	now := monotime.Now()
	for p.Budget(now, bandwidth) > 0 {
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	}

	require.Equal(t, time.Second/50, p.TimeUntilSend(bandwidth).Sub(now))
	// Double the packet size. We now need to wait twice as long to send the next packet.
	const newDatagramSize = 2 * initialMaxDatagramSize
	p.SetMaxDatagramSize(newDatagramSize)
	require.Equal(t, 2*time.Second/50, p.TimeUntilSend(bandwidth).Sub(now))

	// check that the maximum burst size is updated
	require.Equal(t, maxBurstSizePackets*newDatagramSize, p.Budget(now.Add(time.Hour), bandwidth))
}

func TestPacerFastPacing(t *testing.T) {
	const bandwidth = 10000 * Bandwidth(initialMaxDatagramSize) * BytesPerSecond // 10,000 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	// consume the initial budget by sending packets
	now := monotime.Now()
	for p.Budget(now, bandwidth) > 0 {
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	}

	// If we were pacing by packet, we'd expect the next packet to send in 1/10ms.
	// However, we don't want to arm the pacing timer for less than 1ms,
	// so we wait for 1ms, and then send 10 packets in a burst.
	require.Equal(t, time.Millisecond, p.TimeUntilSend(bandwidth).Sub(now))
	require.Equal(t, 10*initialMaxDatagramSize, p.Budget(now.Add(time.Millisecond), bandwidth))

	now = now.Add(time.Millisecond)
	for range 10 {
		require.NotZero(t, p.Budget(now, bandwidth))
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	}
	require.Zero(t, p.Budget(now, bandwidth))
	require.Equal(t, time.Millisecond, p.TimeUntilSend(bandwidth).Sub(now))
}

func TestPacerNoOverflows(t *testing.T) {
	const bandwidth Bandwidth = math.MaxUint64
	p := newPacer(initialMaxDatagramSize)
	now := monotime.Now()
	p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	for range 100000 {
		require.NotZero(t, p.Budget(now.Add(time.Duration(rand.Int64N(math.MaxInt64))), bandwidth))
	}

	burstCount := 1
	for p.Budget(now, bandwidth) > 0 {
		burstCount++
		p.SentPacket(now, initialMaxDatagramSize, bandwidth)
	}
	require.Equal(t, maxBurstSizePackets, burstCount)
	require.Zero(t, p.Budget(now, bandwidth))

	next := p.TimeUntilSend(bandwidth)
	require.Equal(t, next.Sub(now), protocol.MinPacingDelay)
	require.Greater(t, p.Budget(next, bandwidth), initialMaxDatagramSize)
}

func BenchmarkPacer(b *testing.B) {
	const bandwidth = 50 * Bandwidth(initialMaxDatagramSize) * BytesPerSecond // 50 full-size packets per second
	p := newPacer(initialMaxDatagramSize)

	now := monotime.Now()

	var i int
	for b.Loop() {
		i++
		for p.Budget(now, bandwidth) > 0 {
			p.SentPacket(now, initialMaxDatagramSize, bandwidth)
		}
		next := p.TimeUntilSend(bandwidth)
		if i%2 == 0 {
			now = next
		} else {
			now = now.Add(100 * time.Millisecond)
		}
	}
}
