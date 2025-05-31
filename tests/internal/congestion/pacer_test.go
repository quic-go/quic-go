package congestion

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPacerPacing(t *testing.T) {
	bandwidth := 50 * initialMaxDatagramSize // 50 full-size packets per second
	p := newPacer(func() Bandwidth { return Bandwidth(bandwidth) * BytesPerSecond * 4 / 5 })
	now := time.Now()
	require.Zero(t, p.TimeUntilSend())
	budget := p.Budget(now)
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, budget)

	// consume the initial budget by sending packets
	for budget > 0 {
		require.Zero(t, p.TimeUntilSend())
		require.Equal(t, budget, p.Budget(now))
		p.SentPacket(now, initialMaxDatagramSize)
		budget -= initialMaxDatagramSize
	}

	// now packets are being paced
	for range 5 {
		require.Zero(t, p.Budget(now))
		nextPacket := p.TimeUntilSend()
		require.NotZero(t, nextPacket)
		require.Equal(t, time.Second/50, nextPacket.Sub(now))
		now = nextPacket
		p.SentPacket(now, initialMaxDatagramSize)
	}

	nextPacket := p.TimeUntilSend()
	require.Equal(t, time.Second/50, nextPacket.Sub(now))
	// send this packet a bit later, simulating timer delay
	p.SentPacket(nextPacket.Add(time.Millisecond), initialMaxDatagramSize)
	// the next packet should be paced again, without a delay
	require.Equal(t, time.Second/50, p.TimeUntilSend().Sub(nextPacket))

	// now send a half-size packet
	now = p.TimeUntilSend()
	p.SentPacket(now, initialMaxDatagramSize/2)
	require.Equal(t, initialMaxDatagramSize/2, p.Budget(now))
	require.Equal(t, time.Second/100, p.TimeUntilSend().Sub(now))
	p.SentPacket(p.TimeUntilSend(), initialMaxDatagramSize/2)

	now = p.TimeUntilSend()
	// budget accumulates if no packets are sent for a while
	// we should have accumulated budget to send a burst now
	require.Equal(t, 5*initialMaxDatagramSize, p.Budget(now.Add(4*time.Second/50)))
	// but the budget is capped at the max burst size
	require.Equal(t, maxBurstSizePackets*initialMaxDatagramSize, p.Budget(now.Add(time.Hour)))
	p.SentPacket(now, initialMaxDatagramSize)
	require.Zero(t, p.Budget(now))

	// reduce the bandwidth
	bandwidth = 10 * initialMaxDatagramSize // 10 full-size packets per second
	require.Equal(t, time.Second/10, p.TimeUntilSend().Sub(now))
}

func TestPacerUpdatePacketSize(t *testing.T) {
	const bandwidth = 50 * initialMaxDatagramSize // 50 full-size packets per second
	p := newPacer(func() Bandwidth { return Bandwidth(bandwidth) * BytesPerSecond * 4 / 5 })

	// consume the initial budget by sending packets
	now := time.Now()
	for p.Budget(now) > 0 {
		p.SentPacket(now, initialMaxDatagramSize)
	}

	require.Equal(t, time.Second/50, p.TimeUntilSend().Sub(now))
	// Double the packet size. We now need to wait twice as long to send the next packet.
	const newDatagramSize = 2 * initialMaxDatagramSize
	p.SetMaxDatagramSize(newDatagramSize)
	require.Equal(t, 2*time.Second/50, p.TimeUntilSend().Sub(now))

	// check that the maximum burst size is updated
	require.Equal(t, maxBurstSizePackets*newDatagramSize, p.Budget(now.Add(time.Hour)))
}

func TestPacerFastPacing(t *testing.T) {
	const bandwidth = 10000 * initialMaxDatagramSize // 10,000 full-size packets per second
	p := newPacer(func() Bandwidth { return Bandwidth(bandwidth) * BytesPerSecond * 4 / 5 })

	// consume the initial budget by sending packets
	now := time.Now()
	for p.Budget(now) > 0 {
		p.SentPacket(now, initialMaxDatagramSize)
	}

	// If we were pacing by packet, we'd expect the next packet to send in 1/10ms.
	// However, we don't want to arm the pacing timer for less than 1ms,
	// so we wait for 1ms, and then send 10 packets in a burst.
	require.Equal(t, time.Millisecond, p.TimeUntilSend().Sub(now))
	require.Equal(t, 10*initialMaxDatagramSize, p.Budget(now.Add(time.Millisecond)))

	now = now.Add(time.Millisecond)
	for range 10 {
		require.NotZero(t, p.Budget(now))
		p.SentPacket(now, initialMaxDatagramSize)
	}
	require.Zero(t, p.Budget(now))
	require.Equal(t, time.Millisecond, p.TimeUntilSend().Sub(now))
}

func TestPacerNoOverflows(t *testing.T) {
	p := newPacer(func() Bandwidth { return infBandwidth })
	now := time.Now()
	p.SentPacket(now, initialMaxDatagramSize)
	for range 100000 {
		require.NotZero(t, p.Budget(now.Add(time.Duration(rand.Int64N(math.MaxInt64)))))
	}
}
