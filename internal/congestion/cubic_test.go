package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const kBeta float32 = 0.7 // Default Cubic backoff factor.
const kNumConnections uint32 = 2
const kNConnectionBeta float32 = (float32(kNumConnections) - 1 + kBeta) / float32(kNumConnections)
const kNConnectionAlpha float32 = 3 * float32(kNumConnections) * float32(kNumConnections) * (1 - kNConnectionBeta) / (1 + kNConnectionBeta)

var _ = Describe("Cubic", func() {
	var (
		clock mockClock
		cubic *Cubic
	)

	BeforeEach(func() {
		clock = mockClock{}
		cubic = NewCubic(&clock)
	})

	It("works above origin", func() {
		// Convex growth.
		const rtt_min = 100 * time.Millisecond
		const rtt_min_s = float32(rtt_min/time.Millisecond) / 1000.0
		current_cwnd := protocol.PacketNumber(10)
		// Without the signed-integer, cubic-convex fix, we mistakenly
		// increment cwnd after only one_ms_ and a single ack.
		expected_cwnd := current_cwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		initial_time := clock.Now()
		current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
		Expect(current_cwnd).To(Equal(expected_cwnd))
		current_cwnd = expected_cwnd
		initial_cwnd := current_cwnd
		// Normal TCP phase.
		// The maximum number of expected reno RTTs can be calculated by
		// finding the point where the cubic curve and the reno curve meet.
		max_reno_rtts := int(math.Sqrt(float64(kNConnectionAlpha/(0.4*rtt_min_s*rtt_min_s*rtt_min_s))) - 1)
		for i := 0; i < max_reno_rtts; i++ {
			max_per_ack_cwnd := current_cwnd
			for n := uint64(1); n < uint64(float32(max_per_ack_cwnd)/kNConnectionAlpha); n++ {
				// Call once per ACK.
				next_cwnd := cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
				Expect(next_cwnd).To(Equal(current_cwnd))
			}
			clock.Advance(100 * time.Millisecond)
			current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
			// When we fix convex mode and the uint64 arithmetic, we
			// increase the expected_cwnd only after after the first 100ms,
			// rather than after the initial 1ms.
			expected_cwnd++
			Expect(current_cwnd).To(Equal(expected_cwnd))
		}
		// Cubic phase.
		for i := 0; i < 52; i++ {
			for n := protocol.PacketNumber(1); n < current_cwnd; n++ {
				// Call once per ACK.
				Expect(cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)).To(Equal(current_cwnd))
			}
			clock.Advance(100 * time.Millisecond)
			current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
		}
		// Total time elapsed so far; add min_rtt (0.1s) here as well.
		elapsed_time_s := float32(clock.Now().Sub(initial_time)+rtt_min) / float32(time.Second)
		// |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
		expected_cwnd = initial_cwnd + protocol.PacketNumber((elapsed_time_s*elapsed_time_s*elapsed_time_s*410)/1024)
		Expect(current_cwnd).To(Equal(expected_cwnd))
	})

	It("manages loss events", func() {
		rtt_min := 100 * time.Millisecond
		current_cwnd := protocol.PacketNumber(422)
		expected_cwnd := current_cwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)).To(Equal(expected_cwnd))
		expected_cwnd = protocol.PacketNumber(float32(current_cwnd) * kNConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(current_cwnd)).To(Equal(expected_cwnd))
		expected_cwnd = protocol.PacketNumber(float32(current_cwnd) * kNConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(current_cwnd)).To(Equal(expected_cwnd))
	})

	It("works below origin", func() {
		// Concave growth.
		rtt_min := 100 * time.Millisecond
		current_cwnd := protocol.PacketNumber(422)
		expected_cwnd := current_cwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)).To(Equal(expected_cwnd))
		expected_cwnd = protocol.PacketNumber(float32(current_cwnd) * kNConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(current_cwnd)).To(Equal(expected_cwnd))
		current_cwnd = expected_cwnd
		// First update after loss to initialize the epoch.
		current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
		// Cubic phase.
		for i := 0; i < 40; i++ {
			clock.Advance(100 * time.Millisecond)
			current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
		}
		expected_cwnd = 422
		Expect(current_cwnd).To(Equal(expected_cwnd))
	})
})
