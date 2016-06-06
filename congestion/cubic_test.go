package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
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
		rtt_min := 100 * time.Millisecond
		current_cwnd := protocol.PacketNumber(10)
		expected_cwnd := current_cwnd + 1
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)).To(Equal(expected_cwnd))
		current_cwnd = expected_cwnd
		// Normal TCP phase.
		for i := 0; i < 48; i++ {
			for n := uint64(1); n < uint64(float32(current_cwnd)/kNConnectionAlpha); n++ {
				// Call once per ACK.
				Expect(cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)).To(BeNumerically("~", current_cwnd, 1))
			}
			clock.Advance(100 * time.Millisecond)
			current_cwnd = cubic.CongestionWindowAfterAck(current_cwnd, rtt_min)
			Expect(current_cwnd).To(BeNumerically("~", expected_cwnd, 1))
			expected_cwnd++
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
		elapsed_time_s := 10.0 + 0.1
		// |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
		expected_cwnd = protocol.PacketNumber(11 + (elapsed_time_s*elapsed_time_s*elapsed_time_s*410)/1024)
		Expect(current_cwnd).To(Equal(expected_cwnd))
	})

	It("manages loss events", func() {
		rtt_min := 100 * time.Millisecond
		current_cwnd := protocol.PacketNumber(422)
		expected_cwnd := current_cwnd + 1
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
		expected_cwnd := current_cwnd + 1
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
