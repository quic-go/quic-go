package congestion

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const numConnections uint32 = 2
const nConnectionBeta float32 = (float32(numConnections) - 1 + beta) / float32(numConnections)
const nConnectionAlpha float32 = 3 * float32(numConnections) * float32(numConnections) * (1 - nConnectionBeta) / (1 + nConnectionBeta)

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
		const rttMin = 100 * time.Millisecond
		const rttMinS = float32(rttMin/time.Millisecond) / 1000.0
		currentCwnd := protocol.PacketNumber(10)
		// Without the signed-integer, cubic-convex fix, we mistakenly
		// increment cwnd after only one_ms_ and a single ack.
		expectedCwnd := currentCwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		initialTime := clock.Now()
		currentCwnd = cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
		Expect(currentCwnd).To(Equal(expectedCwnd))
		currentCwnd = expectedCwnd
		initialCwnd := currentCwnd
		// Normal TCP phase.
		// The maximum number of expected reno RTTs can be calculated by
		// finding the point where the cubic curve and the reno curve meet.
		maxRenoRtts := int(math.Sqrt(float64(nConnectionAlpha/(0.4*rttMinS*rttMinS*rttMinS))) - 1)
		for i := 0; i < maxRenoRtts; i++ {
			maxPerAckCwnd := currentCwnd
			for n := uint64(1); n < uint64(float32(maxPerAckCwnd)/nConnectionAlpha); n++ {
				// Call once per ACK.
				nextCwnd := cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
				Expect(nextCwnd).To(Equal(currentCwnd))
			}
			clock.Advance(100 * time.Millisecond)
			currentCwnd = cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
			// When we fix convex mode and the uint64 arithmetic, we
			// increase the expected_cwnd only after after the first 100ms,
			// rather than after the initial 1ms.
			expectedCwnd++
			Expect(currentCwnd).To(Equal(expectedCwnd))
		}
		// Cubic phase.
		for i := 0; i < 52; i++ {
			for n := protocol.PacketNumber(1); n < currentCwnd; n++ {
				// Call once per ACK.
				Expect(cubic.CongestionWindowAfterAck(currentCwnd, rttMin)).To(Equal(currentCwnd))
			}
			clock.Advance(100 * time.Millisecond)
			currentCwnd = cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
		}
		// Total time elapsed so far; add min_rtt (0.1s) here as well.
		elapsedTimeS := float32(clock.Now().Sub(initialTime)+rttMin) / float32(time.Second)
		// |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
		expectedCwnd = initialCwnd + protocol.PacketNumber((elapsedTimeS*elapsedTimeS*elapsedTimeS*410)/1024)
		Expect(currentCwnd).To(Equal(expectedCwnd))
	})

	It("manages loss events", func() {
		rttMin := 100 * time.Millisecond
		currentCwnd := protocol.PacketNumber(422)
		expectedCwnd := currentCwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(currentCwnd, rttMin)).To(Equal(expectedCwnd))
		expectedCwnd = protocol.PacketNumber(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		expectedCwnd = protocol.PacketNumber(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
	})

	It("works below origin", func() {
		// Concave growth.
		rttMin := 100 * time.Millisecond
		currentCwnd := protocol.PacketNumber(422)
		expectedCwnd := currentCwnd
		// Initialize the state.
		clock.Advance(time.Millisecond)
		Expect(cubic.CongestionWindowAfterAck(currentCwnd, rttMin)).To(Equal(expectedCwnd))
		expectedCwnd = protocol.PacketNumber(float32(currentCwnd) * nConnectionBeta)
		Expect(cubic.CongestionWindowAfterPacketLoss(currentCwnd)).To(Equal(expectedCwnd))
		currentCwnd = expectedCwnd
		// First update after loss to initialize the epoch.
		currentCwnd = cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
		// Cubic phase.
		for i := 0; i < 40; i++ {
			clock.Advance(100 * time.Millisecond)
			currentCwnd = cubic.CongestionWindowAfterAck(currentCwnd, rttMin)
		}
		expectedCwnd = 422
		Expect(currentCwnd).To(Equal(expectedCwnd))
	})
})
