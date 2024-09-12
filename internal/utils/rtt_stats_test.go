package utils

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RTT stats", func() {
	It("DefaultsBeforeUpdate", func() {
		var rttStats RTTStats
		Expect(rttStats.MinRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(0)))
	})

	It("SmoothedRTT", func() {
		var rttStats RTTStats
		// Verify that ack_delay is ignored in the first measurement.
		rttStats.UpdateRTT((300 * time.Millisecond), (100 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((300 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((300 * time.Millisecond)))
		// Verify that Smoothed RTT includes max ack delay if it's reasonable.
		rttStats.UpdateRTT((350 * time.Millisecond), (50 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((300 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((300 * time.Millisecond)))
		// Verify that large erroneous ack_delay does not change Smoothed RTT.
		rttStats.UpdateRTT((200 * time.Millisecond), (300 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((287500 * time.Microsecond)))
	})

	It("MinRTT", func() {
		var rttStats RTTStats
		rttStats.UpdateRTT((200 * time.Millisecond), 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal((200 * time.Millisecond)))
		rttStats.UpdateRTT((10 * time.Millisecond), 0, time.Time{}.Add((10 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((20 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((30 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((40 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		// Verify that ack_delay does not go into recording of MinRTT_.
		rttStats.UpdateRTT((7 * time.Millisecond), (2 * time.Millisecond), time.Time{}.Add((50 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((7 * time.Millisecond)))
	})

	It("MaxAckDelay", func() {
		var rttStats RTTStats
		rttStats.SetMaxAckDelay(42 * time.Minute)
		Expect(rttStats.MaxAckDelay()).To(Equal(42 * time.Minute))
	})

	It("computes the PTO", func() {
		var rttStats RTTStats
		const (
			maxAckDelay = 42 * time.Minute
			rtt         = time.Second
		)
		rttStats.SetMaxAckDelay(maxAckDelay)
		rttStats.UpdateRTT(rtt, 0, time.Time{})
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
		Expect(rttStats.MeanDeviation()).To(Equal(rtt / 2))
		Expect(rttStats.PTO(false)).To(Equal(rtt + 4*(rtt/2)))
		Expect(rttStats.PTO(true)).To(Equal(rtt + 4*(rtt/2) + maxAckDelay))
	})

	It("uses the granularity for computing the PTO for short RTTs", func() {
		var rttStats RTTStats
		const rtt = time.Microsecond
		rttStats.UpdateRTT(rtt, 0, time.Time{})
		Expect(rttStats.PTO(true)).To(Equal(rtt + protocol.TimerGranularity))
	})

	It("UpdateRTTWithBadSendDeltas", func() {
		var rttStats RTTStats
		const initialRtt = 10 * time.Millisecond
		rttStats.UpdateRTT(initialRtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initialRtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(initialRtt))

		badSendDeltas := []time.Duration{
			0,
			-1000 * time.Microsecond,
		}

		for _, badSendDelta := range badSendDeltas {
			rttStats.UpdateRTT(badSendDelta, 0, time.Time{})
			Expect(rttStats.MinRTT()).To(Equal(initialRtt))
			Expect(rttStats.SmoothedRTT()).To(Equal(initialRtt))
		}
	})

	It("restores the RTT", func() {
		var rttStats RTTStats
		rttStats.SetInitialRTT(10 * time.Second)
		Expect(rttStats.LatestRTT()).To(Equal(10 * time.Second))
		Expect(rttStats.SmoothedRTT()).To(Equal(10 * time.Second))
		Expect(rttStats.MeanDeviation()).To(BeZero())
		// update the RTT and make sure that the initial value is immediately forgotten
		rttStats.UpdateRTT(200*time.Millisecond, 0, time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal(200 * time.Millisecond))
		Expect(rttStats.SmoothedRTT()).To(Equal(200 * time.Millisecond))
		Expect(rttStats.MeanDeviation()).To(Equal(100 * time.Millisecond))
	})

	It("doesn't restore the RTT if we already have a measurement", func() {
		var rttStats RTTStats
		const rtt = 10 * time.Millisecond
		rttStats.UpdateRTT(rtt, 0, time.Now())
		Expect(rttStats.LatestRTT()).To(Equal(rtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
		rttStats.SetInitialRTT(time.Minute)
		Expect(rttStats.LatestRTT()).To(Equal(rtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
	})
})
