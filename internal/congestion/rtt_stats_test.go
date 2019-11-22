package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RTT stats", func() {
	var (
		rttStats *RTTStats
	)

	BeforeEach(func() {
		rttStats = NewRTTStats()
	})

	It("DefaultsBeforeUpdate", func() {
		Expect(rttStats.MinRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(0)))
	})

	It("SmoothedRTT", func() {
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
		rttStats.SetMaxAckDelay(42 * time.Minute)
		Expect(rttStats.MaxAckDelay()).To(Equal(42 * time.Minute))
	})

	It("computes the PTO", func() {
		maxAckDelay := 42 * time.Minute
		rttStats.SetMaxAckDelay(maxAckDelay)
		rtt := time.Second
		rttStats.UpdateRTT(rtt, 0, time.Time{})
		Expect(rttStats.SmoothedRTT()).To(Equal(rtt))
		Expect(rttStats.MeanDeviation()).To(Equal(rtt / 2))
		Expect(rttStats.PTO(false)).To(Equal(rtt + 4*(rtt/2)))
		Expect(rttStats.PTO(true)).To(Equal(rtt + 4*(rtt/2) + maxAckDelay))
	})

	It("uses the granularity for computing the PTO for short RTTs", func() {
		rtt := time.Microsecond
		rttStats.UpdateRTT(rtt, 0, time.Time{})
		Expect(rttStats.PTO(true)).To(Equal(rtt + protocol.TimerGranularity))
	})

	It("ExpireSmoothedMetrics", func() {
		initialRtt := (10 * time.Millisecond)
		rttStats.UpdateRTT(initialRtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initialRtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(initialRtt))

		Expect(rttStats.MeanDeviation()).To(Equal(initialRtt / 2))

		// Update once with a 20ms RTT.
		doubledRtt := initialRtt * (2)
		rttStats.UpdateRTT(doubledRtt, 0, time.Time{})
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(float32(initialRtt) * 1.125)))

		// Expire the smoothed metrics, increasing smoothed rtt and mean deviation.
		rttStats.ExpireSmoothedMetrics()
		Expect(rttStats.SmoothedRTT()).To(Equal(doubledRtt))
		Expect(rttStats.MeanDeviation()).To(Equal(time.Duration(float32(initialRtt) * 0.875)))

		// Now go back down to 5ms and expire the smoothed metrics, and ensure the
		// mean deviation increases to 15ms.
		halfRtt := initialRtt / 2
		rttStats.UpdateRTT(halfRtt, 0, time.Time{})
		Expect(doubledRtt).To(BeNumerically(">", rttStats.SmoothedRTT()))
		Expect(initialRtt).To(BeNumerically("<", rttStats.MeanDeviation()))
	})

	It("UpdateRTTWithBadSendDeltas", func() {
		// Make sure we ignore bad RTTs.
		// base::test::MockLog log;

		initialRtt := (10 * time.Millisecond)
		rttStats.UpdateRTT(initialRtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initialRtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(initialRtt))

		badSendDeltas := []time.Duration{
			0,
			utils.InfDuration,
			-1000 * time.Microsecond,
		}
		// log.StartCapturingLogs();

		for _, badSendDelta := range badSendDeltas {
			// SCOPED_TRACE(Message() << "bad_send_delta = "
			//  << bad_send_delta.ToMicroseconds());
			// EXPECT_CALL(log, Log(LOG_WARNING, _, _, _, HasSubstr("Ignoring")));
			rttStats.UpdateRTT(badSendDelta, 0, time.Time{})
			Expect(rttStats.MinRTT()).To(Equal(initialRtt))
			Expect(rttStats.SmoothedRTT()).To(Equal(initialRtt))
		}
	})

	It("ResetAfterConnectionMigrations", func() {
		rttStats.UpdateRTT((200 * time.Millisecond), 0, time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((200 * time.Millisecond)))
		rttStats.UpdateRTT((300 * time.Millisecond), (100 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((200 * time.Millisecond)))

		// Reset rtt stats on connection migrations.
		rttStats.OnConnectionMigration()
		Expect(rttStats.LatestRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.MinRTT()).To(Equal(time.Duration(0)))
	})

})
