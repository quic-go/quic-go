package congestion

import (
	"time"

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
		Expect(rttStats.InitialRTTus()).To(BeNumerically(">", 0))
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
		Expect(rttStats.RecentMinRTT()).To(Equal((200 * time.Millisecond)))
		rttStats.UpdateRTT((10 * time.Millisecond), 0, time.Time{}.Add((10 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((20 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((30 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))
		rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{}.Add((40 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))
		// Verify that ack_delay does not go into recording of MinRTT_.
		rttStats.UpdateRTT((7 * time.Millisecond), (2 * time.Millisecond), time.Time{}.Add((50 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((7 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((7 * time.Millisecond)))
	})

	It("RecentMinRTT", func() {
		rttStats.UpdateRTT((10 * time.Millisecond), 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))

		rttStats.SampleNewRecentMinRTT(4)
		for i := 0; i < 3; i++ {
			rttStats.UpdateRTT((50 * time.Millisecond), 0, time.Time{})
			Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
			Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))
		}
		rttStats.UpdateRTT((50 * time.Millisecond),
			0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((50 * time.Millisecond)))
	})

	It("WindowedRecentMinRTT", func() {
		// Set the window to 99ms, so 25ms is more than a quarter rtt.
		rttStats.SetRecentMinRTTwindow((99 * time.Millisecond))

		now := time.Time{}
		rttSample := (10 * time.Millisecond)
		rttStats.UpdateRTT(rttSample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))

		// Gradually increase the rtt samples and ensure the RecentMinRTT starts
		// rising.
		for i := 0; i < 8; i++ {
			now = now.Add((25 * time.Millisecond))
			rttSample += (10 * time.Millisecond)
			rttStats.UpdateRTT(rttSample, 0, now)
			Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
			Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rttSample))
			Expect(rttStats.GetHalfWindowRTT()).To(Equal(rttSample - (10 * time.Millisecond)))
			if i < 3 {
				Expect(rttStats.RecentMinRTT()).To(Equal(10 * time.Millisecond))
			} else if i < 5 {
				Expect(rttStats.RecentMinRTT()).To(Equal(30 * time.Millisecond))
			} else if i < 7 {
				Expect(rttStats.RecentMinRTT()).To(Equal(50 * time.Millisecond))
			} else {
				Expect(rttStats.RecentMinRTT()).To(Equal(70 * time.Millisecond))
			}
		}

		// A new quarter rtt low sets that, but nothing else.
		rttSample -= (5 * time.Millisecond)
		rttStats.UpdateRTT(rttSample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rttSample - (5 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((70 * time.Millisecond)))

		// A new half rtt low sets that and the quarter rtt low.
		rttSample -= (15 * time.Millisecond)
		rttStats.UpdateRTT(rttSample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.RecentMinRTT()).To(Equal((70 * time.Millisecond)))

		// A new full window loss sets the RecentMinRTT, but not MinRTT.
		rttSample = (65 * time.Millisecond)
		rttStats.UpdateRTT(rttSample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.RecentMinRTT()).To(Equal(rttSample))

		// A new all time low sets both the MinRTT and the RecentMinRTT.
		rttSample = (5 * time.Millisecond)
		rttStats.UpdateRTT(rttSample, 0, now)

		Expect(rttStats.MinRTT()).To(Equal(rttSample))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rttSample))
		Expect(rttStats.RecentMinRTT()).To(Equal(rttSample))
	})

	It("ExpireSmoothedMetrics", func() {
		initialRtt := (10 * time.Millisecond)
		rttStats.UpdateRTT(initialRtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initialRtt))
		Expect(rttStats.RecentMinRTT()).To(Equal(initialRtt))
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
		Expect(rttStats.RecentMinRTT()).To(Equal(initialRtt))
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
			Expect(rttStats.RecentMinRTT()).To(Equal(initialRtt))
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
		Expect(rttStats.RecentMinRTT()).To(Equal(200 * time.Millisecond))

		// Reset rtt stats on connection migrations.
		rttStats.OnConnectionMigration()
		Expect(rttStats.LatestRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.MinRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.RecentMinRTT()).To(Equal(time.Duration(0)))
	})

})
