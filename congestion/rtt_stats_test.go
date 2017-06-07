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
		// Verify that ack_delay is corrected for in Smoothed RTT.
		rttStats.UpdateRTT((300 * time.Millisecond), (100 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
		// Verify that effective RTT of zero does not change Smoothed RTT.
		rttStats.UpdateRTT((200 * time.Millisecond), (200 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
		// Verify that large erroneous ack_delay does not change Smoothed RTT.
		rttStats.UpdateRTT((200 * time.Millisecond), (300 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
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
		rtt_sample := (10 * time.Millisecond)
		rttStats.UpdateRTT(rtt_sample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((10 * time.Millisecond)))

		// Gradually increase the rtt samples and ensure the RecentMinRTT starts
		// rising.
		for i := 0; i < 8; i++ {
			now = now.Add((25 * time.Millisecond))
			rtt_sample += (10 * time.Millisecond)
			rttStats.UpdateRTT(rtt_sample, 0, now)
			Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
			Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rtt_sample))
			Expect(rttStats.GetHalfWindowRTT()).To(Equal(rtt_sample - (10 * time.Millisecond)))
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
		rtt_sample -= (5 * time.Millisecond)
		rttStats.UpdateRTT(rtt_sample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rtt_sample - (5 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal((70 * time.Millisecond)))

		// A new half rtt low sets that and the quarter rtt low.
		rtt_sample -= (15 * time.Millisecond)
		rttStats.UpdateRTT(rtt_sample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.RecentMinRTT()).To(Equal((70 * time.Millisecond)))

		// A new full window loss sets the RecentMinRTT, but not MinRTT.
		rtt_sample = (65 * time.Millisecond)
		rttStats.UpdateRTT(rtt_sample, 0, now)
		Expect(rttStats.MinRTT()).To(Equal((10 * time.Millisecond)))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.RecentMinRTT()).To(Equal(rtt_sample))

		// A new all time low sets both the MinRTT and the RecentMinRTT.
		rtt_sample = (5 * time.Millisecond)
		rttStats.UpdateRTT(rtt_sample, 0, now)

		Expect(rttStats.MinRTT()).To(Equal(rtt_sample))
		Expect(rttStats.GetQuarterWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.GetHalfWindowRTT()).To(Equal(rtt_sample))
		Expect(rttStats.RecentMinRTT()).To(Equal(rtt_sample))
	})

	It("ExpireSmoothedMetrics", func() {
		initial_rtt := (10 * time.Millisecond)
		rttStats.UpdateRTT(initial_rtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initial_rtt))
		Expect(rttStats.RecentMinRTT()).To(Equal(initial_rtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(initial_rtt))

		Expect(rttStats.MeanDeviation()).To(Equal(initial_rtt / 2))

		// Update once with a 20ms RTT.
		doubled_rtt := initial_rtt * (2)
		rttStats.UpdateRTT(doubled_rtt, 0, time.Time{})
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(float32(initial_rtt) * 1.125)))

		// Expire the smoothed metrics, increasing smoothed rtt and mean deviation.
		rttStats.ExpireSmoothedMetrics()
		Expect(rttStats.SmoothedRTT()).To(Equal(doubled_rtt))
		Expect(rttStats.MeanDeviation()).To(Equal(time.Duration(float32(initial_rtt) * 0.875)))

		// Now go back down to 5ms and expire the smoothed metrics, and ensure the
		// mean deviation increases to 15ms.
		half_rtt := initial_rtt / 2
		rttStats.UpdateRTT(half_rtt, 0, time.Time{})
		Expect(doubled_rtt).To(BeNumerically(">", rttStats.SmoothedRTT()))
		Expect(initial_rtt).To(BeNumerically("<", rttStats.MeanDeviation()))
	})

	It("UpdateRTTWithBadSendDeltas", func() {
		// Make sure we ignore bad RTTs.
		// base::test::MockLog log;

		initial_rtt := (10 * time.Millisecond)
		rttStats.UpdateRTT(initial_rtt, 0, time.Time{})
		Expect(rttStats.MinRTT()).To(Equal(initial_rtt))
		Expect(rttStats.RecentMinRTT()).To(Equal(initial_rtt))
		Expect(rttStats.SmoothedRTT()).To(Equal(initial_rtt))

		bad_send_deltas := []time.Duration{
			0,
			utils.InfDuration,
			-1000 * time.Microsecond,
		}
		// log.StartCapturingLogs();

		for _, bad_send_delta := range bad_send_deltas {
			// SCOPED_TRACE(Message() << "bad_send_delta = "
			//  << bad_send_delta.ToMicroseconds());
			// EXPECT_CALL(log, Log(LOG_WARNING, _, _, _, HasSubstr("Ignoring")));
			rttStats.UpdateRTT(bad_send_delta, 0, time.Time{})
			Expect(rttStats.MinRTT()).To(Equal(initial_rtt))
			Expect(rttStats.RecentMinRTT()).To(Equal(initial_rtt))
			Expect(rttStats.SmoothedRTT()).To(Equal(initial_rtt))
		}
	})

	It("ResetAfterConnectionMigrations", func() {
		rttStats.UpdateRTT((300 * time.Millisecond), (100 * time.Millisecond), time.Time{})
		Expect(rttStats.LatestRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.SmoothedRTT()).To(Equal((200 * time.Millisecond)))
		Expect(rttStats.MinRTT()).To(Equal((300 * time.Millisecond)))
		Expect(rttStats.RecentMinRTT()).To(Equal(300 * time.Millisecond))

		// Reset rtt stats on connection migrations.
		rttStats.OnConnectionMigration()
		Expect(rttStats.LatestRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.SmoothedRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.MinRTT()).To(Equal(time.Duration(0)))
		Expect(rttStats.RecentMinRTT()).To(Equal(time.Duration(0)))
	})

})
