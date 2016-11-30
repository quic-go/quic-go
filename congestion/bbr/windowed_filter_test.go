package bbr

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// only the tests for bandwidths (for the max filter)
var _ = Describe("Windowed Filter", func() {
	var (
		filter    windowedFilter
		startTime roundTripCount
	)

	BeforeEach(func() {
		filter = newWindowedFilter(99)
		startTime = 0
	})

	// Sets up windowed_max_bw_ to have the following values:
	// Best = 900 bps, recorded at 25ms
	// Second best = 700 bps, recorded at 75ms
	// Third best = 600 bps, recorded at 100ms
	initialize := func() {
		bwSample := 1000 * protocol.BitsPerSecond
		now := startTime

		for i := 0; i < 5; i++ {
			filter.Update(bwSample, now)
			now += 25
			bwSample -= 100 * protocol.BitsPerSecond
		}

		Expect(filter.GetBest()).To(Equal(900 * protocol.BitsPerSecond))
		Expect(filter.GetSecondBest()).To(Equal(700 * protocol.BitsPerSecond))
		Expect(filter.GetThirdBest()).To(Equal(600 * protocol.BitsPerSecond))
	}

	// updates the filter with a lot of small values in order
	// to ensure that it is not susceptible to noise.
	updateWithIrrelevantSamples := func(maxValue protocol.Bandwidth, t roundTripCount) {
		for i := 0; i < 1000; i++ {
			filter.Update(protocol.Bandwidth(i)%maxValue, t)
		}
	}

	It("has the correct uninitialized estimates", func() {
		filter = newWindowedFilter(0)
		Expect(filter.GetBest()).To(BeZero())
		Expect(filter.GetSecondBest()).To(BeZero())
		Expect(filter.GetThirdBest()).To(BeZero())
	})

	It("handles a monotonically decreasing max", func() {
		now := startTime
		bwSample := 1000 * protocol.BitsPerSecond // 1000 bits per second
		filter.Update(bwSample, now)
		Expect(filter.GetBest()).To(Equal(bwSample))

		// Gradually decrease the bw samples and ensure the windowed max bw starts decreasing
		for i := 0; i < 6; i++ {
			now += 25
			bwSample -= 100 * protocol.BitsPerSecond
			filter.Update(bwSample, now)
			if i < 3 {
				Expect(filter.GetBest()).To(Equal(1000 * protocol.BitsPerSecond))
			} else if i == 3 {
				Expect(filter.GetBest()).To(Equal(900 * protocol.BitsPerSecond))
			} else if i < 6 {
				Expect(filter.GetBest()).To(Equal(700 * protocol.BitsPerSecond))
			}
		}
	})

	It("changes the third best", func() {
		initialize()
		// BW sample higher than the third-choice max sets that, but nothing else.
		bwSample := filter.GetThirdBest() + 50*protocol.BitsPerSecond
		// Latest sample was recorded at 100ms.
		now := startTime + 101
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(700 * protocol.BitsPerSecond))
		Expect(filter.GetBest()).To(Equal(900 * protocol.BitsPerSecond))
	})

	It("changes the second best", func() {
		initialize()
		// BW sample higher than the second-choice max sets that and also
		// the third-choice max.
		bwSample := filter.GetSecondBest() + 50*protocol.BitsPerSecond
		// Latest sample was recorded at 100ms.
		now := startTime + 101
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(bwSample))
		Expect(filter.GetBest()).To(Equal(900 * protocol.BitsPerSecond))
	})

	It("changes all values", func() {
		initialize()
		// BW sample higher than the first-choice max sets that and also
		// the second and third-choice maxs
		bwSample := filter.GetBest() + 50*protocol.BitsPerSecond
		// Latest sample was recorded at 100ms.
		now := startTime + 101
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(bwSample))
		Expect(filter.GetBest()).To(Equal(bwSample))
	})

	It("expires best", func() {
		initialize()
		oldThirdBest := filter.GetThirdBest()
		oldSecondBest := filter.GetSecondBest()
		bwSample := oldThirdBest - 50*protocol.BitsPerSecond
		// Best max sample was recorded at 25ms, so expiry time is 124ms.
		now := startTime + 125
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(oldThirdBest))
		Expect(filter.GetBest()).To(Equal(oldSecondBest))
	})

	It("expires second best", func() {
		initialize()
		oldThirdBest := filter.GetThirdBest()
		bwSample := oldThirdBest - 50*protocol.BitsPerSecond
		// Second best max sample was recorded at 75ms, so expiry time is 174ms.
		now := startTime + 175
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(bwSample))
		Expect(filter.GetBest()).To(Equal(oldThirdBest))
	})

	It("expires all", func() {
		initialize()
		bwSample := filter.GetThirdBest() - 50*protocol.BitsPerSecond
		// Third best max sample was recorded at 100ms, so expiry time is 199ms.
		now := startTime + 200
		filter.Update(bwSample, now)
		Expect(filter.GetThirdBest()).To(Equal(bwSample))
		Expect(filter.GetSecondBest()).To(Equal(bwSample))
		Expect(filter.GetBest()).To(Equal(bwSample))
	})

	// Test the windowed filter where the time used is an exact counter instead of a
	// timestamp.  This is useful if, for example, the time is measured in round
	// trips.
	It("expires counter based max", func() {
		// Create a window which starts at t = 0 and expires after two cycles.
		filter = newWindowedFilter(2)
		var now roundTripCount

		// Insert 50000 at t = 1.
		best := protocol.Bandwidth(50000)
		now = 1
		filter.Update(best, now)
		Expect(filter.GetBest()).To(Equal(best))
		updateWithIrrelevantSamples(20, now)
		Expect(filter.GetBest()).To(Equal(best))

		// Insert 40000 at t = 2.  Nothing is expected to expire.
		now = 2
		filter.Update(40000, now)
		Expect(filter.GetBest()).To(Equal(best))
		updateWithIrrelevantSamples(20, now)
		Expect(filter.GetBest()).To(Equal(best))

		// Insert 30000 at t = 3.  Nothing is expected to expire yet.
		now = 3
		filter.Update(30000, now)
		Expect(filter.GetBest()).To(Equal(best))
		updateWithIrrelevantSamples(20, now)
		Expect(filter.GetBest()).To(Equal(best))

		// Insert 20000 at t = 4.  50000 at t = 1 expires, so 40000 becomes the new maximum.
		now = 4
		newBest := protocol.Bandwidth(40000)
		filter.Update(20000, now)
		Expect(filter.GetBest()).To(Equal(newBest))
		updateWithIrrelevantSamples(20, now)
		Expect(filter.GetBest()).To(Equal(newBest))
	})
})
