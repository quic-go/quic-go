package utils

import (
	"math"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Windowed filter", func() {
	var (
		// now            int64
		windowedMinRtt *WindowedFilter[time.Duration, int64]
		windowedMaxBw  *WindowedFilter[uint64, int64]

		initializeMinFilter = func() {
			var nowTime int64 = 0
			var rttSample time.Duration = 10 * time.Millisecond
			for i := 0; i < 5; i++ {
				windowedMinRtt.Update(rttSample, nowTime)
				nowTime += 25
				rttSample += 10 * time.Millisecond
			}
		}

		initializeMaxFilter = func() {
			var nowTime int64 = 0
			var bwSample uint64 = 1000
			for i := 0; i < 5; i++ {
				windowedMaxBw.Update(bwSample, nowTime)
				nowTime += 25
				bwSample -= 100
			}
		}

		updateWithIrrelevantSamples = func(
			filter *WindowedFilter[uint64, uint64],
			maxValue, nowTime uint64) {
			for i := uint64(0); i < 1000; i++ {
				filter.Update(i%maxValue, nowTime)
			}
		}
	)

	BeforeEach(func() {
		windowedMinRtt = NewWindowedFilter[time.Duration, int64](99, MinFilter[time.Duration])
		windowedMaxBw = NewWindowedFilter[uint64, int64](99, MaxFilter[uint64])
	})

	It("UninitializedEstimates", func() {
		Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(0 * time.Millisecond)))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(time.Duration(0 * time.Millisecond)))
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(time.Duration(0 * time.Millisecond)))
		Expect(windowedMaxBw.GetBest()).To(Equal(uint64(0)))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(uint64(0)))
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(uint64(0)))
	})

	It("MonotonicallyIncreasingMin", func() {
		var nowTime int64 = 0
		var rttSample time.Duration = 10 * time.Millisecond
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(10 * time.Millisecond)))

		// Gradually increase the rtt samples and ensure the windowed min rtt starts
		// rising.
		for i := 0; i < 6; i++ {
			nowTime += 25
			rttSample += 10 * time.Millisecond
			windowedMinRtt.Update(rttSample, nowTime)
			if i < 3 {
				Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(10 * time.Millisecond)))
			} else if i == 3 {
				Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(20 * time.Millisecond)))
			} else if i < 6 {
				Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(40 * time.Millisecond)))
			}
		}
	})

	It("MonotonicallyDecreasingMax", func() {
		var nowTime int64 = 0
		var bwSample uint64 = 1000
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetBest()).To(Equal(uint64(1000)))

		// Gradually decrease the bw samples and ensure the windowed max bw starts
		// decreasing.
		for i := 0; i < 6; i++ {
			nowTime += 25
			bwSample -= 100
			windowedMaxBw.Update(bwSample, nowTime)
			if i < 3 {
				Expect(windowedMaxBw.GetBest()).To(Equal(uint64(1000)))
			} else if i == 3 {
				Expect(windowedMaxBw.GetBest()).To(Equal(uint64(900)))
			} else if i < 6 {
				Expect(windowedMaxBw.GetBest()).To(Equal(uint64(700)))
			}
		}
	})

	It("SampleChangesThirdBestMin", func() {
		initializeMinFilter()
		// RTT sample lower than the third-choice min-rtt sets that, but nothing else.
		var rttSample = windowedMinRtt.GetThirdBest() - time.Duration(5*time.Millisecond)
		Expect(windowedMinRtt.GetThirdBest() > time.Duration(5*time.Millisecond)).To(BeTrue())
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(time.Duration(40 * time.Millisecond)))
		Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(20 * time.Millisecond)))
	})

	It("SampleChangesThirdBestMax", func() {
		initializeMaxFilter()
		// BW sample higher than the third-choice max sets that, but nothing else.
		var bwSample = windowedMaxBw.GetThirdBest() + uint64(50)
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(uint64(700)))
		Expect(windowedMaxBw.GetBest()).To(Equal(uint64(900)))
	})

	It("SampleChangesSecondBestMin", func() {
		initializeMinFilter()
		// RTT sample lower than the second-choice min sets that and also
		// the third-choice min.
		var rttSample = windowedMinRtt.GetSecondBest() - time.Duration(5*time.Millisecond)
		Expect(windowedMinRtt.GetSecondBest() > time.Duration(5*time.Millisecond)).To(BeTrue())
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetBest()).To(Equal(time.Duration(20 * time.Millisecond)))
	})

	It("SampleChangesSecondBestMax", func() {
		initializeMaxFilter()
		// BW sample higher than the second-choice max sets that and also
		// the third-choice max.
		var bwSample = windowedMaxBw.GetSecondBest() + uint64(50)
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetBest()).To(Equal(uint64(900)))
	})

	It("SampleChangesAllMins", func() {
		initializeMinFilter()
		// RTT sample lower than the first-choice min-rtt sets that and also
		// the second and third-choice mins.
		var rttSample = windowedMinRtt.GetBest() - time.Duration(5*time.Millisecond)
		Expect(windowedMinRtt.GetBest() > time.Duration(5*time.Millisecond)).To(BeTrue())
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetBest()).To(Equal(rttSample))
	})

	It("SampleChangesAllMaxs", func() {
		initializeMaxFilter()
		// BW sample higher than the first-choice max sets that and also
		// the second and third-choice maxs.
		var bwSample = windowedMaxBw.GetBest() + uint64(50)
		// Latest sample was recorded at 100ms.
		var nowTime int64 = 101
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetBest()).To(Equal(bwSample))
	})

	It("ExpireBestMin", func() {
		initializeMinFilter()
		var oldThirdBest = windowedMinRtt.GetThirdBest()
		var oldSecondBest = windowedMinRtt.GetSecondBest()
		var rttSample = oldThirdBest + time.Duration(5*time.Millisecond)
		// Best min sample was recorded at 25ms, so expiry time is 124ms.
		var nowTime int64 = 125
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(oldThirdBest))
		Expect(windowedMinRtt.GetBest()).To(Equal(oldSecondBest))
	})

	It("ExpireBestMax", func() {
		initializeMaxFilter()
		var oldThirdBest = windowedMaxBw.GetThirdBest()
		var oldSecondBest = windowedMaxBw.GetSecondBest()
		var bwSample = oldThirdBest - uint64(50)
		// Best max sample was recorded at 25ms, so expiry time is 124ms.
		var nowTime int64 = 125
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(oldThirdBest))
		Expect(windowedMaxBw.GetBest()).To(Equal(oldSecondBest))
	})

	It("ExpireSecondBestMin", func() {
		initializeMinFilter()
		var oldThirdBest = windowedMinRtt.GetThirdBest()
		var rttSample = oldThirdBest + time.Duration(5*time.Millisecond)
		// Second best min sample was recorded at 75ms, so expiry time is 174ms.
		var nowTime int64 = 175
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetBest()).To(Equal(oldThirdBest))
	})

	It("ExpireSecondBestMax", func() {
		initializeMaxFilter()
		var oldThirdBest = windowedMaxBw.GetThirdBest()
		var bwSample = oldThirdBest - uint64(50)
		// Second best max sample was recorded at 75ms, so expiry time is 174ms.
		var nowTime int64 = 175
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetBest()).To(Equal(oldThirdBest))
	})

	It("ExpireAllMins", func() {
		initializeMinFilter()
		var rttSample = windowedMinRtt.GetThirdBest() + time.Duration(5*time.Millisecond)
		Expect(windowedMinRtt.GetBest() < time.Duration(math.MaxInt64)-time.Duration(5*time.Millisecond)).To(BeTrue())
		// Third best min sample was recorded at 100ms, so expiry time is 199ms.
		var nowTime int64 = 200
		windowedMinRtt.Update(rttSample, nowTime)
		Expect(windowedMinRtt.GetThirdBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetSecondBest()).To(Equal(rttSample))
		Expect(windowedMinRtt.GetBest()).To(Equal(rttSample))

	})

	It("ExpireAllMaxs", func() {
		initializeMaxFilter()
		var bwSample = windowedMaxBw.GetThirdBest() - uint64(50)
		// Third best max sample was recorded at 100ms, so expiry time is 199ms.
		var nowTime int64 = 200
		windowedMaxBw.Update(bwSample, nowTime)
		Expect(windowedMaxBw.GetThirdBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetSecondBest()).To(Equal(bwSample))
		Expect(windowedMaxBw.GetBest()).To(Equal(bwSample))
	})

	// Test the windowed filter where the time used is an exact counter instead of a
	// timestamp.  This is useful if, for example, the time is measured in round
	// trips.
	It("ExpireCounterBasedMax", func() {
		// Create a window which starts at t = 0 and expires after two cycles.
		var maxFilter = NewWindowedFilter[uint64, uint64](2, MaxFilter[uint64])
		var kBest = uint64(50000)
		// Insert 50000 at t = 1.
		maxFilter.Update(uint64(50000), 1)
		Expect(maxFilter.GetBest()).To(Equal(kBest))
		updateWithIrrelevantSamples(maxFilter, 20, 1)
		Expect(maxFilter.GetBest()).To(Equal(kBest))

		// Insert 40000 at t = 2.  Nothing is expected to expire.
		maxFilter.Update(uint64(40000), 2)
		Expect(maxFilter.GetBest()).To(Equal(kBest))
		updateWithIrrelevantSamples(maxFilter, 20, 2)
		Expect(maxFilter.GetBest()).To(Equal(kBest))

		// Insert 30000 at t = 3.  Nothing is expected to expire yet.
		maxFilter.Update(uint64(30000), 3)
		Expect(maxFilter.GetBest()).To(Equal(kBest))
		updateWithIrrelevantSamples(maxFilter, 20, 3)
		Expect(maxFilter.GetBest()).To(Equal(kBest))

		// Insert 20000 at t = 4.  50000 at t = 1 expires, so 40000 becomes the new
		// maximum.
		var kNewBest = uint64(40000)
		maxFilter.Update(uint64(20000), 4)
		Expect(maxFilter.GetBest()).To(Equal(kNewBest))
		updateWithIrrelevantSamples(maxFilter, 20, 4)
		Expect(maxFilter.GetBest()).To(Equal(kNewBest))
	})
})
