package proxy

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RTT settings", func() {
	Context("no variance", func() {
		It("always gets the same value", func() {
			rttGen := newRttGenerator(10*time.Millisecond, 10*time.Millisecond)
			for i := 0; i < 100; i++ {
				Expect(rttGen.getRTT()).To(Equal(10 * time.Millisecond))
			}
		})
	})

	Context("random RTT", func() {
		var rttGen rttGenerator

		BeforeEach(func() {
			rttGen = newRttGenerator(10*time.Millisecond, 30*time.Millisecond)
		})

		It("has the right mean value", func() {
			var rttSum time.Duration
			rep := 1000
			for i := 0; i < rep; i++ {
				rttSum += rttGen.getRTT()
			}
			averageRTT := rttSum.Nanoseconds() / 1000 / int64(rep) // in microseconds
			Expect(averageRTT).To(BeNumerically("~", 20000, 1000)) // between 19 and 21 microseconds
		})

		It("covers the whole interval", func() {
			var max time.Duration
			min := time.Hour

			rep := 1000
			for i := 0; i < rep; i++ {
				rtt := rttGen.getRTT()
				if rtt > max {
					max = rtt
				}
				if rtt < min {
					min = rtt
				}
			}

			Expect(min.Nanoseconds() / 1000).To(BeNumerically("<", 11000))
			Expect(max.Nanoseconds() / 1000).To(BeNumerically(">", 29000))
		})
	})
})
