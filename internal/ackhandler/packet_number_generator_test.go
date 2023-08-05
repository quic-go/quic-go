package ackhandler

import (
	"fmt"
	"math"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sequential Packet Number Generator", func() {
	It("generates sequential packet numbers", func() {
		const initialPN protocol.PacketNumber = 123
		png := newSequentialPacketNumberGenerator(initialPN)

		for i := initialPN; i < initialPN+1000; i++ {
			Expect(png.Peek()).To(Equal(i))
			Expect(png.Peek()).To(Equal(i))
			skipNext, pn := png.Pop()
			Expect(skipNext).To(BeFalse())
			Expect(pn).To(Equal(i))
		}
	})
})

var _ = Describe("Skipping Packet Number Generator", func() {
	const initialPN protocol.PacketNumber = 8
	const initialPeriod protocol.PacketNumber = 25
	const maxPeriod protocol.PacketNumber = 300

	It("uses a maximum period that is sufficiently small such that using a 32-bit random number is ok", func() {
		Expect(2 * protocol.SkipPacketMaxPeriod).To(BeNumerically("<", math.MaxInt32))
	})

	It("can be initialized to return any first packet number", func() {
		png := newSkippingPacketNumberGenerator(12345, initialPeriod, maxPeriod)
		_, pn := png.Pop()
		Expect(pn).To(Equal(protocol.PacketNumber(12345)))
	})

	It("allows peeking", func() {
		png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod).(*skippingPacketNumberGenerator)
		Expect(png.Peek()).To(Equal(initialPN))
		Expect(png.Peek()).To(Equal(initialPN))
		skipped, pn := png.Pop()
		Expect(pn).To(Equal(initialPN))
		next := initialPN + 1
		if skipped {
			next++
		}
		Expect(png.Peek()).To(Equal(next))
		Expect(png.Peek()).To(Equal(next))
	})

	It("skips a packet number", func() {
		png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod)
		var last protocol.PacketNumber
		var skipped bool
		for i := 0; i < int(maxPeriod); i++ {
			didSkip, num := png.Pop()
			if didSkip {
				skipped = true
				_, nextNum := png.Pop()
				Expect(nextNum).To(Equal(num + 1))
				break
			}
			if i != 0 {
				Expect(num).To(Equal(last + 1))
			}
			last = num
		}
		Expect(skipped).To(BeTrue())
	})

	It("generates a new packet number to skip", func() {
		const rep = 2500
		periods := make([][]protocol.PacketNumber, rep)
		expectedPeriods := []protocol.PacketNumber{25, 50, 100, 200, 300, 300, 300}

		for i := 0; i < rep; i++ {
			png := newSkippingPacketNumberGenerator(initialPN, initialPeriod, maxPeriod)
			lastSkip := initialPN
			for len(periods[i]) < len(expectedPeriods) {
				skipNext, next := png.Pop()
				if skipNext {
					skipped := next + 1
					Expect(skipped).To(BeNumerically(">", lastSkip+1))
					periods[i] = append(periods[i], skipped-lastSkip-1)
					lastSkip = skipped
				}
			}
		}

		for j := 0; j < len(expectedPeriods); j++ {
			var average float64
			for i := 0; i < rep; i++ {
				average += float64(periods[i][j]) / float64(len(periods))
			}
			fmt.Fprintf(GinkgoWriter, "Period %d: %.2f (expected %d)\n", j, average, expectedPeriods[j])
			tolerance := protocol.PacketNumber(5)
			if t := expectedPeriods[j] / 10; t > tolerance {
				tolerance = t
			}
			Expect(average).To(BeNumerically("~", expectedPeriods[j]+1 /* we never skip two packet numbers at the same time */, tolerance))
		}
	})
})
