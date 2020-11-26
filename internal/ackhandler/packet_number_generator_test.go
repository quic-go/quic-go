package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Number Generator", func() {
	var png *packetNumberGenerator
	const initialPN protocol.PacketNumber = 8

	BeforeEach(func() {
		png = newPacketNumberGenerator(initialPN, 100)
	})

	It("can be initialized to return any first packet number", func() {
		png = newPacketNumberGenerator(12345, 100)
		Expect(png.Pop()).To(Equal(protocol.PacketNumber(12345)))
	})

	It("gets the first packet number", func() {
		num := png.Pop()
		Expect(num).To(Equal(initialPN))
	})

	It("allows peeking", func() {
		png.nextToSkip = 1000
		Expect(png.Peek()).To(Equal(initialPN))
		Expect(png.Peek()).To(Equal(initialPN))
		Expect(png.Pop()).To(Equal(initialPN))
		Expect(png.Peek()).To(Equal(initialPN + 1))
		Expect(png.Peek()).To(Equal(initialPN + 1))
	})

	It("skips a packet number", func() {
		var last protocol.PacketNumber
		var skipped bool
		for i := 0; i < 1000; i++ {
			num := png.Pop()
			if num > last+1 {
				skipped = true
				break
			}
			last = num
		}
		Expect(skipped).To(BeTrue())
	})

	It("skips a specific packet number", func() {
		png.nextToSkip = initialPN + 1
		Expect(png.Pop()).To(Equal(initialPN))
		Expect(png.Peek()).To(Equal(initialPN + 2))
		Expect(png.Pop()).To(Equal(initialPN + 2))
	})

	It("generates a new packet number to skip", func() {
		const averagePeriod = 25
		png.averagePeriod = averagePeriod

		periods := make([]protocol.PacketNumber, 0, 500)
		last := initialPN
		var lastSkip protocol.PacketNumber
		for len(periods) < cap(periods) {
			next := png.Pop()
			if next > last+1 {
				skipped := next - 1
				Expect(skipped).To(BeNumerically(">", lastSkip+1))
				periods = append(periods, skipped-lastSkip-1)
				lastSkip = skipped
			}
			last = next
		}

		var average float64
		for _, p := range periods {
			average += float64(p) / float64(len(periods))
		}
		Expect(average).To(BeNumerically("~", averagePeriod+1 /* we never skip two packet numbers at the same time */, 5))
	})
})
