package ackhandler

import (
	"math"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Number Generator", func() {
	var png *packetNumberGenerator

	BeforeEach(func() {
		png = newPacketNumberGenerator(1, 100)
	})

	It("can be initialized to return any first packet number", func() {
		png = newPacketNumberGenerator(12345, 100)
		Expect(png.Pop()).To(Equal(protocol.PacketNumber(12345)))
	})

	It("gets 1 as the first packet number", func() {
		num := png.Pop()
		Expect(num).To(Equal(protocol.PacketNumber(1)))
	})

	It("allows peeking", func() {
		png.nextToSkip = 1000
		Expect(png.Peek()).To(Equal(protocol.PacketNumber(1)))
		Expect(png.Peek()).To(Equal(protocol.PacketNumber(1)))
		num := png.Pop()
		Expect(num).To(Equal(protocol.PacketNumber(1)))
		Expect(png.Peek()).To(Equal(protocol.PacketNumber(2)))
		Expect(png.Peek()).To(Equal(protocol.PacketNumber(2)))
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
		png.nextToSkip = 2
		num := png.Pop()
		Expect(num).To(Equal(protocol.PacketNumber(1)))
		Expect(png.Peek()).To(Equal(protocol.PacketNumber(3)))
		num = png.Pop()
		Expect(num).To(Equal(protocol.PacketNumber(3)))
	})

	It("generates a new packet number to skip", func() {
		png.next = 100
		png.averagePeriod = 100

		rep := 5000
		var sum protocol.PacketNumber

		for i := 0; i < rep; i++ {
			png.generateNewSkip()
			Expect(png.nextToSkip).ToNot(Equal(protocol.PacketNumber(101)))
			sum += png.nextToSkip
		}

		average := sum / protocol.PacketNumber(rep)
		Expect(average).To(BeNumerically("==", protocol.PacketNumber(200), 4))
	})

	It("uses random numbers", func() {
		var smallest uint16 = math.MaxUint16
		var largest uint16
		var sum uint64

		rep := 10000

		for i := 0; i < rep; i++ {
			num := png.getRandomNumber()
			sum += uint64(num)
			if num > largest {
				largest = num
			}
			if num < smallest {
				smallest = num
			}
		}

		Expect(smallest).To(BeNumerically("<", 300))
		Expect(largest).To(BeNumerically(">", math.MaxUint16-300))
		Expect(sum / uint64(rep)).To(BeNumerically("==", uint64(math.MaxUint16/2), 1000))
	})

	It("validates ACK frames", func() {
		var skipped []protocol.PacketNumber
		var lastPN protocol.PacketNumber
		for len(skipped) < 3 {
			if png.Peek() > lastPN+1 {
				skipped = append(skipped, lastPN+1)
			}
			lastPN = png.Pop()
		}
		invalidACK := &wire.AckFrame{
			AckRanges: []wire.AckRange{{Smallest: 1, Largest: lastPN}},
		}
		Expect(png.Validate(invalidACK)).To(BeFalse())
		validACK1 := &wire.AckFrame{
			AckRanges: []wire.AckRange{{Smallest: 1, Largest: skipped[0] - 1}},
		}
		Expect(png.Validate(validACK1)).To(BeTrue())
		validACK2 := &wire.AckFrame{
			AckRanges: []wire.AckRange{
				{Smallest: 1, Largest: skipped[0] - 1},
				{Smallest: skipped[0] + 1, Largest: skipped[1] - 1},
				{Smallest: skipped[1] + 1, Largest: skipped[2] - 1},
				{Smallest: skipped[2] + 1, Largest: skipped[2] + 100},
			},
		}
		Expect(png.Validate(validACK2)).To(BeTrue())
	})

	It("tracks a maximum number of protocol.MaxTrackedSkippedPackets packets", func() {
		var skipped []protocol.PacketNumber
		var lastPN protocol.PacketNumber
		for len(skipped) < protocol.MaxTrackedSkippedPackets+3 {
			if png.Peek() > lastPN+1 {
				skipped = append(skipped, lastPN+1)
			}
			lastPN = png.Pop()
			Expect(len(png.history)).To(BeNumerically("<=", protocol.MaxTrackedSkippedPackets))
		}
		Expect(len(png.history)).To(Equal(protocol.MaxTrackedSkippedPackets))
	})
})
