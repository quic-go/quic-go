package ackhandlernew

import (
	"github.com/lucas-clemente/quic-go/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHistory", func() {
	var (
		hist *receivedPacketHistory
	)

	BeforeEach(func() {
		hist = newReceivedPacketHistory()
	})

	It("adds the first packet", func() {
		hist.ReceivedPacket(4)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
	})

	It("doesn't care about duplicate packets", func() {
		hist.ReceivedPacket(4)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
	})

	It("adds a few consecutive packets", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(5)
		hist.ReceivedPacket(6)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
	})

	It("doesn't care about a duplicate packet contained in an existing range", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(5)
		hist.ReceivedPacket(6)
		hist.ReceivedPacket(5)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
	})

	It("extends a range at the front", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(3)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 3, End: 4}))
	})

	It("creates a new range when a packet is lost", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(6)
		Expect(hist.ranges.Len()).To(Equal(2))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
	})

	It("creates a new range in between two ranges", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(10)
		Expect(hist.ranges.Len()).To(Equal(2))
		hist.ReceivedPacket(7)
		Expect(hist.ranges.Len()).To(Equal(3))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		Expect(hist.ranges.Front().Next().Value).To(Equal(utils.PacketInterval{Start: 7, End: 7}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
	})

	It("creates a new range before an existing range for a belated packet", func() {
		hist.ReceivedPacket(6)
		hist.ReceivedPacket(4)
		Expect(hist.ranges.Len()).To(Equal(2))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
	})

	It("extends a previous range at the end", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(7)
		hist.ReceivedPacket(5)
		Expect(hist.ranges.Len()).To(Equal(2))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 5}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 7, End: 7}))
	})

	It("extends a range at the front", func() {
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(7)
		hist.ReceivedPacket(6)
		Expect(hist.ranges.Len()).To(Equal(2))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 7}))
	})

	It("closes a range", func() {
		hist.ReceivedPacket(6)
		hist.ReceivedPacket(4)
		Expect(hist.ranges.Len()).To(Equal(2))
		hist.ReceivedPacket(5)
		Expect(hist.ranges.Len()).To(Equal(1))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
	})

	It("closes a range in the middle", func() {
		hist.ReceivedPacket(1)
		hist.ReceivedPacket(10)
		hist.ReceivedPacket(4)
		hist.ReceivedPacket(6)
		Expect(hist.ranges.Len()).To(Equal(4))
		hist.ReceivedPacket(5)
		Expect(hist.ranges.Len()).To(Equal(3))
		Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 1, End: 1}))
		Expect(hist.ranges.Front().Next().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
		Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
	})
})
