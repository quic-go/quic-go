package congestion

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
)

var _ = Describe("PacketNumber indexed queue", func() {
	var (
		queue       *packetNumberIndexedQueue[string]
		strZero     string = "zero"
		strOne      string = "one"
		strOneKinda string = "one (kinda)"
		strTwo      string = "two"
		strThree    string = "three"
		strFour     string = "four"
	)

	BeforeEach(func() {
		queue = newPacketNumberIndexedQueue[string](1)
	})

	It("InitialState", func() {
		Expect(queue.IsEmpty()).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.InvalidPacketNumber))
		Expect(queue.LastPacket()).To(Equal(protocol.InvalidPacketNumber))
		Expect(queue.NumberOfPresentEntries()).To(Equal(0))
		Expect(queue.EntrySlotsUsed()).To(Equal(0))
	})

	It("InsertingContinuousElements", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1001))).To(Equal(&strOne))

		Expect(queue.Emplace(protocol.PacketNumber(1002), &strTwo)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1002))).To(Equal(&strTwo))

		Expect(queue.IsEmpty()).To(BeFalse())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(1002)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))
		Expect(queue.EntrySlotsUsed()).To(Equal(2))
	})

	It("InsertingOutOfOrder", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())

		Expect(queue.Emplace(protocol.PacketNumber(1003), &strThree)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1002))).To(BeNil())
		Expect(queue.GetEntry(protocol.PacketNumber(1003))).To(Equal(&strThree))

		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(1003)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))
		Expect(queue.EntrySlotsUsed()).To(Equal(3))

		Expect(queue.Emplace(protocol.PacketNumber(1002), &strTwo)).To(BeFalse())
	})

	It("InsertingIntoPast", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())

		Expect(queue.Emplace(protocol.PacketNumber(1001), &strZero)).To(BeFalse())
	})

	It("InsertingDuplicate", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeFalse())
	})

	It("RemoveInTheMiddle", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1002), &strTwo)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1003), &strThree)).To(BeTrue())

		Expect(queue.Remove(protocol.PacketNumber(1002), nil)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1002))).To(BeNil())

		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(1003)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))
		Expect(queue.EntrySlotsUsed()).To(Equal(3))
	})

	It("RemoveAtImmediateEdges", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1002), &strTwo)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1003), &strThree)).To(BeTrue())

		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1001))).To(BeNil())
		Expect(queue.Remove(protocol.PacketNumber(1003), nil)).To(BeTrue())
		Expect(queue.GetEntry(protocol.PacketNumber(1003))).To(BeNil())

		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1002)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(1003)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(1))
		Expect(queue.EntrySlotsUsed()).To(Equal(2))

		Expect(queue.Emplace(protocol.PacketNumber(1004), &strFour)).To(BeTrue())
	})

	It("RemoveAtDistantFront", func() {

		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(1002), &strOneKinda)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(2001), &strTwo)).To(BeTrue())

		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(3))
		Expect(queue.EntrySlotsUsed()).To(Equal(1001))

		Expect(queue.Remove(protocol.PacketNumber(1002), nil)).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))
		Expect(queue.EntrySlotsUsed()).To(Equal(1001))

		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(1))
		Expect(queue.EntrySlotsUsed()).To(Equal(1))
	})

	It("RemoveAtDistantBack", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(2001), &strTwo)).To(BeTrue())

		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(2001)))

		Expect(queue.Remove(protocol.PacketNumber(2001), nil)).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(2001)))
	})

	It("ClearAndRepopulate", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(2001), &strTwo)).To(BeTrue())

		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeTrue())
		Expect(queue.Remove(protocol.PacketNumber(2001), nil)).To(BeTrue())
		Expect(queue.IsEmpty()).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.InvalidPacketNumber))
		Expect(queue.LastPacket()).To(Equal(protocol.InvalidPacketNumber))

		Expect(queue.Emplace(protocol.PacketNumber(101), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(201), &strTwo)).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(101)))
		Expect(queue.LastPacket()).To(Equal(protocol.PacketNumber(201)))
	})

	It("FailToRemoveElementsThatNeverExisted", func() {
		Expect(queue.Remove(protocol.PacketNumber(1000), nil)).To(BeFalse())
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Remove(protocol.PacketNumber(1000), nil)).To(BeFalse())
		Expect(queue.Remove(protocol.PacketNumber(1002), nil)).To(BeFalse())
	})

	It("FailToRemoveElementsTwice", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeTrue())
		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeFalse())
		Expect(queue.Remove(protocol.PacketNumber(1001), nil)).To(BeFalse())
	})

	It("RemoveUpTo", func() {
		Expect(queue.Emplace(protocol.PacketNumber(1001), &strOne)).To(BeTrue())
		Expect(queue.Emplace(protocol.PacketNumber(2001), &strTwo)).To(BeTrue())
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))

		queue.RemoveUpTo(protocol.PacketNumber(1001))
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(1001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(2))

		// Remove up to 1100, since [1100, 2001) are !present, they should be cleaned
		// up from the front.
		queue.RemoveUpTo(protocol.PacketNumber(1100))
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(1))

		queue.RemoveUpTo(protocol.PacketNumber(2001))
		Expect(queue.FirstPacket()).To(Equal(protocol.PacketNumber(2001)))
		Expect(queue.NumberOfPresentEntries()).To(Equal(1))

		queue.RemoveUpTo(protocol.PacketNumber(2002))
		Expect(queue.FirstPacket()).To(Equal(protocol.InvalidPacketNumber))
		Expect(queue.NumberOfPresentEntries()).To(Equal(0))
	})
})
