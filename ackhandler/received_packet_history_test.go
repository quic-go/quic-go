package ackhandler

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
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

	// check if the ranges PacketIntervalList contains exactly the same packet number as the receivedPacketNumbers
	historiesConsistent := func() bool {
		// check if a packet number is contained in any of the ranges
		containedInRanges := func(p protocol.PacketNumber) bool {
			for el := hist.ranges.Front(); el != nil; el = el.Next() {
				if p >= el.Value.Start && p <= el.Value.End {
					return true
				}
			}
			return false
		}

		// first check if all packets contained in the ranges are present in the map
		for el := hist.ranges.Front(); el != nil; el = el.Next() {
			for i := el.Value.Start; i <= el.Value.Start; i++ {
				_, ok := hist.receivedPacketNumbers[i]
				if !ok {
					return false
				}
			}
		}

		// then check if all packets in the map are contained in any of the ranges
		for i := range hist.receivedPacketNumbers {
			if !containedInRanges(i) {
				return false
			}
		}

		return true
	}

	Context("ranges", func() {
		It("adds the first packet", func() {
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("doesn't care about duplicate packets", func() {
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("adds a few consecutive packets", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("doesn't care about a duplicate packet contained in an existing range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("extends a range at the front", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(3)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 3, End: 4}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("creates a new range when a packet is lost", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
			Expect(historiesConsistent()).To(BeTrue())
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
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("creates a new range before an existing range for a belated packet", func() {
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 6}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("extends a previous range at the end", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(7)
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 5}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 7, End: 7}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("extends a range at the front", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(7)
			hist.ReceivedPacket(6)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 6, End: 7}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("closes a range", func() {
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(4)
			Expect(hist.ranges.Len()).To(Equal(2))
			hist.ReceivedPacket(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 6}))
			Expect(historiesConsistent()).To(BeTrue())
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
			Expect(historiesConsistent()).To(BeTrue())
		})
	})

	Context("deleting", func() {
		It("does nothing when the history is empty", func() {
			hist.DeleteUpTo(5)
			Expect(hist.ranges.Len()).To(BeZero())
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("deletes a range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteUpTo(5)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("deletes multiple ranges", func() {
			hist.ReceivedPacket(1)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteUpTo(8)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("adjusts a range, if packets are delete from an existing range", func() {
			hist.ReceivedPacket(3)
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(7)
			hist.DeleteUpTo(4)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 5, End: 7}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("adjusts a range, if only one packet remains in the range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(10)
			hist.DeleteUpTo(4)
			Expect(hist.ranges.Len()).To(Equal(2))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 5, End: 5}))
			Expect(hist.ranges.Back().Value).To(Equal(utils.PacketInterval{Start: 10, End: 10}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		It("keeps a one-packet range, if deleting up to the packet directly below", func() {
			hist.ReceivedPacket(4)
			hist.DeleteUpTo(3)
			Expect(hist.ranges.Len()).To(Equal(1))
			Expect(hist.ranges.Front().Value).To(Equal(utils.PacketInterval{Start: 4, End: 4}))
			Expect(historiesConsistent()).To(BeTrue())
		})

		Context("DoS protection", func() {
			It("doesn't create more than MaxTrackedReceivedAckRanges ranges", func() {
				for i := protocol.PacketNumber(1); i <= protocol.MaxTrackedReceivedAckRanges; i++ {
					err := hist.ReceivedPacket(2 * i)
					Expect(err).ToNot(HaveOccurred())
				}
				err := hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 2)
				Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
				Expect(historiesConsistent()).To(BeTrue())
			})

			It("doesn't store more than MaxTrackedReceivedPackets packets", func() {
				err := hist.ReceivedPacket(1)
				Expect(err).ToNot(HaveOccurred())
				for i := protocol.PacketNumber(3); i < 3+protocol.MaxTrackedReceivedPackets-1; i++ {
					err := hist.ReceivedPacket(protocol.PacketNumber(i))
					Expect(err).ToNot(HaveOccurred())
				}
				err = hist.ReceivedPacket(protocol.PacketNumber(protocol.MaxTrackedReceivedPackets) + 10)
				Expect(err).To(MatchError(errTooManyOutstandingReceivedPackets))
			})

			It("doesn't consider already deleted ranges for MaxTrackedReceivedAckRanges", func() {
				for i := protocol.PacketNumber(1); i <= protocol.MaxTrackedReceivedAckRanges; i++ {
					err := hist.ReceivedPacket(2 * i)
					Expect(err).ToNot(HaveOccurred())
				}
				err := hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 2)
				Expect(err).To(MatchError(errTooManyOutstandingReceivedAckRanges))
				hist.DeleteUpTo(protocol.MaxTrackedReceivedAckRanges) // deletes about half of the ranges
				err = hist.ReceivedPacket(2*protocol.MaxTrackedReceivedAckRanges + 4)
				Expect(err).ToNot(HaveOccurred())
				Expect(historiesConsistent()).To(BeTrue())
			})
		})
	})

	Context("duplicate packet detection", func() {
		It("detects duplicates for existing ranges", func() {
			hist.ReceivedPacket(2)
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			Expect(hist.IsDuplicate(1)).To(BeFalse())
			Expect(hist.IsDuplicate(2)).To(BeTrue())
			Expect(hist.IsDuplicate(3)).To(BeFalse())
			Expect(hist.IsDuplicate(4)).To(BeTrue())
			Expect(hist.IsDuplicate(5)).To(BeTrue())
			Expect(hist.IsDuplicate(6)).To(BeFalse())
		})

		It("detects duplicates after a range has been deleted", func() {
			hist.ReceivedPacket(2)
			hist.ReceivedPacket(3)
			hist.ReceivedPacket(6)
			hist.DeleteUpTo(4)
			for i := 1; i < 5; i++ {
				Expect(hist.IsDuplicate(protocol.PacketNumber(i))).To(BeTrue())
			}
			Expect(hist.IsDuplicate(5)).To(BeFalse())
			Expect(hist.IsDuplicate(6)).To(BeTrue())
			Expect(hist.IsDuplicate(7)).To(BeFalse())
		})
	})

	Context("ACK range export", func() {
		It("returns nil if there are no ranges", func() {
			Expect(hist.GetAckRanges()).To(BeNil())
		})

		It("gets a single ACK range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			ackRanges := hist.GetAckRanges()
			Expect(ackRanges).To(HaveLen(1))
			Expect(ackRanges[0]).To(Equal(wire.AckRange{FirstPacketNumber: 4, LastPacketNumber: 5}))
		})

		It("gets multiple ACK ranges", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(1)
			hist.ReceivedPacket(11)
			hist.ReceivedPacket(10)
			hist.ReceivedPacket(2)
			ackRanges := hist.GetAckRanges()
			Expect(ackRanges).To(HaveLen(3))
			Expect(ackRanges[0]).To(Equal(wire.AckRange{FirstPacketNumber: 10, LastPacketNumber: 11}))
			Expect(ackRanges[1]).To(Equal(wire.AckRange{FirstPacketNumber: 4, LastPacketNumber: 6}))
			Expect(ackRanges[2]).To(Equal(wire.AckRange{FirstPacketNumber: 1, LastPacketNumber: 2}))
		})
	})

	Context("Getting the highest ACK range", func() {
		It("returns the zero value if there are no ranges", func() {
			Expect(hist.GetHighestAckRange()).To(BeZero())
		})

		It("gets a single ACK range", func() {
			hist.ReceivedPacket(4)
			hist.ReceivedPacket(5)
			Expect(hist.GetHighestAckRange()).To(Equal(wire.AckRange{FirstPacketNumber: 4, LastPacketNumber: 5}))
		})

		It("gets the highest of multiple ACK ranges", func() {
			hist.ReceivedPacket(3)
			hist.ReceivedPacket(6)
			hist.ReceivedPacket(7)
			Expect(hist.GetHighestAckRange()).To(Equal(wire.AckRange{FirstPacketNumber: 6, LastPacketNumber: 7}))
		})
	})
})
