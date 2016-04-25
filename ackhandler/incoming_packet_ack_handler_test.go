package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("incomingPacketAckHandler", func() {
	var (
		handler         *incomingPacketAckHandler
		expectedEntropy EntropyAccumulator
	)

	BeforeEach(func() {
		handler = NewIncomingPacketAckHandler().(*incomingPacketAckHandler)
		expectedEntropy = EntropyAccumulator(0)
	})

	Context("accepting and rejecting packets", func() {
		It("handles a packet that arrives late", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(3), false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			nackRanges, _ := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(0))
		})

		It("rejects a duplicate package with PacketNumber equal to LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(4, false)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ErrDuplicatePacket))
		})

		It("rejects a duplicate package with PacketNumber less than the LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(2, false)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ErrDuplicatePacket))
		})
	})

	Context("Entropy calculation", func() {
		It("calculates the entropy for continously received packets", func() {
			for i := 1; i < 100; i++ {
				entropyBit := false
				if i%3 == 0 || i%5 == 0 {
					entropyBit = true
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.highestInOrderObservedEntropy).To(Equal(expectedEntropy))
		})

		It("calculates the entropy if there is a NACK range", func() {
			for i := 1; i < 100; i++ {
				entropyBit := false
				if i%3 == 0 || i%5 == 0 {
					entropyBit = true
				}

				if i == 10 || i == 11 || i == 12 {
					continue
				}
				if i < 10 {
					expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.highestInOrderObservedEntropy).To(Equal(expectedEntropy))
		})
	})

	Context("NACK range calculation", func() {
		It("Returns no NACK ranges for continously received packets", func() {
			for i := 1; i < 100; i++ {
				entropyBit := false
				if i%2 == 0 {
					entropyBit = true
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(99)))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(99)))
			nackRanges, entropy := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(0))
			Expect(entropy).To(Equal(expectedEntropy))
		})

		It("handles a single lost package", func() {
			for i := 1; i < 10; i++ {
				entropyBit := true
				if i == 5 {
					continue
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
			nackRanges, entropy := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(1))
			Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(4)))
			Expect(entropy).To(Equal(expectedEntropy))
		})

		It("handles two consecutive lost packages", func() {
			for i := 1; i < 12; i++ {
				entropyBit := false
				if i%2 == 0 || i == 5 {
					entropyBit = true
				}
				if i == 5 || i == 6 {
					continue
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(11)))
			nackRanges, entropy := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(1))
			Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(6)))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(4)))
			Expect(entropy).To(Equal(expectedEntropy))
		})

		It("handles two non-consecutively lost packages", func() {
			for i := 1; i < 10; i++ {
				entropyBit := false
				if i%2 != 0 {
					entropyBit = true
				}
				if i == 3 || i == 7 {
					continue
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
			nackRanges, entropy := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(2))
			Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
			Expect(nackRanges[1].LastPacketNumber).To(Equal(protocol.PacketNumber(7)))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(2)))
			Expect(entropy).To(Equal(expectedEntropy))
		})

		It("handles two sequences of lost packages", func() {
			for i := 1; i < 10; i++ {
				entropyBit := true
				if i == 2 || i == 3 || i == 4 || i == 7 || i == 8 {
					continue
				}
				expectedEntropy.Add(protocol.PacketNumber(i), entropyBit)
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.largestObserved).To(Equal(protocol.PacketNumber(9)))
			nackRanges, entropy := handler.getNackRanges()
			Expect(len(nackRanges)).To(Equal(2))
			Expect(nackRanges[0].FirstPacketNumber).To(Equal(protocol.PacketNumber(2)))
			Expect(nackRanges[0].LastPacketNumber).To(Equal(protocol.PacketNumber(4)))
			Expect(nackRanges[1].FirstPacketNumber).To(Equal(protocol.PacketNumber(7)))
			Expect(nackRanges[1].LastPacketNumber).To(Equal(protocol.PacketNumber(8)))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(1)))
			Expect(entropy).To(Equal(expectedEntropy))
		})
	})

	Context("handling STOP_WAITING frames", func() {
		It("resets the entropy", func() {
			// We simulate 20 packets, numbers 10, 11 and 12 lost
			expectedAfterStopWaiting := EntropyAccumulator(0)
			for i := 1; i < 20; i++ {
				entropyBit := false
				if i%3 == 0 || i%5 == 0 {
					entropyBit = true
				}

				if i == 10 || i == 11 || i == 12 {
					continue
				}
				if i > 12 {
					expectedAfterStopWaiting.Add(protocol.PacketNumber(i), entropyBit)
				}
				err := handler.ReceivedPacket(protocol.PacketNumber(i), entropyBit)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{Entropy: 42, LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			_, e := handler.getNackRanges()
			Expect(e).To(Equal(42 ^ expectedAfterStopWaiting))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(12)))
			Expect(handler.highestInOrderObservedEntropy).To(Equal(EntropyAccumulator(42)))
		})

		It("does not emit nack ranges after STOP_WAITING", func() {
			err := handler.ReceivedPacket(10, false)
			Expect(err).ToNot(HaveOccurred())
			ranges, _ := handler.getNackRanges()
			Expect(ranges).To(HaveLen(1))
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{Entropy: 0, LeastUnacked: protocol.PacketNumber(9)})
			Expect(err).ToNot(HaveOccurred())
			ranges, _ = handler.getNackRanges()
			Expect(ranges).To(HaveLen(0))
		})
	})
})
