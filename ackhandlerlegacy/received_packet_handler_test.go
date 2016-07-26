package ackhandlerlegacy

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("receivedPacketHandler", func() {
	var (
		handler         *receivedPacketHandler
		expectedEntropy EntropyAccumulator
	)

	BeforeEach(func() {
		handler = NewReceivedPacketHandler().(*receivedPacketHandler)
		expectedEntropy = EntropyAccumulator(0)
	})

	Context("accepting packets", func() {
		It("handles a packet that arrives late", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(1)))
			err = handler.ReceivedPacket(protocol.PacketNumber(3), false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			err = handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
		})

		It("rejects packets with packet number 0", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(0), false)
			Expect(err).To(MatchError(errInvalidPacketNumber))
		})

		It("rejects a duplicate package with PacketNumber equal to LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(4, false)
			Expect(err).To(MatchError(ErrDuplicatePacket))
		})

		It("rejects a duplicate package with PacketNumber less than the LargestObserved", func() {
			for i := 1; i < 5; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(2, false)
			Expect(err).To(MatchError(ErrDuplicatePacket))
		})

		It("ignores a packet with PacketNumber less than the LeastUnacked of a previously received StopWaiting", func() {
			err := handler.ReceivedPacket(5, false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(9, false)
			Expect(err).To(MatchError(ErrPacketSmallerThanLastStopWaiting))
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(9)))
		})

		It("does not ignore a packet with PacketNumber equal to LeastUnacked of a previously received StopWaiting", func() {
			err := handler.ReceivedPacket(5, false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(10, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(10)))
		})

		It("saves the time when each packet arrived", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(3), false)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(3)))
			Expect(handler.packetHistory[3].TimeReceived).To(BeTemporally("~", time.Now(), 10*time.Millisecond))
		})

		It("doesn't store more than MaxTrackedReceivedPackets packets", func() {
			for i := uint32(0); i < protocol.MaxTrackedReceivedPackets; i++ {
				packetNumber := protocol.PacketNumber(1 + 2*i)
				err := handler.ReceivedPacket(packetNumber, true)
				Expect(err).ToNot(HaveOccurred())
			}
			err := handler.ReceivedPacket(protocol.PacketNumber(3*protocol.MaxTrackedReceivedPackets), true)
			Expect(err).To(MatchError(errTooManyOutstandingReceivedPackets))
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
			Expect(nackRanges).To(BeEmpty())
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
			Expect(nackRanges).To(HaveLen(1))
			Expect(nackRanges[0]).To(Equal(frames.NackRange{FirstPacketNumber: 5, LastPacketNumber: 5}))
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
			Expect(nackRanges).To(HaveLen(1))
			Expect(nackRanges[0]).To(Equal(frames.NackRange{FirstPacketNumber: 5, LastPacketNumber: 6}))
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
			Expect(nackRanges).To(HaveLen(2))
			Expect(nackRanges[0]).To(Equal(frames.NackRange{FirstPacketNumber: 7, LastPacketNumber: 7}))
			Expect(nackRanges[1]).To(Equal(frames.NackRange{FirstPacketNumber: 3, LastPacketNumber: 3}))
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
			Expect(nackRanges).To(HaveLen(2))
			Expect(nackRanges[0]).To(Equal(frames.NackRange{FirstPacketNumber: 7, LastPacketNumber: 8}))
			Expect(nackRanges[1]).To(Equal(frames.NackRange{FirstPacketNumber: 2, LastPacketNumber: 4}))
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
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(11)))
			Expect(handler.highestInOrderObservedEntropy).To(Equal(EntropyAccumulator(42)))
		})

		It("does not emit NACK ranges after STOP_WAITING", func() {
			err := handler.ReceivedPacket(10, false)
			Expect(err).ToNot(HaveOccurred())
			ranges, _ := handler.getNackRanges()
			Expect(ranges).To(HaveLen(1))
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{Entropy: 0, LeastUnacked: protocol.PacketNumber(10)})
			Expect(err).ToNot(HaveOccurred())
			ranges, _ = handler.getNackRanges()
			Expect(ranges).To(BeEmpty())
		})

		It("increases the ignorePacketsBelow number", func() {
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})

		It("increase the ignorePacketsBelow number, even if all packets below the LeastUnacked were already acked", func() {
			for i := 1; i < 20; i++ {
				err := handler.ReceivedPacket(protocol.PacketNumber(i), false)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(handler.highestInOrderObserved).To(Equal(protocol.PacketNumber(19)))
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})

		It("does not decrease the ignorePacketsBelow number when an out-of-order StopWaiting arrives", func() {
			err := handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(12)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
			err = handler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: protocol.PacketNumber(6)})
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ignorePacketsBelow).To(Equal(protocol.PacketNumber(11)))
		})
	})

	Context("ACK package generation", func() {
		It("generates a simple ACK frame", func() {
			entropy := EntropyAccumulator(0)
			entropy.Add(1, true)
			entropy.Add(2, true)
			err := handler.ReceivedPacket(protocol.PacketNumber(1), true)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2), true)
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.LargestObserved).To(Equal(protocol.PacketNumber(2)))
			Expect(ack.AckFrameLegacy.Entropy).To(Equal(byte(entropy)))
		})

		It("generates an ACK frame with a NACK range", func() {
			entropy := EntropyAccumulator(0)
			entropy.Add(1, true)
			entropy.Add(4, true)
			err := handler.ReceivedPacket(protocol.PacketNumber(1), true)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(4), true)
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.LargestObserved).To(Equal(protocol.PacketNumber(4)))
			Expect(ack.AckFrameLegacy.Entropy).To(Equal(byte(entropy)))
			Expect(ack.AckFrameLegacy.NackRanges).To(Equal([]frames.NackRange{{FirstPacketNumber: 2, LastPacketNumber: 3}}))
		})

		It("does not generate an ACK if an ACK has already been sent for the largest Packet", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(true)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).To(BeNil())
		})

		It("does not dequeue an ACK frame if told so", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack, err = handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
		})

		It("returns a cached ACK frame if the ACK was not dequeued", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			ack, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack).ToNot(BeNil())
			ack2, err := handler.GetAckFrame(false)
			Expect(err).ToNot(HaveOccurred())
			Expect(ack2).ToNot(BeNil())
			Expect(&ack).To(Equal(&ack2))
		})

		It("generates a new ACK (and deletes the cached one) when a new packet arrives", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
			Expect(err).ToNot(HaveOccurred())
			ack, _ := handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.LargestObserved).To(Equal(protocol.PacketNumber(1)))
			err = handler.ReceivedPacket(protocol.PacketNumber(3), false)
			Expect(err).ToNot(HaveOccurred())
			ack, _ = handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.LargestObserved).To(Equal(protocol.PacketNumber(3)))
		})

		It("generates a new ACK when an out-of-order packet arrives", func() {
			err := handler.ReceivedPacket(protocol.PacketNumber(1), false)
			Expect(err).ToNot(HaveOccurred())
			err = handler.ReceivedPacket(protocol.PacketNumber(3), false)
			Expect(err).ToNot(HaveOccurred())
			ack, _ := handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.NackRanges).To(HaveLen(1))
			err = handler.ReceivedPacket(protocol.PacketNumber(2), false)
			Expect(err).ToNot(HaveOccurred())
			ack, _ = handler.GetAckFrame(true)
			Expect(ack).ToNot(BeNil())
			Expect(ack.AckFrameLegacy).ToNot(BeNil())
			Expect(ack.AckFrameLegacy.NackRanges).To(BeEmpty())
		})
	})

	Context("Garbage Collector", func() {
		It("only keeps packets with packet numbers higher than the highestInOrderObserved in packetHistory", func() {
			handler.ReceivedPacket(1, true)
			handler.ReceivedPacket(2, true)
			handler.ReceivedPacket(4, true)
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
		})

		It("garbage collects packetHistory after receiving a StopWaiting", func() {
			handler.ReceivedPacket(1, true)
			handler.ReceivedPacket(2, true)
			handler.ReceivedPacket(4, true)
			swf := frames.StopWaitingFrame{LeastUnacked: 4}
			handler.ReceivedStopWaiting(&swf)
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(1)))
			Expect(handler.packetHistory).ToNot(HaveKey(protocol.PacketNumber(2)))
			Expect(handler.packetHistory).To(HaveKey(protocol.PacketNumber(4)))
		})
	})
})
