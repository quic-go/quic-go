package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHistory", func() {
	var (
		hist     *sentPacketHistory
		rttStats *utils.RTTStats
	)

	expectInHistory := func(packetNumbers []protocol.PacketNumber) {
		ExpectWithOffset(1, hist.packetMap).To(HaveLen(len(packetNumbers)))
		ExpectWithOffset(1, hist.packetList.Len()).To(Equal(len(packetNumbers)))
		i := 0
		err := hist.Iterate(func(p *Packet) (bool, error) {
			pn := packetNumbers[i]
			ExpectWithOffset(1, p.PacketNumber).To(Equal(pn))
			ExpectWithOffset(1, hist.packetMap[pn].Value.PacketNumber).To(Equal(pn))
			i++
			return true, nil
		})
		Expect(err).ToNot(HaveOccurred())
	}

	BeforeEach(func() {
		rttStats = utils.NewRTTStats()
		hist = newSentPacketHistory(rttStats)
	})

	It("saves sent packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		hist.SentPacket(&Packet{PacketNumber: 3}, true)
		hist.SentPacket(&Packet{PacketNumber: 4}, true)
		expectInHistory([]protocol.PacketNumber{1, 3, 4})
	})

	It("doesn't save non-ack-eliciting packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		hist.SentPacket(&Packet{PacketNumber: 3}, false)
		hist.SentPacket(&Packet{PacketNumber: 4}, true)
		expectInHistory([]protocol.PacketNumber{1, 4})
	})

	It("gets the length", func() {
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		hist.SentPacket(&Packet{PacketNumber: 10}, true)
		Expect(hist.Len()).To(Equal(2))
	})

	Context("getting the first outstanding packet", func() {
		It("gets nil, if there are no packets", func() {
			Expect(hist.FirstOutstanding()).To(BeNil())
		})

		It("gets the first outstanding packet", func() {
			hist.SentPacket(&Packet{PacketNumber: 2}, true)
			hist.SentPacket(&Packet{PacketNumber: 3}, true)
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})
	})

	It("removes packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		hist.SentPacket(&Packet{PacketNumber: 4}, true)
		hist.SentPacket(&Packet{PacketNumber: 8}, true)
		err := hist.Remove(4)
		Expect(err).ToNot(HaveOccurred())
		expectInHistory([]protocol.PacketNumber{1, 8})
	})

	It("errors when trying to remove a non existing packet", func() {
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		err := hist.Remove(2)
		Expect(err).To(MatchError("packet 2 not found in sent packet history"))
	})

	Context("iterating", func() {
		BeforeEach(func() {
			hist.SentPacket(&Packet{PacketNumber: 10}, true)
			hist.SentPacket(&Packet{PacketNumber: 14}, true)
			hist.SentPacket(&Packet{PacketNumber: 18}, true)
		})

		It("iterates over all packets", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return true, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14, 18}))
		})

		It("stops iterating", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return p.PacketNumber != 14, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})

		It("returns the error", func() {
			testErr := errors.New("test error")
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 14 {
					return false, testErr
				}
				return true, nil
			})).To(MatchError(testErr))
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})

		It("allows deletions", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 14 {
					Expect(hist.Remove(14)).To(Succeed())
				}
				return true, nil
			})).To(Succeed())
			expectInHistory([]protocol.PacketNumber{10, 18})
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14, 18}))
		})
	})

	Context("outstanding packets", func() {
		It("says if it has outstanding packets", func() {
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
			hist.SentPacket(&Packet{EncryptionLevel: protocol.Encryption1RTT}, true)
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
		})

		It("accounts for deleted packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			}, true)
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			Expect(hist.Remove(10)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("counts the number of packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			}, true)
			hist.SentPacket(&Packet{
				PacketNumber:    11,
				EncryptionLevel: protocol.Encryption1RTT,
			}, true)
			Expect(hist.Remove(11)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			Expect(hist.Remove(10)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})
	})

	Context("deleting old packets", func() {
		const pto = 3 * time.Second

		BeforeEach(func() {
			rttStats.UpdateRTT(time.Second, 0, time.Time{})
			Expect(rttStats.PTO(false)).To(Equal(pto))
		})

		It("deletes old packets after 3 PTOs", func() {
			now := time.Now()
			hist.SentPacket(&Packet{PacketNumber: 10, SendTime: now.Add(-3 * pto), declaredLost: true}, true)
			Expect(hist.Len()).To(Equal(1))
			hist.DeleteOldPackets(now.Add(-time.Nanosecond))
			Expect(hist.Len()).To(Equal(1))
			hist.DeleteOldPackets(now)
			Expect(hist.Len()).To(BeZero())
		})

		It("doesn't delete a packet if it hasn't been declared lost yet", func() {
			now := time.Now()
			hist.SentPacket(&Packet{PacketNumber: 10, SendTime: now.Add(-3 * pto), declaredLost: true}, true)
			hist.SentPacket(&Packet{PacketNumber: 11, SendTime: now.Add(-3 * pto), declaredLost: false}, true)
			Expect(hist.Len()).To(Equal(2))
			hist.DeleteOldPackets(now)
			Expect(hist.Len()).To(Equal(1))
		})
	})
})
