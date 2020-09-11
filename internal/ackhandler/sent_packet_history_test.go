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
		var mapLen int
		for _, el := range hist.packetMap {
			if !el.Value.skippedPacket {
				mapLen++
			}
		}
		var listLen int
		for el := hist.packetList.Front(); el != nil; el = el.Next() {
			if !el.Value.skippedPacket {
				listLen++
			}
		}
		ExpectWithOffset(1, mapLen).To(Equal(len(packetNumbers)))
		ExpectWithOffset(1, listLen).To(Equal(len(packetNumbers)))
		i := 0
		err := hist.Iterate(func(p *Packet) (bool, error) {
			if p.skippedPacket {
				return true, nil
			}
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
		for el := hist.packetList.Front(); el != nil; el = el.Next() {
			Expect(el.Value.PacketNumber).ToNot(Equal(protocol.PacketNumber(3)))
		}
	})

	It("gets the length", func() {
		hist.SentPacket(&Packet{PacketNumber: 0}, true)
		hist.SentPacket(&Packet{PacketNumber: 1}, true)
		hist.SentPacket(&Packet{PacketNumber: 2}, true)
		Expect(hist.Len()).To(Equal(3))
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
			hist.SentPacket(&Packet{PacketNumber: 1}, true)
			hist.SentPacket(&Packet{PacketNumber: 4}, true)
			hist.SentPacket(&Packet{PacketNumber: 8}, true)
		})

		It("iterates over all packets", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				return true, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 4, 8}))
		})

		It("also iterates over skipped packets", func() {
			var packets, skippedPackets []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				if p.skippedPacket {
					skippedPackets = append(skippedPackets, p.PacketNumber)
				} else {
					packets = append(packets, p.PacketNumber)
				}
				return true, nil
			})).To(Succeed())
			Expect(packets).To(Equal([]protocol.PacketNumber{1, 4, 8}))
			Expect(skippedPackets).To(Equal([]protocol.PacketNumber{0, 2, 3, 5, 6, 7}))
		})

		It("stops iterating", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				return p.PacketNumber != 4, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 4}))
		})

		It("returns the error", func() {
			testErr := errors.New("test error")
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 4 {
					return false, testErr
				}
				return true, nil
			})).To(MatchError(testErr))
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 4}))
		})

		It("allows deletions", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *Packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 4 {
					Expect(hist.Remove(4)).To(Succeed())
				}
				return true, nil
			})).To(Succeed())
			expectInHistory([]protocol.PacketNumber{1, 8})
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 4, 8}))
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
			expectInHistory([]protocol.PacketNumber{10})
			hist.DeleteOldPackets(now.Add(-time.Nanosecond))
			expectInHistory([]protocol.PacketNumber{10})
			hist.DeleteOldPackets(now)
			expectInHistory([]protocol.PacketNumber{})
		})

		It("doesn't delete a packet if it hasn't been declared lost yet", func() {
			now := time.Now()
			hist.SentPacket(&Packet{PacketNumber: 10, SendTime: now.Add(-3 * pto), declaredLost: true}, true)
			hist.SentPacket(&Packet{PacketNumber: 11, SendTime: now.Add(-3 * pto), declaredLost: false}, true)
			expectInHistory([]protocol.PacketNumber{10, 11})
			hist.DeleteOldPackets(now)
			expectInHistory([]protocol.PacketNumber{11})
		})

		It("deletes skipped packets", func() {
			now := time.Now()
			hist.SentPacket(&Packet{PacketNumber: 10, SendTime: now.Add(-3 * pto)}, true)
			expectInHistory([]protocol.PacketNumber{10})
			Expect(hist.Len()).To(Equal(11))
			hist.DeleteOldPackets(now)
			expectInHistory([]protocol.PacketNumber{10}) // the packet was not declared lost
			Expect(hist.Len()).To(Equal(1))
		})
	})
})
