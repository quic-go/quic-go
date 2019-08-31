package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHistory", func() {
	var hist *sentPacketHistory

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
		hist = newSentPacketHistory()
	})

	It("saves sent packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 3})
		hist.SentPacket(&Packet{PacketNumber: 4})
		expectInHistory([]protocol.PacketNumber{1, 3, 4})
	})

	It("gets the length", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 10})
		Expect(hist.Len()).To(Equal(2))
	})

	Context("getting the first outstanding packet", func() {
		It("gets nil, if there are no packets", func() {
			Expect(hist.FirstOutstanding()).To(BeNil())
		})

		It("gets the first outstanding packet", func() {
			hist.SentPacket(&Packet{PacketNumber: 2})
			hist.SentPacket(&Packet{PacketNumber: 3})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})
	})

	It("gets a packet by packet number", func() {
		p := &Packet{PacketNumber: 2}
		hist.SentPacket(p)
		Expect(hist.GetPacket(2)).To(Equal(p))
	})

	It("returns nil if the packet doesn't exist", func() {
		Expect(hist.GetPacket(1337)).To(BeNil())
	})

	It("removes packets", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		hist.SentPacket(&Packet{PacketNumber: 4})
		hist.SentPacket(&Packet{PacketNumber: 8})
		err := hist.Remove(4)
		Expect(err).ToNot(HaveOccurred())
		expectInHistory([]protocol.PacketNumber{1, 8})
	})

	It("errors when trying to remove a non existing packet", func() {
		hist.SentPacket(&Packet{PacketNumber: 1})
		err := hist.Remove(2)
		Expect(err).To(MatchError("packet 2 not found in sent packet history"))
	})

	Context("iterating", func() {
		BeforeEach(func() {
			hist.SentPacket(&Packet{PacketNumber: 10})
			hist.SentPacket(&Packet{PacketNumber: 14})
			hist.SentPacket(&Packet{PacketNumber: 18})
		})

		It("iterates over all packets", func() {
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return true, nil
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14, 18}))
		})

		It("stops iterating", func() {
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				return p.PacketNumber != 14, nil
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})

		It("returns the error", func() {
			testErr := errors.New("test error")
			var iterations []protocol.PacketNumber
			err := hist.Iterate(func(p *Packet) (bool, error) {
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 14 {
					return false, testErr
				}
				return true, nil
			})
			Expect(err).To(MatchError(testErr))
			Expect(iterations).To(Equal([]protocol.PacketNumber{10, 14}))
		})
	})

	Context("outstanding packets", func() {
		It("says if it has outstanding packets", func() {
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
			hist.SentPacket(&Packet{EncryptionLevel: protocol.Encryption1RTT})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
		})

		It("accounts for deleted packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			Expect(hist.Remove(10)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("counts the number of packets", func() {
			hist.SentPacket(&Packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			})
			hist.SentPacket(&Packet{
				PacketNumber:    11,
				EncryptionLevel: protocol.Encryption1RTT,
			})
			Expect(hist.Remove(11)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			Expect(hist.Remove(10)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})
	})
})
