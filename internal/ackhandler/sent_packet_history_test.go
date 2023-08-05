package ackhandler

import (
	"errors"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHistory", func() {
	var hist *sentPacketHistory

	expectInHistory := func(expected []protocol.PacketNumber) {
		pns := make([]protocol.PacketNumber, 0, len(expected))
		for _, p := range hist.packets {
			if p != nil && !p.skippedPacket {
				pns = append(pns, p.PacketNumber)
			}
		}
		if len(expected) == 0 {
			Expect(pns).To(BeEmpty())
			return
		}
		Expect(pns).To(Equal(expected))
	}

	expectSkippedInHistory := func(expected []protocol.PacketNumber) {
		pns := make([]protocol.PacketNumber, 0, len(expected))
		for _, p := range hist.packets {
			if p != nil && p.skippedPacket {
				pns = append(pns, p.PacketNumber)
			}
		}
		if len(expected) == 0 {
			Expect(pns).To(BeEmpty())
			return
		}
		Expect(pns).To(Equal(expected))
	}

	BeforeEach(func() {
		hist = newSentPacketHistory()
	})

	It("saves sent packets", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
		expectInHistory([]protocol.PacketNumber{0, 1, 2})
		expectSkippedInHistory(nil)
	})

	It("saves non-ack-eliciting packets", func() {
		now := time.Now()
		hist.SentNonAckElicitingPacket(0)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1, SendTime: now})
		hist.SentNonAckElicitingPacket(2)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 3, SendTime: now})
		expectInHistory([]protocol.PacketNumber{1, 3})
	})

	It("saves sent packets, with skipped packet number", func() {
		hist.SkippedPacket(0)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SkippedPacket(2)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
		expectInHistory([]protocol.PacketNumber{1, 3, 4})
		expectSkippedInHistory([]protocol.PacketNumber{0, 2})
	})

	It("doesn't save non-ack-eliciting packets", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SkippedPacket(2)
		hist.SentNonAckElicitingPacket(3)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
		expectInHistory([]protocol.PacketNumber{1, 4})
	})

	It("gets the length", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
		Expect(hist.Len()).To(Equal(3))
	})

	Context("getting the first outstanding packet", func() {
		It("gets nil, if there are no packets", func() {
			Expect(hist.FirstOutstanding()).To(BeNil())
		})

		It("gets the first outstanding packet", func() {
			hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
			hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(2)))
			hist.Remove(2)
			front = hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(3)))
		})

		It("doesn't regard path MTU packets as outstanding", func() {
			hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
			hist.SkippedPacket(3)
			hist.SentAckElicitingPacket(&packet{PacketNumber: 4, IsPathMTUProbePacket: true})
			front := hist.FirstOutstanding()
			Expect(front).ToNot(BeNil())
			Expect(front.PacketNumber).To(Equal(protocol.PacketNumber(2)))
		})
	})

	It("removes packets", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 3})
		Expect(hist.Remove(2)).To(Succeed())
		expectInHistory([]protocol.PacketNumber{0, 1, 3})
	})

	It("also removes skipped packets before the removed packet", func() {
		hist.SkippedPacket(0)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SkippedPacket(2)
		hist.SkippedPacket(3)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
		expectSkippedInHistory([]protocol.PacketNumber{0, 2, 3})
		Expect(hist.Remove(4)).To(Succeed())
		expectSkippedInHistory([]protocol.PacketNumber{0})
		expectInHistory([]protocol.PacketNumber{1})
		Expect(hist.Remove(1)).To(Succeed())
		expectInHistory(nil)
		expectSkippedInHistory(nil)
	})

	It("panics on non-sequential packet number use", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 100})
		Expect(func() { hist.SentAckElicitingPacket(&packet{PacketNumber: 102}) }).To(Panic())
	})

	It("removes and adds packets", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		hist.SkippedPacket(2)
		hist.SkippedPacket(3)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
		hist.SkippedPacket(5)
		hist.SentAckElicitingPacket(&packet{PacketNumber: 6})
		Expect(hist.Remove(0)).To(Succeed())
		Expect(hist.Remove(1)).To(Succeed())
		hist.SentAckElicitingPacket(&packet{PacketNumber: 7})
		expectInHistory([]protocol.PacketNumber{4, 6, 7})
	})

	It("removes the last packet, then adds more", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 0})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		Expect(hist.Remove(0)).To(Succeed())
		Expect(hist.Remove(1)).To(Succeed())
		expectInHistory([]protocol.PacketNumber{})
		hist.SentAckElicitingPacket(&packet{PacketNumber: 2})
		expectInHistory([]protocol.PacketNumber{2})
		Expect(hist.Remove(2)).To(Succeed())
		expectInHistory(nil)
	})

	It("errors when trying to remove a non existing packet", func() {
		hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
		Expect(hist.Remove(2)).To(MatchError("packet 2 not found in sent packet history"))
	})

	Context("iterating", func() {
		BeforeEach(func() {
			hist.SkippedPacket(0)
			hist.SentAckElicitingPacket(&packet{PacketNumber: 1})
			hist.SkippedPacket(2)
			hist.SkippedPacket(3)
			hist.SentAckElicitingPacket(&packet{PacketNumber: 4})
			hist.SkippedPacket(5)
			hist.SkippedPacket(6)
			hist.SkippedPacket(7)
			hist.SentAckElicitingPacket(&packet{PacketNumber: 8})
		})

		It("iterates over all packets", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				return true, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 4, 8}))
		})

		It("also iterates over skipped packets", func() {
			var packets, skippedPackets, allPackets []protocol.PacketNumber
			Expect(hist.Iterate(func(p *packet) (bool, error) {
				if p.skippedPacket {
					skippedPackets = append(skippedPackets, p.PacketNumber)
				} else {
					packets = append(packets, p.PacketNumber)
				}
				allPackets = append(allPackets, p.PacketNumber)
				return true, nil
			})).To(Succeed())
			Expect(packets).To(Equal([]protocol.PacketNumber{1, 4, 8}))
			Expect(skippedPackets).To(Equal([]protocol.PacketNumber{0, 2, 3, 5, 6, 7}))
			Expect(allPackets).To(Equal([]protocol.PacketNumber{0, 1, 2, 3, 4, 5, 6, 7, 8}))
		})

		It("stops iterating", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *packet) (bool, error) {
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
			Expect(hist.Iterate(func(p *packet) (bool, error) {
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

		It("doesn't iterate over deleted packets", func() {
			hist.Remove(4)
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *packet) (bool, error) {
				if p.skippedPacket {
					return true, nil
				}
				iterations = append(iterations, p.PacketNumber)
				if p.PacketNumber == 4 {
					Expect(hist.Remove(4)).To(Succeed())
				}
				return true, nil
			})).To(Succeed())
			Expect(iterations).To(Equal([]protocol.PacketNumber{1, 8}))
		})

		It("allows deletions", func() {
			var iterations []protocol.PacketNumber
			Expect(hist.Iterate(func(p *packet) (bool, error) {
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
			hist.SentAckElicitingPacket(&packet{EncryptionLevel: protocol.Encryption1RTT, PacketNumber: 0})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
		})

		It("accounts for deleted packets", func() {
			hist.SentAckElicitingPacket(&packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			})
			Expect(hist.HasOutstandingPackets()).To(BeTrue())
			Expect(hist.Remove(10)).To(Succeed())
			Expect(hist.HasOutstandingPackets()).To(BeFalse())
		})

		It("counts the number of packets", func() {
			hist.SentAckElicitingPacket(&packet{
				PacketNumber:    10,
				EncryptionLevel: protocol.Encryption1RTT,
			})
			hist.SentAckElicitingPacket(&packet{
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
