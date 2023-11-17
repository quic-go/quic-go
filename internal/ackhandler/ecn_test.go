package ackhandler

import (
	mocklogging "github.com/Psiphon-Labs/quic-go/internal/mocks/logging"
	"github.com/Psiphon-Labs/quic-go/internal/protocol"
	"github.com/Psiphon-Labs/quic-go/internal/utils"
	"github.com/Psiphon-Labs/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ECN tracker", func() {
	var ecnTracker *ecnTracker
	var tracer *mocklogging.MockConnectionTracer

	getAckedPackets := func(pns ...protocol.PacketNumber) []*packet {
		var packets []*packet
		for _, p := range pns {
			packets = append(packets, &packet{PacketNumber: p})
		}
		return packets
	}

	BeforeEach(func() {
		var tr *logging.ConnectionTracer
		tr, tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		ecnTracker = newECNTracker(utils.DefaultLogger, tr)
	})

	It("sends exactly 10 testing packets", func() {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
		for i := 0; i < 9; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			// Do this twice to make sure only sent packets are counted
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(10+i), protocol.ECT0)
		}
		Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
		ecnTracker.SentPacket(20, protocol.ECT0)
		// In unknown state, packets shouldn't be ECN-marked.
		Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
	})

	sendAllTestingPackets := func() {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
		for i := 0; i < 10; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
		}
	}

	It("fails ECN validation if all ECN testing packets are lost", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		for i := 0; i < 9; i++ {
			ecnTracker.LostPacket(protocol.PacketNumber(i))
		}
		// We don't care about the loss of non-testing packets
		ecnTracker.LostPacket(15)
		// Now lose the last testing packet.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedLostAllTestingPackets)
		ecnTracker.LostPacket(9)
		Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
		// We still don't care about more non-testing packets being lost
		ecnTracker.LostPacket(16)
	})

	It("only detects ECN mangling after sending all testing packets", func() {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
		for i := 0; i < 9; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
			ecnTracker.LostPacket(protocol.PacketNumber(i))
		}
		// Send the last testing packet, and receive a
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
		ecnTracker.SentPacket(9, protocol.ECT0)
		// Now lose the last testing packet.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedLostAllTestingPackets)
		ecnTracker.LostPacket(9)
	})

	It("passes ECN validation when a testing packet is acknowledged, while still in testing state", func() {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
		for i := 0; i < 5; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
		}
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(3), 1, 0, 0)).To(BeFalse())
		// make sure we continue sending ECT(0) packets
		for i := 5; i < 100; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
		}
	})

	It("passes ECN validation when a testing packet is acknowledged, while in unknown state", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// Lose some packets to make sure this doesn't influence the outcome.
		for i := 0; i < 5; i++ {
			ecnTracker.LostPacket(protocol.PacketNumber(i))
		}
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked([]*packet{{PacketNumber: 7}}, 1, 0, 0)).To(BeFalse())
	})

	It("fails ECN validation when the ACK contains more ECN counts than we sent packets", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// only 10 ECT(0) packets were sent, but the ACK claims to have received 12 of them
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedMoreECNCountsThanSent)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 12, 0, 0)).To(BeFalse())
	})

	It("fails ECN validation when the ACK contains ECN counts for the wrong code point", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// We sent ECT(0), but this ACK acknowledges ECT(1).
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedMoreECNCountsThanSent)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 0, 1, 0)).To(BeFalse())
	})

	It("fails ECN validation when the ACK doesn't contain ECN counts", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// First only acknowledge packets sent without ECN marks.
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(12, 13, 14), 0, 0, 0)).To(BeFalse())
		// Now acknowledge some packets sent with ECN marks.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedNoECNCounts)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 15), 0, 0, 0)).To(BeFalse())
	})

	It("fails ECN validation when an ACK decreases ECN counts", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 3, 0, 0)).To(BeFalse())
		// Now acknowledge some more packets, but decrease the ECN counts. Obviously, this doesn't make any sense.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedDecreasedECNCounts)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 2, 0, 0)).To(BeFalse())
		// make sure that new ACKs are ignored
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 5, 0, 0)).To(BeFalse())
	})

	// This can happen if ACK are lost / reordered.
	It("doesn't fail validation if the ACK contains more ECN counts than it acknowledges packets", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 8, 0, 0)).To(BeFalse())
	})

	It("fails ECN validation when the ACK doesn't contain enough ECN counts", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// First only acknowledge some packets sent with ECN marks.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1)).To(BeTrue())
		// Now acknowledge some more packets sent with ECN marks, but don't increase the counters enough.
		// This ACK acknowledges 3 more ECN-marked packets, but the counters only increase by 2.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedTooFewECNCounts)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 15), 3, 0, 2)).To(BeFalse())
	})

	It("detects ECN mangling if all testing packets are marked CE", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3), 0, 0, 4)).To(BeFalse())
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 10, 11, 12), 0, 0, 7)).To(BeFalse())
		// With the next ACK, all testing packets will now have been marked CE.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 13), 0, 0, 10)).To(BeFalse())
	})

	It("only detects ECN mangling after sending all testing packets", func() {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
		for i := 0; i < 9; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
			Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(protocol.PacketNumber(i)), 0, 0, int64(i+1))).To(BeFalse())
		}
		// Send the last testing packet, and receive a
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.Mode()).To(Equal(protocol.ECT0))
		ecnTracker.SentPacket(9, protocol.ECT0)
		// This ACK now reports the last testing packets as CE as well.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(9), 0, 0, 10)).To(BeFalse())
	})

	It("detects ECN mangling, if some testing packets are marked CE, and then others are lost", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3), 0, 0, 4)).To(BeFalse())
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(6, 7, 8, 9), 0, 0, 8)).To(BeFalse())
		// Lose one of the two unacknowledged packets.
		ecnTracker.LostPacket(4)
		// By losing the last unacknowledged testing packets, we should detect the mangling.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
		ecnTracker.LostPacket(5)
	})

	It("detects ECN mangling, if some testing packets are lost, and then others are marked CE", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// Lose a few packets.
		ecnTracker.LostPacket(0)
		ecnTracker.LostPacket(1)
		ecnTracker.LostPacket(2)
		// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(3, 4, 5, 6, 7, 8), 0, 0, 6)).To(BeFalse())
		// By CE-marking the last unacknowledged testing packets, we should detect the mangling.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(9), 0, 0, 7)).To(BeFalse())
	})

	It("declares congestion", func() {
		sendAllTestingPackets()
		for i := 10; i < 20; i++ {
			Expect(ecnTracker.Mode()).To(Equal(protocol.ECNNon))
			ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
		}
		// Receive one CE count.
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1)).To(BeTrue())
		// No increase in CE. No congestion.
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 5, 0, 1)).To(BeFalse())
		// Increase in CE. More congestion.
		Expect(ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 7, 0, 2)).To(BeTrue())
	})
})
