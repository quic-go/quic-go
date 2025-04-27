package ackhandler

import (
	"testing"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func getAckedPackets(pns ...protocol.PacketNumber) []*packet {
	var packets []*packet
	for _, p := range pns {
		packets = append(packets, &packet{PacketNumber: p})
	}
	return packets
}

// sendECNTestingPackets sends 10 ECT(0) packets, and then one more packet
// Packet numbers: 0 through 9.
func sendECNTestingPackets(t *testing.T, ecnTracker *ecnTracker, tracer *mocklogging.MockConnectionTracer) {
	t.Helper()

	tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
	for i := range protocol.PacketNumber(9) {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		// do this twice to make sure only sent packets are counted
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(i, protocol.ECT0)
	}
	require.Equal(t, protocol.ECT0, ecnTracker.Mode())
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
	ecnTracker.SentPacket(9, protocol.ECT0)
	// in unknown state, packets shouldn't be ECN-marked
	require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
}

// ECN validation fails if *all* ECN testing packets are lost.
func TestECNTestingPacketsLoss(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)

	// send non-testing packets
	for i := range protocol.PacketNumber(10) {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(10+i, protocol.ECNNon)
	}

	// lose all but one packet
	for pn := range protocol.PacketNumber(10) {
		if pn == 4 {
			continue
		}
		ecnTracker.LostPacket(pn)
	}
	// loss of non-testing packets doesn't matter
	ecnTracker.LostPacket(13)
	ecnTracker.LostPacket(14)

	// now lose the last testing packet
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedLostAllTestingPackets)
	ecnTracker.LostPacket(4)
}

// ECN support is validated once an acknowledgment for any testing packet is received.
// This applies even if that happens before all testing packets have been sent out.
func TestECNValidationInTestingState(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
	for i := range 5 {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
	}
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(3), 1, 0, 0))
	// make sure we continue sending ECT(0) packets
	for i := 5; i < 100; i++ {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
	}
}

// ENC is also validated after all testing packets have been sent out,
// once an acknowledgment for any testing packet is received.
func TestECNValidationInUnknownState(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)

	for i := range protocol.PacketNumber(10) {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		pn := 10 + i
		ecnTracker.SentPacket(pn, protocol.ECNNon)
		// lose some packets to make sure this doesn't influence the outcome.
		if i%2 == 0 {
			ecnTracker.LostPacket(pn)
		}
	}
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7), 1, 0, 0))
}

func TestECNValidationFailures(t *testing.T) {
	t.Run("ECN bleaching", func(t *testing.T) {
		// this ACK doesn't contain any ECN counts
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 0, 0, 0, logging.ECNFailedNoECNCounts)
	})

	t.Run("wrong ECN code point", func(t *testing.T) {
		// we sent ECT(0), but this ACK acknowledges ECT(1)
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 0, 1, 0, logging.ECNFailedMoreECNCountsThanSent)
	})

	t.Run("more ECN counts than sent packets", func(t *testing.T) {
		// only 10 ECT(0) packets were sent, but the ACK claims to have received 12 of them
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 12, 0, 0, logging.ECNFailedMoreECNCountsThanSent)
	})
}

func testECNValidationFailure(t *testing.T, ackedPackets []*packet, ect0, ect1, ecnce int64, expectedTrigger logging.ECNStateTrigger) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}

	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, expectedTrigger)
	require.False(t, ecnTracker.HandleNewlyAcked(ackedPackets, ect0, ect1, ecnce))
}

func TestECNValidationNotEnoughECNCounts(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	// First only acknowledge some packets sent with ECN marks.
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1))
	// Now acknowledge some more packets sent with ECN marks, but don't increase the counters enough.
	// This ACK acknowledges 3 more ECN-marked packets, but the counters only increase by 2.
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedTooFewECNCounts)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 15), 3, 0, 2))
}

func TestECNNonsensicalECNCountDecrease(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 3, 0, 0))
	// Now acknowledge some more packets, but decrease the ECN counts. Obviously, this doesn't make any sense.
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedDecreasedECNCounts)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 2, 0, 0))
	// make sure that new ACKs are ignored
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 5, 0, 0))
}

func TestECNACKReordering(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	// The ACK contains more ECN counts than it acknowledges packets.
	// This can happen if ACKs are lost / reordered.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 8, 0, 0))
}

// Mangling is detected if all testing packets are marked CE.
func TestECNManglingAllPacketsMarkedCE(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3), 0, 0, 4))
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 10, 11, 12), 0, 0, 7))
	// With the next ACK, all testing packets will now have been marked CE.
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 13), 0, 0, 10))
}

// Mangling is also detected if some testing packets are lost, and then others are marked CE.
func TestECNManglingSomePacketsLostSomeMarkedCE(t *testing.T) {
	t.Run("packet loss first", func(t *testing.T) {
		testECNManglingSomePacketsLostSomeMarkedCE(t, true)
	})
	t.Run("CE marking first", func(t *testing.T) {
		testECNManglingSomePacketsLostSomeMarkedCE(t, false)
	})
}

func testECNManglingSomePacketsLostSomeMarkedCE(t *testing.T, packetLossFirst bool) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	// Lose a few packets.
	if packetLossFirst {
		ecnTracker.LostPacket(0)
		ecnTracker.LostPacket(1)
		ecnTracker.LostPacket(2)
	}
	// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(3, 4, 5, 6, 7, 8), 0, 0, 6))
	// By CE-marking the last unacknowledged testing packets, we should detect the mangling.
	if packetLossFirst {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
	}
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(9), 0, 0, 7))

	if !packetLossFirst {
		tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedManglingDetected)
		ecnTracker.LostPacket(0)
		ecnTracker.LostPacket(1)
		ecnTracker.LostPacket(2)
	}
}

func TestECNCongestionDetection(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	sendECNTestingPackets(t, ecnTracker, tracer)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	// Receive one CE count.
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1))
	// No increase in CE. No congestion.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 5, 0, 1))
	// Increase in CE. More congestion.
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 7, 0, 2))
}
