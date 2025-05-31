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

func sendECNTestingPackets(t *testing.T, ecnTracker *ecnTracker, tracer *mocklogging.MockConnectionTracer) []protocol.PacketNumber {
	t.Helper()

	tracer.EXPECT().ECNStateUpdated(logging.ECNStateTesting, logging.ECNTriggerNoTrigger)
	var pns []protocol.PacketNumber
	for i := range 9 {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		// do this twice to make sure only sent packets are counted
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		pn := protocol.PacketNumber(10 + i)
		ecnTracker.SentPacket(pn, protocol.ECT0)
		pns = append(pns, pn)
	}
	require.Equal(t, protocol.ECT0, ecnTracker.Mode())
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
	ecnTracker.SentPacket(20, protocol.ECT0)
	pns = append(pns, 20)
	// in unknown state, packets shouldn't be ECN-marked
	require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
	return pns
}

// ECN validation fails if _all_ ECN testing packets are lost
func TestECNTestingPacketsLoss(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	testingPackets := sendECNTestingPackets(t, ecnTracker, tracer)

	// send non-testing packets
	var nonTestingPackets []protocol.PacketNumber
	for i := range 10 {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		pn := testingPackets[len(testingPackets)-1] + protocol.PacketNumber(i) + 1
		nonTestingPackets = append(nonTestingPackets, pn)
		ecnTracker.SentPacket(pn, protocol.ECNNon)
	}

	// lose all but one packet
	for i, pn := range testingPackets {
		if i == 4 {
			continue
		}
		ecnTracker.LostPacket(pn)
	}
	// loss of non-testing packets doesn't matter
	ecnTracker.LostPacket(nonTestingPackets[3])
	ecnTracker.LostPacket(nonTestingPackets[4])

	// now lose the last testing packet
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedLostAllTestingPackets)
	ecnTracker.LostPacket(testingPackets[4])
}

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

func TestECNValidationInUnknownState(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	ecnTracker := newECNTracker(utils.DefaultLogger, tr)

	pns := sendECNTestingPackets(t, ecnTracker, tracer)
	for i := range 10 {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		pn := pns[len(pns)-1] + 1 + protocol.PacketNumber(i)
		ecnTracker.SentPacket(pn, protocol.ECNNon)
		// lose some packets to make sure this doesn't influence the outcome.
		if i%2 == 0 {
			ecnTracker.LostPacket(pn)
		}
	}
	tracer.EXPECT().ECNStateUpdated(logging.ECNStateCapable, logging.ECNTriggerNoTrigger)
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(pns[7]), 1, 0, 0))
}
