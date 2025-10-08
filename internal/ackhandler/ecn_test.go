package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func getAckedPackets(pns ...protocol.PacketNumber) []packetWithPacketNumber {
	var packets []packetWithPacketNumber
	for _, p := range pns {
		packets = append(packets, packetWithPacketNumber{PacketNumber: p})
	}
	return packets
}

// sendECNTestingPackets sends 10 ECT(0) packets, and then one more packet
// Packet numbers: 0 through 9.
func sendECNTestingPackets(t *testing.T, ecnTracker *ecnTracker, recorder *events.Recorder) {
	t.Helper()

	for i := range protocol.PacketNumber(9) {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		// do this twice to make sure only sent packets are counted
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(i, protocol.ECT0)
	}
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateTesting}},
		recorder.Events(),
	)
	require.Equal(t, protocol.ECT0, ecnTracker.Mode())
	recorder.Clear()
	ecnTracker.SentPacket(9, protocol.ECT0)
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateUnknown}},
		recorder.Events(),
	)
	recorder.Clear()
	// in unknown state, packets shouldn't be ECN-marked
	require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
}

// ECN validation fails if *all* ECN testing packets are lost.
func TestECNTestingPacketsLoss(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)

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
	require.Empty(t, eventRecorder.Events())
	eventRecorder.Clear()
	ecnTracker.LostPacket(4)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedLostAllTestingPackets},
		},
		eventRecorder.Events(),
	)
}

// ECN support is validated once an acknowledgment for any testing packet is received.
// This applies even if that happens before all testing packets have been sent out.
func TestECNValidationInTestingState(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	for i := range 5 {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
	}
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateTesting}},
		eventRecorder.Events(),
	)
	eventRecorder.Clear()
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(3), 1, 0, 0))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)

	// make sure we continue sending ECT(0) packets
	for i := 5; i < 100; i++ {
		require.Equal(t, protocol.ECT0, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECT0)
	}
}

// ENC is also validated after all testing packets have been sent out,
// once an acknowledgment for any testing packet is received.
func TestECNValidationInUnknownState(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)

	for i := range protocol.PacketNumber(10) {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		pn := 10 + i
		ecnTracker.SentPacket(pn, protocol.ECNNon)
		// lose some packets to make sure this doesn't influence the outcome.
		if i%2 == 0 {
			ecnTracker.LostPacket(pn)
		}
	}
	require.Empty(t, eventRecorder.Events())
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7), 1, 0, 0))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)
}

func TestECNValidationFailures(t *testing.T) {
	t.Run("ECN bleaching", func(t *testing.T) {
		// this ACK doesn't contain any ECN counts
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 0, 0, 0, ecnFailedNoECNCounts)
	})

	t.Run("wrong ECN code point", func(t *testing.T) {
		// we sent ECT(0), but this ACK acknowledges ECT(1)
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 0, 1, 0, ecnFailedMoreECNCountsThanSent)
	})

	t.Run("more ECN counts than sent packets", func(t *testing.T) {
		// only 10 ECT(0) packets were sent, but the ACK claims to have received 12 of them
		testECNValidationFailure(t, getAckedPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 12, 0, 0, ecnFailedMoreECNCountsThanSent)
	})
}

func testECNValidationFailure(
	t *testing.T,
	ackedPackets []packetWithPacketNumber,
	ect0, ect1, ecnce int64,
	expectedTrigger string,
) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}

	require.False(t, ecnTracker.HandleNewlyAcked(ackedPackets, ect0, ect1, ecnce))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: expectedTrigger}},
		eventRecorder.Events(),
	)
}

func TestECNValidationNotEnoughECNCounts(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	require.Empty(t, eventRecorder.Events())
	// First only acknowledge some packets sent with ECN marks.
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// Now acknowledge some more packets sent with ECN marks, but don't increase the counters enough.
	// This ACK acknowledges 3 more ECN-marked packets, but the counters only increase by 2.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 15), 3, 0, 2))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedTooFewECNCounts}},
		eventRecorder.Events(),
	)
}

func TestECNNonsensicalECNCountDecrease(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	require.Empty(t, eventRecorder.Events())
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 3, 0, 0))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// Now acknowledge some more packets, but decrease the ECN counts. Obviously, this doesn't make any sense.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 2, 0, 0))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedDecreasedECNCounts}},
		eventRecorder.Events(),
	)
	eventRecorder.Clear()

	// make sure that new ACKs are ignored
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 5, 0, 0))
	require.Empty(t, eventRecorder.Events())
}

func TestECNACKReordering(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	require.Empty(t, eventRecorder.Events())

	// The ACK contains more ECN counts than it acknowledges packets.
	// This can happen if ACKs are lost / reordered.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 8, 0, 0))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)
}

// Mangling is detected if all testing packets are marked CE.
func TestECNManglingAllPacketsMarkedCE(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}

	// ECN capability not confirmed yet, therefore CE marks are not regarded as congestion events
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(0, 1, 2, 3), 0, 0, 4))
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 10, 11, 12), 0, 0, 7))
	require.Empty(t, eventRecorder.Events())

	// With the next ACK, all testing packets will now have been marked CE.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 13), 0, 0, 10))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedManglingDetected}},
		eventRecorder.Events(),
	)
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
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
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
	require.Empty(t, eventRecorder.Events())
	// By CE-marking the last unacknowledged testing packets, we should detect the mangling.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(9), 0, 0, 7))
	if packetLossFirst {
		require.Equal(t,
			[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedManglingDetected}},
			eventRecorder.Events(),
		)
	} else {
		require.Empty(t, eventRecorder.Events())
	}

	if !packetLossFirst {
		ecnTracker.LostPacket(0)
		ecnTracker.LostPacket(1)
		ecnTracker.LostPacket(2)

		require.Equal(t,
			[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateFailed, Trigger: ecnFailedManglingDetected}},
			eventRecorder.Events(),
		)
	}
}

func TestECNCongestionDetection(t *testing.T) {
	var eventRecorder events.Recorder
	ecnTracker := newECNTracker(utils.DefaultLogger, &eventRecorder)

	sendECNTestingPackets(t, ecnTracker, &eventRecorder)
	for i := 10; i < 20; i++ {
		require.Equal(t, protocol.ECNNon, ecnTracker.Mode())
		ecnTracker.SentPacket(protocol.PacketNumber(i), protocol.ECNNon)
	}
	// Receive one CE count.
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(1, 2, 3, 12), 2, 0, 1))
	require.Equal(t,
		[]qlogwriter.Event{qlog.ECNStateUpdated{State: qlog.ECNStateCapable}},
		eventRecorder.Events(),
	)

	// No increase in CE. No congestion.
	require.False(t, ecnTracker.HandleNewlyAcked(getAckedPackets(4, 5, 6, 13), 5, 0, 1))
	eventRecorder.Clear()

	// Increase in CE. More congestion.
	require.True(t, ecnTracker.HandleNewlyAcked(getAckedPackets(7, 8, 9, 14), 7, 0, 2))
	require.Empty(t, eventRecorder.Events())
}
