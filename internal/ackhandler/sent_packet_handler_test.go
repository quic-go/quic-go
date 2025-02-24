package ackhandler

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type customFrameHandler struct {
	onLost, onAcked func(wire.Frame)
}

func (h *customFrameHandler) OnLost(f wire.Frame) {
	if h.onLost != nil {
		h.onLost(f)
	}
}

func (h *customFrameHandler) OnAcked(f wire.Frame) {
	if h.onAcked != nil {
		h.onAcked(f)
	}
}

type packetTracker struct {
	Acked []protocol.PacketNumber
	Lost  []protocol.PacketNumber
}

func (t *packetTracker) NewPingFrame(pn protocol.PacketNumber) Frame {
	return Frame{
		Frame: &wire.PingFrame{},
		Handler: &customFrameHandler{
			onAcked: func(wire.Frame) { t.Acked = append(t.Acked, pn) },
			onLost:  func(wire.Frame) { t.Lost = append(t.Lost, pn) },
		},
	}
}

func (h *sentPacketHandler) getBytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

func ackRanges(pns ...protocol.PacketNumber) []wire.AckRange {
	if len(pns) == 0 {
		return nil
	}
	slices.Sort(pns)
	slices.Reverse(pns)

	var ranges []wire.AckRange
	start := pns[0]
	for i := 1; i < len(pns); i++ {
		if pns[i-1]-pns[i] > 1 {
			ranges = append(ranges, wire.AckRange{Smallest: pns[i-1], Largest: start})
			start = pns[i]
		}
	}
	return append(ranges, wire.AckRange{Smallest: pns[len(pns)-1], Largest: start})
}

func TestAckRanges(t *testing.T) {
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 1}}, ackRanges(1))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ackRanges(1, 2))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(1, 2, 3))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(3, 2, 1))
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 3}}, ackRanges(1, 3, 2))

	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 3}, {Smallest: 1, Largest: 1}}, ackRanges(1, 3))
	require.Equal(t, []wire.AckRange{{Smallest: 3, Largest: 4}, {Smallest: 1, Largest: 1}}, ackRanges(1, 3, 4))
	require.Equal(t, []wire.AckRange{{Smallest: 5, Largest: 6}, {Smallest: 0, Largest: 2}}, ackRanges(0, 1, 2, 5, 6))
}

func TestSentPacketHandlerSendAndAcknowledge(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerSendAndAcknowledge(t, protocol.Encryption1RTT)
	})
}

func testSentPacketHandlerSendAndAcknowledge(t *testing.T, encLevel protocol.EncryptionLevel) {
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		false,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	var packets packetTracker
	var pns []protocol.PacketNumber
	now := time.Now()
	for i := range 10 {
		e := encLevel
		// also send some 0-RTT packets to make sure they're acknowledged in the same packet number space
		if encLevel == protocol.Encryption1RTT && i < 5 {
			e = protocol.Encryption0RTT
		}
		pn := sph.PopPacketNumber(e)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, e, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9])},
		encLevel,
		time.Now(),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9]}, packets.Acked)

	// ACKs that don't acknowledge new packets are ok
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[1], pns[2], pns[3])},
		encLevel,
		time.Now(),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1], pns[2], pns[3], pns[4], pns[7], pns[8], pns[9]}, packets.Acked)

	// ACKs that don't acknowledge packets that we didn't send are not ok
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[7], pns[8], pns[9], pns[9]+1)},
		encLevel,
		time.Now(),
	)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, "received ACK for an unsent packet")
}

func TestSentPacketHandlerAcknowledgeSkippedPacket(t *testing.T) {
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		false,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	now := time.Now()
	lastPN := protocol.InvalidPacketNumber
	skippedPN := protocol.InvalidPacketNumber
	for {
		pn, _ := sph.PeekPacketNumber(protocol.Encryption1RTT)
		require.Equal(t, pn, sph.PopPacketNumber(protocol.Encryption1RTT))
		if pn > lastPN+1 {
			skippedPN = pn - 1
		}
		if pn >= 1e6 {
			t.Fatal("expected a skipped packet number")
		}
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		lastPN = pn
		if skippedPN != protocol.InvalidPacketNumber {
			break
		}
	}

	_, err := sph.ReceivedAck(&wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 0, Largest: lastPN}},
	}, protocol.Encryption1RTT, time.Now())
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.ErrorContains(t, err, fmt.Sprintf("received an ACK for skipped packet number: %d (1-RTT)", skippedPN))
}

func TestSentPacketHandlerRTTs(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerRTTs(t, protocol.EncryptionInitial, false)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerRTTs(t, protocol.EncryptionHandshake, false)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerRTTs(t, protocol.Encryption1RTT, true)
	})
}

func testSentPacketHandlerRTTs(t *testing.T, encLevel protocol.EncryptionLevel, usesAckDelay bool) {
	var expectedRTTStats utils.RTTStats
	expectedRTTStats.SetMaxAckDelay(time.Second)
	var rttStats utils.RTTStats
	rttStats.SetMaxAckDelay(time.Second)
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		false,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	sendPacket := func(ti time.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1200, false, false)
		return pn
	}

	ackPacket := func(pn protocol.PacketNumber, ti time.Time, d time.Duration) {
		t.Helper()
		_, err := sph.ReceivedAck(&wire.AckFrame{DelayTime: d, AckRanges: ackRanges(pn)}, encLevel, ti)
		require.NoError(t, err)
	}

	var packets []protocol.PacketNumber
	now := time.Now()
	// send some packets and receive ACKs with 0 ack delay
	for i := 0; i < 5; i++ {
		packets = append(packets, sendPacket(now))
	}
	for i := 0; i < 5; i++ {
		expectedRTTStats.UpdateRTT(time.Duration(i+1)*time.Second, 0)
		now = now.Add(time.Second)
		ackPacket(packets[i], now, 0)
		require.Equal(t, expectedRTTStats.SmoothedRTT(), rttStats.SmoothedRTT())
		require.Equal(t, time.Second, rttStats.MinRTT())
		require.Equal(t, time.Duration(i+1)*time.Second, rttStats.LatestRTT())
	}
	packets = packets[:0]

	// send some more packets and receive ACKs with non-zero ack delay
	for i := 0; i < 5; i++ {
		packets = append(packets, sendPacket(now))
	}
	expectedRTTStatsNoAckDelay := expectedRTTStats
	for i := 0; i < 5; i++ {
		const ackDelay = 500 * time.Millisecond
		expectedRTTStats.UpdateRTT(time.Duration(i+1)*time.Second, ackDelay)
		expectedRTTStatsNoAckDelay.UpdateRTT(time.Duration(i+1)*time.Second, 0)
		now = now.Add(time.Second)
		ackPacket(packets[i], now, ackDelay)
		if usesAckDelay {
			require.Equal(t, expectedRTTStats.SmoothedRTT(), rttStats.SmoothedRTT())
		} else {
			require.Equal(t, expectedRTTStatsNoAckDelay.SmoothedRTT(), rttStats.SmoothedRTT())
		}
	}
	packets = packets[:0]
	// make sure that taking ack delay into account actually changes the RTT,
	// otherwise the test is not meaningful
	require.NotEqual(t, expectedRTTStats.SmoothedRTT(), expectedRTTStatsNoAckDelay.SmoothedRTT())

	// Send two more packets, and acknowledge them in opposite order.
	// This tests that the RTT is updated even if the ACK doesn't increase the largest acked.
	packets = append(packets, sendPacket(now))
	packets = append(packets, sendPacket(now))
	ackPacket(packets[1], now.Add(time.Second), 0)
	rtt := rttStats.SmoothedRTT()
	ackPacket(packets[0], now.Add(10*time.Second), 0)
	require.NotEqual(t, rtt, rttStats.SmoothedRTT())

	// Send one more packet, and send where the largest acked is acknowledged twice.
	pn := sendPacket(now)
	ackPacket(pn, now.Add(time.Second), 0)
	rtt = rttStats.SmoothedRTT()
	ackPacket(pn, now.Add(10*time.Second), 0)
	require.Equal(t, rtt, rttStats.SmoothedRTT())
}

func TestSentPacketHandlerAmplificationLimitServer(t *testing.T) {
	t.Run("address validated", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitServer(t, true)
	})
	t.Run("address not validated", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitServer(t, false)
	})
}

func testSentPacketHandlerAmplificationLimitServer(t *testing.T, addressValidated bool) {
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		addressValidated,
		false,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)

	if addressValidated {
		require.Equal(t, SendAny, sph.SendMode(time.Now()))
		return
	}

	// no data received yet, so we can't send any packet yet
	require.Equal(t, SendNone, sph.SendMode(time.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// Receive 1000 bytes from the client.
	// As long as we haven't sent out 3x the amount of bytes received, we can send out new packets,
	// even if we go above the 3x limit by sending the last packet.
	sph.ReceivedBytes(1000, time.Now())
	for i := 0; i < 4; i++ {
		require.Equal(t, SendAny, sph.SendMode(time.Now()))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(time.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 999, false, false)
		if i != 3 {
			require.NotZero(t, sph.GetLossDetectionTimeout())
		}
	}
	require.Equal(t, SendNone, sph.SendMode(time.Now()))
	// no need to set a loss detection timer, as we're blocked by the amplification limit
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving more data allows us to send out more packets
	sph.ReceivedBytes(1000, time.Now())
	require.NotZero(t, sph.GetLossDetectionTimeout())
	for i := 0; i < 3; i++ {
		require.Equal(t, SendAny, sph.SendMode(time.Now()))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(time.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
	}
	require.Equal(t, SendNone, sph.SendMode(time.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving an Initial packet doesn't validate the client's address
	sph.ReceivedPacket(protocol.EncryptionInitial, time.Now())
	require.Equal(t, SendNone, sph.SendMode(time.Now()))
	require.Zero(t, sph.GetLossDetectionTimeout())

	// receiving a Handshake packet validates the client's address
	sph.ReceivedPacket(protocol.EncryptionHandshake, time.Now())
	require.Equal(t, SendAny, sph.SendMode(time.Now()))
	require.NotZero(t, sph.GetLossDetectionTimeout())
}

func TestSentPacketHandlerAmplificationLimitClient(t *testing.T) {
	t.Run("handshake ACK", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitClient(t, false)
	})

	t.Run("drop Handshake without ACK", func(t *testing.T) {
		testSentPacketHandlerAmplificationLimitClient(t, true)
	})
}

func testSentPacketHandlerAmplificationLimitClient(t *testing.T, dropHandshake bool) {
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	require.Equal(t, SendAny, sph.SendMode(time.Now()))
	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(time.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 999, false, false)
	// it's not surprising that the loss detection timer is set, as this packet might be lost...
	require.NotZero(t, sph.GetLossDetectionTimeout())
	// ... but it's still set after receiving an ACK for this packet,
	// since we might need to unblock the server's amplification limit
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, time.Now())
	require.NoError(t, err)
	require.NotZero(t, sph.GetLossDetectionTimeout())
	require.Equal(t, SendAny, sph.SendMode(time.Now()))

	// when the timer expires, we should send a PTO packet
	sph.OnLossDetectionTimeout(time.Now())
	require.Equal(t, SendPTOInitial, sph.SendMode(time.Now()))
	require.NotZero(t, sph.GetLossDetectionTimeout())

	if dropHandshake {
		// dropping the handshake packet number space completes the handshake,
		// even if no ACK for a handshake packet was received
		sph.DropPackets(protocol.EncryptionHandshake, time.Now())
		require.Zero(t, sph.GetLossDetectionTimeout())
		return
	}

	// once the Initial packet number space is dropped, we need to send a Handshake PTO packet,
	// even if we haven't sent any packet in the Handshake packet number space yet
	sph.DropPackets(protocol.EncryptionInitial, time.Now())
	require.NotZero(t, sph.GetLossDetectionTimeout())
	sph.OnLossDetectionTimeout(time.Now())
	require.Equal(t, SendPTOHandshake, sph.SendMode(time.Now()))

	// receiving an ACK for a handshake packet shows that the server completed address validation
	pn = sph.PopPacketNumber(protocol.EncryptionHandshake)
	sph.SentPacket(time.Now(), pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionHandshake, protocol.ECNNon, 999, false, false)
	require.NotZero(t, sph.GetLossDetectionTimeout())
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionHandshake, time.Now())
	require.NoError(t, err)
	require.Zero(t, sph.GetLossDetectionTimeout())
}

func TestSentPacketHandlerDelayBasedLossDetection(t *testing.T) {
	var rttStats utils.RTTStats
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)

	var packets packetTracker
	sendPacket := func(ti time.Time, isPathMTUProbePacket bool) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, isPathMTUProbePacket, false)
		return pn
	}

	const rtt = time.Second
	now := time.Now()
	t1 := now.Add(-rtt)
	t2 := now.Add(-10 * time.Millisecond)
	// Send 3 packets
	pn1 := sendPacket(t1, false)
	pn2 := sendPacket(t2, false)
	// Also send a Path MTU probe packet.
	// We expect the same loss recovery logic to be applied to it.
	pn3 := sendPacket(t2, true)
	pn4 := sendPacket(now, false)

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn4)},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	// make sure that the RTT is actually 1s
	require.Equal(t, rtt, rttStats.SmoothedRTT())
	require.Equal(t, []protocol.PacketNumber{pn4}, packets.Acked)
	// only the first packet was lost
	require.Equal(t, []protocol.PacketNumber{pn1}, packets.Lost)
	// ... but we armed a timer to declare packet 2 lost after 9/8 RTTs
	require.Equal(t, t2.Add(time.Second*9/8), sph.GetLossDetectionTimeout())

	sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout().Add(-time.Microsecond))
	require.Len(t, packets.Lost, 1)
	sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout())
	require.Equal(t, []protocol.PacketNumber{pn1, pn2, pn3}, packets.Lost)
}

func TestSentPacketHandlerPacketBasedLossDetection(t *testing.T) {
	var rttStats utils.RTTStats
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)

	var packets packetTracker
	now := time.Now()
	var pns []protocol.PacketNumber
	for range 5 {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
		pns = append(pns, pn)
	}

	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[3])},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0]}, packets.Lost)

	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[4])},
		protocol.EncryptionInitial,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[3], pns[4]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)
}

func TestSentPacketHandlerPTO(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.EncryptionInitial, SendPTOInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.EncryptionHandshake, SendPTOHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testSentPacketHandlerPTO(t, protocol.Encryption1RTT, SendPTOAppData)
	})
}

func testSentPacketHandlerPTO(t *testing.T, encLevel protocol.EncryptionLevel, ptoMode SendMode) {
	var packets packetTracker

	mockCtrl := gomock.NewController(t)
	tracer, tr := mocklogging.NewMockConnectionTracer(mockCtrl)
	tr.EXPECT().UpdatedCongestionState(gomock.Any()).AnyTimes()
	tr.EXPECT().UpdatedMetrics(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	var rttStats utils.RTTStats
	rttStats.SetMaxAckDelay(25 * time.Millisecond)
	rttStats.UpdateRTT(500*time.Millisecond, 0)
	rttStats.UpdateRTT(1000*time.Millisecond, 0)
	rttStats.UpdateRTT(1500*time.Millisecond, 0)
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveServer,
		tracer,
		utils.DefaultLogger,
	)

	// in the application-data packet number space, the PTO is only set
	if encLevel == protocol.Encryption1RTT {
		sph.DropPackets(protocol.EncryptionInitial, time.Now())
		sph.DropPackets(protocol.EncryptionHandshake, time.Now())
	}

	sendPacket := func(ti time.Time, ackEliciting bool) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel)
		if ackEliciting {
			tr.EXPECT().SetLossTimer(logging.TimerTypePTO, encLevel, gomock.Any())
			sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, encLevel, protocol.ECNNon, 1000, false, false)
		} else {
			sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, nil, encLevel, protocol.ECNNon, 1000, true, false)
		}
		return pn
	}

	now := time.Now()
	sendTimes := []time.Time{
		now,
		now.Add(100 * time.Millisecond),
		now.Add(200 * time.Millisecond),
		now.Add(300 * time.Millisecond),
	}
	var pns []protocol.PacketNumber
	// send packet 0, 1, 2, 3
	for i := range 3 {
		pns = append(pns, sendPacket(sendTimes[i], true))
	}
	pns = append(pns, sendPacket(sendTimes[3], false))

	// The PTO includes the max_ack_delay only for the application-data packet number space.
	// Make sure that the value is actually different, so this test is meaningful.
	require.NotEqual(t, rttStats.PTO(true), rttStats.PTO(false))

	timeout := sph.GetLossDetectionTimeout()
	// the PTO is based on the *last* ack-eliciting packet
	require.Equal(t, sendTimes[2].Add(rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)

	gomock.InOrder(
		tr.EXPECT().LossTimerExpired(logging.TimerTypePTO, encLevel),
		tr.EXPECT().UpdatedPTOCount(uint32(1)),
		tr.EXPECT().SetLossTimer(logging.TimerTypePTO, encLevel, gomock.Any()),
	)
	sph.OnLossDetectionTimeout(timeout)
	// PTO timer expiration doesn't declare packets lost
	require.Empty(t, packets.Lost)

	now = timeout
	require.Equal(t, ptoMode, sph.SendMode(now))
	// queue a probe packet
	require.True(t, sph.QueueProbePacket(encLevel))
	require.True(t, sph.QueueProbePacket(encLevel))
	require.True(t, sph.QueueProbePacket(encLevel))
	// there are only two ack-eliciting packets that could be queued
	require.False(t, sph.QueueProbePacket(encLevel))
	// Queueing probe packets currently works by declaring them lost.
	// We shouldn't do this, but this is how the code is currently written.
	require.Equal(t, pns[:3], packets.Lost)
	packets.Lost = packets.Lost[:0]

	// send packet 4 and 6 as probe packets
	// 5 doesn't count, since it's not an ack-eliciting packet
	sendTimes = append(sendTimes, now.Add(100*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(200*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(300*time.Millisecond))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[4])) // first probe packet
	pns = append(pns, sendPacket(sendTimes[4], true))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[5])) // next probe packet
	pns = append(pns, sendPacket(sendTimes[5], false))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[6])) // non-ack-eliciting packet didn't count as a probe packet
	pns = append(pns, sendPacket(sendTimes[6], true))
	require.Equal(t, SendAny, sph.SendMode(sendTimes[6])) // enough probe packets sent

	timeout = sph.GetLossDetectionTimeout()
	// exponential backoff
	require.Equal(t, sendTimes[6].Add(2*rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)
	now = timeout

	gomock.InOrder(
		tr.EXPECT().LossTimerExpired(logging.TimerTypePTO, encLevel),
		tr.EXPECT().UpdatedPTOCount(uint32(2)),
		tr.EXPECT().SetLossTimer(logging.TimerTypePTO, encLevel, gomock.Any()),
	)
	sph.OnLossDetectionTimeout(timeout)
	// PTO timer expiration doesn't declare packets lost
	require.Empty(t, packets.Lost)

	// send packet 7, 8 as probe packets
	sendTimes = append(sendTimes, now.Add(100*time.Millisecond))
	sendTimes = append(sendTimes, now.Add(200*time.Millisecond))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[7])) // first probe packet
	pns = append(pns, sendPacket(sendTimes[7], true))
	require.Equal(t, ptoMode, sph.SendMode(sendTimes[8])) // next probe packet
	pns = append(pns, sendPacket(sendTimes[8], true))
	require.Equal(t, SendAny, sph.SendMode(sendTimes[8])) // enough probe packets sent

	timeout = sph.GetLossDetectionTimeout()

	// exponential backoff, again
	require.Equal(t, sendTimes[8].Add(4*rttStats.PTO(encLevel == protocol.Encryption1RTT)), timeout)

	// Receive an ACK for packet 7.
	// This now declares packets lost, and leads to arming of a timer for packet 8.
	tr.EXPECT().LostPacket(gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
	gomock.InOrder(
		tr.EXPECT().AcknowledgedPacket(encLevel, pns[7]),
		tr.EXPECT().UpdatedPTOCount(uint32(0)),
		tr.EXPECT().SetLossTimer(logging.TimerTypePTO, encLevel, gomock.Any()),
	)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[7])},
		encLevel,
		sendTimes[7].Add(time.Microsecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[7]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[4], pns[6]}, packets.Lost)

	// the PTO timer is now set for the last remaining packet (8),
	// with no exponential backoff
	require.Equal(t, sendTimes[8].Add(rttStats.PTO(encLevel == protocol.Encryption1RTT)), sph.GetLossDetectionTimeout())
}

func TestSentPacketHandlerPacketNumberSpacesPTO(t *testing.T) {
	var rttStats utils.RTTStats
	const rtt = time.Second
	rttStats.UpdateRTT(rtt, 0)
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)

	sendPacket := func(ti time.Time, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1000, false, false)
		return pn
	}

	var initialPNs, handshakePNs [4]protocol.PacketNumber
	var initialTimes, handshakeTimes [4]time.Time
	now := time.Now()
	initialPNs[0] = sendPacket(now, protocol.EncryptionInitial)
	initialTimes[0] = now
	now = now.Add(100 * time.Millisecond)
	handshakePNs[0] = sendPacket(now, protocol.EncryptionHandshake)
	handshakeTimes[0] = now
	now = now.Add(100 * time.Millisecond)
	initialPNs[1] = sendPacket(now, protocol.EncryptionInitial)
	initialTimes[1] = now
	now = now.Add(100 * time.Millisecond)
	handshakePNs[1] = sendPacket(now, protocol.EncryptionHandshake)
	handshakeTimes[1] = now
	require.Equal(t, protocol.ByteCount(4000), sph.getBytesInFlight())

	// the PTO is the earliest time of the PTO times for both packet number spaces,
	// i.e. the 2nd Initial packet sent
	timeout := sph.GetLossDetectionTimeout()
	require.Equal(t, initialTimes[1].Add(rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))
	// send a PTO probe packet (Initial)
	now = timeout.Add(100 * time.Millisecond)
	initialPNs[2] = sendPacket(now, protocol.EncryptionInitial)
	initialTimes[2] = now

	// the earliest PTO time is now the 2nd Handshake packet
	timeout = sph.GetLossDetectionTimeout()
	// pto_count is a global property, so there's now an exponential backoff
	require.Equal(t, handshakeTimes[1].Add(2*rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(timeout))
	// send a PTO probe packet (Handshake)
	now = timeout.Add(100 * time.Millisecond)
	handshakePNs[2] = sendPacket(now, protocol.EncryptionHandshake)
	handshakeTimes[2] = now

	// the earliest PTO time is now the 3rd Initial packet
	timeout = sph.GetLossDetectionTimeout()
	require.Equal(t, initialTimes[2].Add(4*rttStats.PTO(false)), timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))

	// drop the Initial packet number space
	now = timeout.Add(100 * time.Millisecond)
	require.Equal(t, protocol.ByteCount(6000), sph.getBytesInFlight())
	sph.DropPackets(protocol.EncryptionInitial, now)
	require.Equal(t, protocol.ByteCount(3000), sph.getBytesInFlight())

	// Since the Initial packets are gone:
	// * the earliest PTO time is now based on the 3rd Handshake packet
	// * the PTO count is reset to 0
	timeout = sph.GetLossDetectionTimeout()
	require.Equal(t, handshakeTimes[2].Add(rttStats.PTO(false)), timeout)

	// send a 1-RTT packet
	now = timeout.Add(100 * time.Millisecond)
	sendTime := now
	sendPacket(now, protocol.Encryption1RTT)

	// until handshake confirmation, the PTO timer is based on the Handshake packet number space
	require.Equal(t, timeout, sph.GetLossDetectionTimeout())
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(now))

	// Drop Handshake packet number space.
	// This confirms the handshake, and the PTO timer is now based on the 1-RTT packet number space.
	sph.DropPackets(protocol.EncryptionHandshake, now)
	require.Equal(t, sendTime.Add(rttStats.PTO(false)), sph.GetLossDetectionTimeout())
}

func TestSentPacketHandler0RTT(t *testing.T) {
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	var appDataPackets packetTracker
	sendPacket := func(ti time.Time, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel)
		var frames []Frame
		if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
			frames = []Frame{appDataPackets.NewPingFrame(pn)}
		} else {
			frames = []Frame{{Frame: &wire.PingFrame{}}}
		}
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, frames, encLevel, protocol.ECNNon, 1000, false, false)
		return pn
	}

	now := time.Now()
	sendPacket(now, protocol.Encryption0RTT)
	sendPacket(now.Add(100*time.Millisecond), protocol.EncryptionHandshake)
	sendPacket(now.Add(200*time.Millisecond), protocol.Encryption0RTT)
	sendPacket(now.Add(300*time.Millisecond), protocol.Encryption1RTT)
	sendPacket(now.Add(400*time.Millisecond), protocol.Encryption1RTT)
	require.Equal(t, protocol.ByteCount(5000), sph.getBytesInFlight())

	// The PTO timer is based on the Handshake packet number space, not the 0-RTT packets
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOHandshake, sph.SendMode(timeout))

	now = timeout.Add(100 * time.Millisecond)
	sph.DropPackets(protocol.Encryption0RTT, now)
	require.Equal(t, protocol.ByteCount(3000), sph.getBytesInFlight())
	// 0-RTT are discarded, not lost
	require.Empty(t, appDataPackets.Lost)
}

func TestSentPacketHandlerCongestion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	var rttStats utils.RTTStats
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)
	sph.congestion = cong

	var packets packetTracker
	// Send the first 5 packets: not congestion-limited, not pacing-limited.
	// The 2nd packet is a Path MTU Probe packet.
	now := time.Now()
	var bytesInFlight protocol.ByteCount
	var pns []protocol.PacketNumber
	var sendTimes []time.Time
	for i := range 5 {
		gomock.InOrder(
			cong.EXPECT().CanSend(bytesInFlight).Return(true),
			cong.EXPECT().HasPacingBudget(now).Return(true),
		)
		require.Equal(t, SendAny, sph.SendMode(now))
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		bytesInFlight += 1000
		cong.EXPECT().OnPacketSent(now, bytesInFlight, pn, protocol.ByteCount(1000), true)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, i == 1, false)
		pns = append(pns, pn)
		sendTimes = append(sendTimes, now)
		now = now.Add(100 * time.Millisecond)
	}

	// try to send another packet: not congestion-limited, but pacing-limited
	now = now.Add(100 * time.Millisecond)
	gomock.InOrder(
		cong.EXPECT().CanSend(bytesInFlight).Return(true),
		cong.EXPECT().HasPacingBudget(now).Return(false),
	)
	require.Equal(t, SendPacingLimited, sph.SendMode(now))
	// the connection would call TimeUntilSend, to find out when a new packet can be sent again
	pacingDeadline := now.Add(500 * time.Millisecond)
	cong.EXPECT().TimeUntilSend(bytesInFlight).Return(pacingDeadline)
	require.Equal(t, pacingDeadline, sph.TimeUntilSend())

	// try to send another packet, but now we're congestion limited
	now = now.Add(100 * time.Millisecond)
	cong.EXPECT().CanSend(bytesInFlight).Return(false)
	require.Equal(t, SendAck, sph.SendMode(now)) // ACKs are allowed even if congestion limited

	// Receive an ACK for packet 3 and 4 (which declares the 1st and 2nd packet lost).
	// However, since the 2nd packet was a Path MTU probe packet, it won't get reported
	// to the congestion controller.
	ackTime := sendTimes[3].Add(time.Second)
	gomock.InOrder(
		cong.EXPECT().MaybeExitSlowStart(),
		cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(1000), protocol.ByteCount(5000)),
		cong.EXPECT().OnPacketAcked(pns[2], protocol.ByteCount(1000), protocol.ByteCount(5000), ackTime),
		cong.EXPECT().OnPacketAcked(pns[3], protocol.ByteCount(1000), protocol.ByteCount(5000), ackTime),
	)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[2], pns[3])}, protocol.EncryptionInitial, ackTime)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[2], pns[3]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[1]}, packets.Lost)

	// Now receive a (delayed) ACK for the 1st packet.
	// Since this packet was already lost, we don't expect any calls to the congestion controller.
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0])}, protocol.EncryptionInitial, ackTime)
	require.NoError(t, err)

	// we should now have a PTO timer armed for the 4th packet
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))

	// send another packet to check that bytes_in_flight was correctly adjusted
	now = timeout.Add(100 * time.Millisecond)
	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	cong.EXPECT().OnPacketSent(now, protocol.ByteCount(2000), pn, protocol.ByteCount(1000), true)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
}

func TestSentPacketHandlerRetry(t *testing.T) {
	t.Run("long RTT measurement", func(t *testing.T) {
		testSentPacketHandlerRetry(t, time.Second, time.Second)
	})

	// The estimated RTT should be at least 5ms, even if the RTT measurement is very short.
	t.Run("short RTT measurement", func(t *testing.T) {
		testSentPacketHandlerRetry(t, minRTTAfterRetry/3, minRTTAfterRetry)
	})
}

func testSentPacketHandlerRetry(t *testing.T, rtt, expectedRTT time.Duration) {
	var initialPackets, appDataPackets packetTracker

	var rttStats utils.RTTStats
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	start := time.Now()
	now := start
	var initialPNs, appDataPNs []protocol.PacketNumber
	// send 2 initial and 2 0-RTT packets
	for range 2 {
		pn := sph.PopPacketNumber(protocol.EncryptionInitial)
		initialPNs = append(initialPNs, pn)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{initialPackets.NewPingFrame(pn)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)
		now = now.Add(100 * time.Millisecond)

		pn = sph.PopPacketNumber(protocol.Encryption0RTT)
		appDataPNs = append(appDataPNs, pn)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{appDataPackets.NewPingFrame(pn)}, protocol.Encryption0RTT, protocol.ECNNon, 1000, false, false)
		now = now.Add(100 * time.Millisecond)
	}
	require.Equal(t, protocol.ByteCount(4000), sph.getBytesInFlight())
	require.NotZero(t, sph.GetLossDetectionTimeout())

	sph.ResetForRetry(start.Add(rtt))
	// receiving a Retry cancels all timers
	require.Zero(t, sph.GetLossDetectionTimeout())
	// all packets sent so far are declared lost
	require.Equal(t, []protocol.PacketNumber{initialPNs[0], initialPNs[1]}, initialPackets.Lost)
	require.Equal(t, []protocol.PacketNumber{appDataPNs[0], appDataPNs[1]}, appDataPackets.Lost)
	require.False(t, sph.QueueProbePacket(protocol.EncryptionInitial))
	require.False(t, sph.QueueProbePacket(protocol.Encryption0RTT))
	// the RTT measurement is taken from the first packet sent
	require.Equal(t, expectedRTT, rttStats.SmoothedRTT())
	require.Zero(t, sph.getBytesInFlight())

	// packet numbers continue increasing
	initialPN, _ := sph.PeekPacketNumber(protocol.EncryptionInitial)
	require.Greater(t, initialPN, initialPNs[1])
	appDataPN, _ := sph.PeekPacketNumber(protocol.Encryption0RTT)
	require.Greater(t, appDataPN, appDataPNs[1])
}

func TestSentPacketHandlerRetryAfterPTO(t *testing.T) {
	var rttStats utils.RTTStats
	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)

	var packets packetTracker
	start := time.Now()
	now := start
	pn1 := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn1)}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)

	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	sph.OnLossDetectionTimeout(timeout)
	require.Equal(t, SendPTOInitial, sph.SendMode(timeout))
	require.True(t, sph.QueueProbePacket(protocol.EncryptionInitial))

	// send a retransmission for the first packet
	now = timeout.Add(100 * time.Millisecond)
	pn2 := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn2, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn2)}, protocol.EncryptionInitial, protocol.ECNNon, 900, false, false)

	const rtt = time.Second
	sph.ResetForRetry(now.Add(rtt))

	require.Equal(t, []protocol.PacketNumber{pn1, pn2}, packets.Lost)
	// no RTT measurement is taken, since the PTO timer fired
	require.Zero(t, rttStats.SmoothedRTT())
}

func TestSentPacketHandlerECN(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cong := mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
	cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().OnPacketAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	cong.EXPECT().MaybeExitSlowStart().AnyTimes()
	ecnHandler := NewMockECNHandler(mockCtrl)
	sph := newSentPacketHandler(
		0,
		1200,
		&utils.RTTStats{},
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	sph.ecnTracker = ecnHandler
	sph.congestion = cong

	// ECN marks on non-1-RTT packets are ignored
	sph.SentPacket(time.Now(), sph.PopPacketNumber(protocol.EncryptionInitial), protocol.InvalidPacketNumber, nil, nil, protocol.EncryptionInitial, protocol.ECT1, 1200, false, false)
	sph.SentPacket(time.Now(), sph.PopPacketNumber(protocol.EncryptionHandshake), protocol.InvalidPacketNumber, nil, nil, protocol.EncryptionHandshake, protocol.ECT0, 1200, false, false)
	sph.SentPacket(time.Now(), sph.PopPacketNumber(protocol.Encryption0RTT), protocol.InvalidPacketNumber, nil, nil, protocol.Encryption0RTT, protocol.ECNCE, 1200, false, false)

	var packets packetTracker
	sendPacket := func(ti time.Time, ecn protocol.ECN) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		ecnHandler.EXPECT().SentPacket(pn, ecn)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, ecn, 1200, false, false)
		return pn
	}

	pns := make([]protocol.PacketNumber, 4)
	now := time.Now()
	pns[0] = sendPacket(now, protocol.ECT1)
	now = now.Add(time.Second)
	pns[1] = sendPacket(now, protocol.ECT0)
	pns[2] = sendPacket(now, protocol.ECT0)
	pns[3] = sendPacket(now, protocol.ECT0)

	// Receive an ACK with a short RTT, such that the first packet is lost.
	cong.EXPECT().OnCongestionEvent(gomock.Any(), gomock.Any(), gomock.Any())
	ecnHandler.EXPECT().LostPacket(pns[0])
	ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), int64(10), int64(11), int64(12)).DoAndReturn(func(packets []*packet, _, _, _ int64) bool {
		require.Len(t, packets, 2)
		require.Equal(t, packets[0].PacketNumber, pns[2])
		require.Equal(t, packets[1].PacketNumber, pns[3])
		return false
	})
	_, err := sph.ReceivedAck(
		&wire.AckFrame{
			AckRanges: ackRanges(pns[2], pns[3]),
			ECT0:      10,
			ECT1:      11,
			ECNCE:     12,
		},
		protocol.Encryption1RTT,
		now.Add(100*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0]}, packets.Lost)

	// The second packet is still outstanding.
	// Receive a (delayed) ACK for it.
	// Since the new ECN counts were already reported, ECN marks on this ACK frame are ignored.
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)

	// Send two more packets, and receive an ACK for the second one.
	pns = pns[:2]
	pns[0] = sendPacket(now, protocol.ECT1)
	pns[1] = sendPacket(now, protocol.ECT1)
	ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(packets []*packet, _, _, _ int64) bool {
			require.Len(t, packets, 1)
			require.Equal(t, pns[1], packets[0].PacketNumber)
			return false
		},
	)
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)
	// Receiving an ACK that covers both packets doesn't cause the ECN marks to be reported,
	// since the largest acked didn't increase.
	now = now.Add(100 * time.Millisecond)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1])}, protocol.Encryption1RTT, now)
	require.NoError(t, err)

	// Send another packet, and have the ECN handler report congestion.
	// This needs to be reported to the congestion controller.
	pns = pns[:1]
	now = now.Add(time.Second)
	pns[0] = sendPacket(now, protocol.ECT1)

	gomock.InOrder(
		ecnHandler.EXPECT().HandleNewlyAcked(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true),
		cong.EXPECT().OnCongestionEvent(pns[0], protocol.ByteCount(0), gomock.Any()),
	)
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0])}, protocol.Encryption1RTT, now.Add(100*time.Millisecond))
	require.NoError(t, err)
}

func TestSentPacketHandlerPathProbe(t *testing.T) {
	const rtt = 10 * time.Millisecond // RTT of the original path
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(rtt, 0)

	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	sph.DropPackets(protocol.EncryptionInitial, time.Now())
	sph.DropPackets(protocol.EncryptionHandshake, time.Now())

	var packets packetTracker
	sendPacket := func(ti time.Time, isPathProbe bool) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, isPathProbe)
		return pn
	}

	// send 5 packets: 2 non-probe packets, 1 probe packet, 2 non-probe packets
	now := time.Now()
	var pns [5]protocol.PacketNumber
	pns[0] = sendPacket(now, false)
	now = now.Add(rtt)
	pns[1] = sendPacket(now, false)
	pns[2] = sendPacket(now, true)
	pathProbeTimeout := now.Add(pathProbePacketLossTimeout)
	now = now.Add(rtt)
	pns[3] = sendPacket(now, false)
	now = now.Add(rtt)
	pns[4] = sendPacket(now, false)
	require.Less(t, sph.GetLossDetectionTimeout(), pathProbeTimeout)

	now = now.Add(100 * time.Millisecond)
	// make sure that this ACK doesn't declare the path probe packet lost
	require.Greater(t, pathProbeTimeout, now)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[3], pns[4])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[3], pns[4]}, packets.Acked)
	// despite having been sent at the same time, the probe packet was not lost
	require.Equal(t, []protocol.PacketNumber{pns[1]}, packets.Lost)

	// the timeout is now based on the probe packet
	timeout := sph.GetLossDetectionTimeout()
	require.Equal(t, pathProbeTimeout, timeout)
	require.Zero(t, sph.getBytesInFlight())
	pn1 := sendPacket(now, false)
	pn2 := sendPacket(now, false)
	require.Equal(t, protocol.ByteCount(2400), sph.getBytesInFlight())

	// send one more non-probe packet
	pn := sendPacket(now, false)
	// the timeout is now based on this packet
	require.Less(t, sph.GetLossDetectionTimeout(), pathProbeTimeout)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[2], pn)},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)

	packets.Lost = packets.Lost[:0]
	sph.MigratedPath(now, 1200)
	require.Zero(t, sph.getBytesInFlight())
	require.Zero(t, rttStats.SmoothedRTT())
	require.Equal(t, []protocol.PacketNumber{pn1, pn2}, packets.Lost)
}

func TestSentPacketHandlerPathProbeAckAndLoss(t *testing.T) {
	const rtt = 10 * time.Millisecond // RTT of the original path
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(rtt, 0)

	sph := newSentPacketHandler(
		0,
		1200,
		&rttStats,
		true,
		false,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	sph.DropPackets(protocol.EncryptionInitial, time.Now())
	sph.DropPackets(protocol.EncryptionHandshake, time.Now())

	var packets packetTracker
	sendPacket := func(ti time.Time, isPathProbe bool) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, isPathProbe)
		return pn
	}

	now := time.Now()
	pn1 := sendPacket(now, true)
	t1 := now
	now = now.Add(100 * time.Millisecond)
	_ = sendPacket(now, true)
	t2 := now
	now = now.Add(100 * time.Millisecond)
	pn3 := sendPacket(now, true)

	now = now.Add(100 * time.Millisecond)
	require.Equal(t, t1.Add(pathProbePacketLossTimeout), sph.GetLossDetectionTimeout())
	require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
	require.Equal(t, []protocol.PacketNumber{pn1}, packets.Lost)
	packets.Lost = packets.Lost[:0]

	// receive a delayed ACK for the path probe packet
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn1, pn3)},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pn3}, packets.Acked)
	require.Empty(t, packets.Lost)

	require.Equal(t, t2.Add(pathProbePacketLossTimeout), sph.GetLossDetectionTimeout())
}
