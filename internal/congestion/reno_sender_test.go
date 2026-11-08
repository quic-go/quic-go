package congestion

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

const (
	maxDatagramSize                = protocol.ByteCount(protocol.InitialPacketSize)
	initialCongestionWindowPackets = 10
	defaultWindowTCP               = protocol.ByteCount(initialCongestionWindowPackets) * maxDatagramSize
)

type testRenoSender struct {
	sender            *renoSender
	now               monotime.Time
	rttStats          *utils.RTTStats
	bytesInFlight     protocol.ByteCount
	packetNumber      protocol.PacketNumber
	ackedPacketNumber protocol.PacketNumber
}

func newTestRenoSender() *testRenoSender {
	rttStats := utils.RTTStats{}
	return &testRenoSender{
		rttStats:     &rttStats,
		packetNumber: 1,
		sender: newRenoSender(
			&rttStats,
			protocol.InitialPacketSize,
			initialCongestionWindowPackets*maxDatagramSize,
			nil,
		),
	}
}

func (s *testRenoSender) SendAvailableSendWindow() int {
	var packetsSent int
	for s.sender.CanSend(s.bytesInFlight) {
		s.sender.OnPacketSent(s.now, s.packetNumber, maxDatagramSize, true)
		s.packetNumber++
		packetsSent++
		s.bytesInFlight += maxDatagramSize
	}
	return packetsSent
}

func (s *testRenoSender) AckNPackets(n int) {
	s.rttStats.UpdateRTT(60*time.Millisecond, 0)
	s.sender.MaybeExitSlowStart()
	for range n {
		s.ackedPacketNumber++
		s.sender.OnPacketAcked(s.ackedPacketNumber, s.bytesInFlight)
	}
	s.bytesInFlight -= protocol.ByteCount(n) * maxDatagramSize
	s.now = s.now.Add(time.Millisecond)
}

func (s *testRenoSender) LoseNPackets(n int) {
	for range n {
		s.ackedPacketNumber++
		s.sender.OnCongestionEvent(s.ackedPacketNumber)
	}
	s.bytesInFlight -= protocol.ByteCount(n) * maxDatagramSize
}

func (s *testRenoSender) LosePacket(number protocol.PacketNumber) {
	s.sender.OnCongestionEvent(number)
	s.bytesInFlight -= maxDatagramSize
}

func TestRenoSenderStartup(t *testing.T) {
	sender := newTestRenoSender()

	// At startup make sure we are at the default.
	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())

	// Make sure we can send.
	require.Zero(t, sender.sender.TimeUntilSend())
	require.True(t, sender.sender.CanSend(sender.bytesInFlight))

	// And that window is un-affected.
	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())

	// Fill the send window with data, then verify that we can't send.
	sender.SendAvailableSendWindow()
	require.False(t, sender.sender.CanSend(sender.bytesInFlight))
}

func TestRenoSenderPacing(t *testing.T) {
	sender := newTestRenoSender()

	// Set up RTT and advance clock
	sender.rttStats.UpdateRTT(10*time.Millisecond, 0)
	sender.now = sender.now.Add(time.Hour)

	// Fill the send window with data, then verify that we can't send.
	sender.SendAvailableSendWindow()
	sender.AckNPackets(1)

	// Check that we can't send immediately due to pacing
	delay := sender.sender.TimeUntilSend()
	require.NotZero(t, delay)
	require.Less(t, delay.Sub(sender.now), time.Hour)
}

func TestRenoSenderPacingRate(t *testing.T) {
	const rtt = 100 * time.Millisecond
	now := monotime.Now()
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)
	sender := NewRenoSender(rttStats, maxDatagramSize, nil)

	// Exhaust the burst allowance before checking the pacing rate.
	for pn := protocol.PacketNumber(0); sender.HasPacingBudget(now); pn++ {
		sender.OnPacketSent(now, pn, maxDatagramSize, true)
	}
	require.Equal(t, rtt/(2*initialCongestionWindow), sender.TimeUntilSend().Sub(now))

	sender.OnCongestionEvent(0)
	require.False(t, sender.InSlowStart())
	wantDelay := float64(rtt) * float64(maxDatagramSize) / (1.25 * float64(sender.GetCongestionWindow()))
	require.InDelta(t, wantDelay, float64(sender.TimeUntilSend().Sub(now)), float64(time.Microsecond))
}

func TestRenoSenderPacingInitialPacketSize(t *testing.T) {
	const size = 1500
	now := monotime.Now()
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(time.Second, 0)
	sender := NewRenoSender(rttStats, size, nil)

	for pn := protocol.PacketNumber(0); sender.HasPacingBudget(now); pn++ {
		sender.OnPacketSent(now, pn, size, true)
	}
	require.True(t, sender.HasPacingBudget(sender.TimeUntilSend()))
}

func TestRenoSenderApplicationLimitedSlowStart(t *testing.T) {
	sender := newTestRenoSender()

	// At startup make sure we can send.
	require.True(t, sender.sender.CanSend(0))
	require.Zero(t, sender.sender.TimeUntilSend())

	// Send exactly 10 packets and ensure the CWND ends at 14 packets.
	const numberOfAcks = 5
	sender.SendAvailableSendWindow()
	for range numberOfAcks {
		sender.AckNPackets(2)
	}

	bytesToSend := sender.sender.GetCongestionWindow()
	// It's expected 2 acks will arrive when the bytes_in_flight are greater than
	// half the CWND.
	require.Equal(t, defaultWindowTCP+maxDatagramSize*2*2, bytesToSend)
}

func TestRenoSenderExponentialSlowStart(t *testing.T) {
	sender := newTestRenoSender()

	// At startup make sure we can send.
	require.True(t, sender.sender.CanSend(0))
	require.Zero(t, sender.sender.TimeUntilSend())

	const numberOfAcks = 20
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}

	cwnd := sender.sender.GetCongestionWindow()
	require.Equal(t, defaultWindowTCP+maxDatagramSize*2*numberOfAcks, cwnd)
	require.Equal(t, BandwidthFromDelta(cwnd, sender.rttStats.SmoothedRTT()), sender.sender.BandwidthEstimate())
}

func TestRenoSenderSlowStartPacketLoss(t *testing.T) {
	sender := newTestRenoSender()

	const numberOfAcks = 10
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}
	sender.SendAvailableSendWindow()
	expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Lose a packet to exit slow start.
	sender.LoseNPackets(1)
	packetsInRecoveryWindow := expectedSendWindow / maxDatagramSize

	// We should now have fallen out of slow start with a reduced window.
	expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Recovery phase. We need to ack every packet in the recovery window before
	// we exit recovery.
	numberOfPacketsInWindow := expectedSendWindow / maxDatagramSize
	sender.AckNPackets(int(packetsInRecoveryWindow))
	sender.SendAvailableSendWindow()
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// We need to ack an entire window before we increase CWND by 1.
	sender.AckNPackets(int(numberOfPacketsInWindow) - 2)
	sender.SendAvailableSendWindow()
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Next ack should increase cwnd by 1.
	sender.AckNPackets(1)
	expectedSendWindow += maxDatagramSize
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
}

func TestRenoSenderSlowStartPacketLossPRR(t *testing.T) {
	sender := newTestRenoSender()

	// Test based on the first example in RFC6937.
	// Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
	const numberOfAcks = 5
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}
	sender.SendAvailableSendWindow()
	expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	sender.LoseNPackets(1)

	// We should now have fallen out of slow start with a reduced window.
	sendWindowBeforeLoss := expectedSendWindow
	expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Testing TCP proportional rate reduction.
	// We should send packets paced over the received acks for the remaining
	// outstanding packets. The number of packets before we exit recovery is the
	// original CWND minus the packet that has been lost and the one which
	// triggered the loss.
	remainingPacketsInRecovery := sendWindowBeforeLoss/maxDatagramSize - 2

	for range remainingPacketsInRecovery {
		sender.AckNPackets(1)
		sender.SendAvailableSendWindow()
		require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
	}

	// We need to ack another window before we increase CWND by 1.
	numberOfPacketsInWindow := expectedSendWindow / maxDatagramSize
	for range numberOfPacketsInWindow {
		sender.AckNPackets(1)
		require.Equal(t, 1, sender.SendAvailableSendWindow())
		require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
	}

	sender.AckNPackets(1)
	expectedSendWindow += maxDatagramSize
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
}

func TestRenoSenderSlowStartBurstPacketLossPRR(t *testing.T) {
	sender := newTestRenoSender()

	// Test based on the second example in RFC6937, though we also implement
	// forward acknowledgements, so the first two incoming acks will trigger
	// PRR immediately.
	// Ack 20 packets in 10 acks to raise the CWND to 30.
	const numberOfAcks = 10
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}
	sender.SendAvailableSendWindow()
	expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Lose one more than the congestion window reduction, so that after loss,
	// bytes_in_flight is lesser than the congestion window.
	sendWindowAfterLoss := protocol.ByteCount(renoBeta * float32(expectedSendWindow))
	numPacketsToLose := (expectedSendWindow-sendWindowAfterLoss)/maxDatagramSize + 1
	sender.LoseNPackets(int(numPacketsToLose))
	// Immediately after the loss, ensure at least one packet can be sent.
	// Losses without subsequent acks can occur with timer based loss detection.
	require.True(t, sender.sender.CanSend(sender.bytesInFlight))
	sender.AckNPackets(1)

	// We should now have fallen out of slow start with a reduced window.
	expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Only 2 packets should be allowed to be sent, per PRR-SSRB
	require.Equal(t, 2, sender.SendAvailableSendWindow())

	// Ack the next packet, which triggers another loss.
	sender.LoseNPackets(1)
	sender.AckNPackets(1)

	// Send 2 packets to simulate PRR-SSRB.
	require.Equal(t, 2, sender.SendAvailableSendWindow())

	// Ack the next packet, which triggers another loss.
	sender.LoseNPackets(1)
	sender.AckNPackets(1)

	// Send 2 packets to simulate PRR-SSRB.
	require.Equal(t, 2, sender.SendAvailableSendWindow())

	// Exit recovery and return to sending at the new rate.
	for range numberOfAcks {
		sender.AckNPackets(1)
		require.Equal(t, 1, sender.SendAvailableSendWindow())
	}
}

func TestRenoSenderMultipleLossesInOneWindow(t *testing.T) {
	sender := newTestRenoSender()

	sender.SendAvailableSendWindow()
	initialWindow := sender.sender.GetCongestionWindow()
	sender.LosePacket(sender.ackedPacketNumber + 1)
	postLossWindow := sender.sender.GetCongestionWindow()
	require.Greater(t, initialWindow, postLossWindow)
	sender.LosePacket(sender.ackedPacketNumber + 3)
	require.Equal(t, postLossWindow, sender.sender.GetCongestionWindow())
	sender.LosePacket(sender.packetNumber - 1)
	require.Equal(t, postLossWindow, sender.sender.GetCongestionWindow())

	// Lose a later packet and ensure the window decreases.
	sender.LosePacket(sender.packetNumber)
	require.Greater(t, postLossWindow, sender.sender.GetCongestionWindow())
}

func TestRenoSenderSpuriousLoss(t *testing.T) {
	sender := newTestRenoSender()
	sender.SendAvailableSendWindow()
	sender.LoseNPackets(1)
	sender.AckNPackets(9)

	sender.SendAvailableSendWindow()
	sender.AckNPackets(1) // packet 11 exits recovery and earns one ACK of Reno credit
	window := sender.sender.GetCongestionWindow()
	sender.LoseNPackets(2) // packets 12 and 13 belong to the new recovery period
	reducedWindow := sender.sender.GetCongestionWindow()
	sender.sender.OnSpuriousLoss(1)
	require.Equal(t, reducedWindow, sender.sender.GetCongestionWindow())
	sender.sender.OnSpuriousLoss(12)
	require.Equal(t, reducedWindow, sender.sender.GetCongestionWindow())
	sender.sender.OnSpuriousLoss(13)
	require.Equal(t, window, sender.sender.GetCongestionWindow())
	require.Equal(t, window, sender.sender.slowStartThreshold)
	require.False(t, sender.sender.InRecovery())
	require.Zero(t, sender.sender.undoState)

	// Restoring the ACK credit lets the seventh ACK grow the window.
	sender.AckNPackets(4)
	sender.SendAvailableSendWindow()
	sender.AckNPackets(1)
	require.Equal(t, window, sender.sender.GetCongestionWindow())
	sender.AckNPackets(1)
	require.Equal(t, window+maxDatagramSize, sender.sender.GetCongestionWindow())
}

func TestRenoSenderSpuriousLossAfterWindowGrowth(t *testing.T) {
	sender := newTestRenoSender()
	sender.SendAvailableSendWindow()
	sender.LoseNPackets(1)
	sender.AckNPackets(9)
	for sender.sender.GetCongestionWindow() <= defaultWindowTCP {
		sender.AckNPackets(sender.SendAvailableSendWindow())
	}
	window := sender.sender.GetCongestionWindow()
	sender.sender.OnSpuriousLoss(1)
	require.Equal(t, window, sender.sender.GetCongestionWindow())
	require.False(t, sender.sender.InSlowStart())
	require.Zero(t, sender.sender.undoState)
}

func TestRenoSenderSpuriousLossWithECN(t *testing.T) {
	for _, ecnFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("ECN first %t", ecnFirst), func(t *testing.T) {
			sender := newTestRenoSender()
			sender.SendAvailableSendWindow()
			if ecnFirst {
				sender.sender.OnCongestionEvent(10)
			}
			sender.LoseNPackets(1)
			if !ecnFirst {
				sender.sender.OnCongestionEvent(10)
			}
			window := sender.sender.GetCongestionWindow()
			sender.sender.OnSpuriousLoss(1)
			require.Equal(t, window, sender.sender.GetCongestionWindow())
			require.False(t, sender.sender.InSlowStart())
		})
	}
}

func TestRenoSender1ConnectionCongestionAvoidanceAtEndOfRecovery(t *testing.T) {
	sender := newTestRenoSender()

	// Ack 10 packets in 5 acks to raise the CWND to 20.
	const numberOfAcks = 5
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}
	sender.SendAvailableSendWindow()
	expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	sender.LoseNPackets(1)

	// We should now have fallen out of slow start with a reduced window.
	expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// No congestion window growth should occur in recovery phase, i.e., until the
	// currently outstanding 20 packets are acked.
	for range 10 {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		require.True(t, sender.sender.InRecovery())
		sender.AckNPackets(2)
		require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
	}
	require.False(t, sender.sender.InRecovery())

	// Out of recovery now. Congestion window should not grow during RTT.
	for i := protocol.ByteCount(0); i < expectedSendWindow/maxDatagramSize-2; i += 2 {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
		require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
	}

	// Next ack should cause congestion window to grow by 1MSS.
	sender.SendAvailableSendWindow()
	sender.AckNPackets(2)
	expectedSendWindow += maxDatagramSize
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
}

func TestRenoSenderNoPRR(t *testing.T) {
	sender := newTestRenoSender()

	sender.SendAvailableSendWindow()
	sender.LoseNPackets(9)
	sender.AckNPackets(1)

	require.Equal(t, protocol.ByteCount(renoBeta*float32(defaultWindowTCP)), sender.sender.GetCongestionWindow())
	windowInPackets := int(renoBeta * float32(defaultWindowTCP) / float32(maxDatagramSize))
	numSent := sender.SendAvailableSendWindow()
	require.Equal(t, windowInPackets, numSent)
}

func TestRenoSenderSlowStartsUpToMaximumCongestionWindow(t *testing.T) {
	rttStats := utils.RTTStats{}
	const initialMaxCongestionWindow = protocol.MaxCongestionWindowPackets * initialMaxDatagramSize
	sender := newRenoSender(
		&rttStats,
		protocol.InitialPacketSize,
		initialCongestionWindowPackets*maxDatagramSize,
		nil,
	)

	for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
		sender.MaybeExitSlowStart()
		sender.OnPacketAcked(protocol.PacketNumber(i), sender.GetCongestionWindow())
	}
	require.Equal(t, initialMaxCongestionWindow, sender.GetCongestionWindow())
}

func TestRenoSenderMaximumPacketSizeReduction(t *testing.T) {
	sender := newTestRenoSender()
	require.NotPanics(t, func() { sender.sender.SetMaxDatagramSize(protocol.MinInitialPacketSize) })
}

func TestRenoSenderSlowStartsPacketSizeIncrease(t *testing.T) {
	rttStats := utils.RTTStats{}
	sender := newRenoSender(
		&rttStats,
		protocol.InitialPacketSize,
		initialCongestionWindowPackets*maxDatagramSize,
		nil,
	)
	const packetSize = initialMaxDatagramSize + 100
	sender.SetMaxDatagramSize(packetSize)
	for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
		sender.OnPacketAcked(protocol.PacketNumber(i), sender.GetCongestionWindow())
	}
	const maxCwnd = protocol.MaxCongestionWindowPackets * packetSize
	require.Greater(t, sender.GetCongestionWindow(), maxCwnd)
	require.LessOrEqual(t, sender.GetCongestionWindow(), maxCwnd+packetSize)
}
