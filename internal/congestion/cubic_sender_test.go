package congestion

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

const (
	initialCongestionWindowPackets = 10
	defaultWindowTCP               = protocol.ByteCount(initialCongestionWindowPackets) * maxDatagramSize
)

type mockClock time.Time

func (c *mockClock) Now() time.Time {
	return time.Time(*c)
}

func (c *mockClock) Advance(d time.Duration) {
	*c = mockClock(time.Time(*c).Add(d))
}

const MaxCongestionWindow = 200 * maxDatagramSize

type testCubicSender struct {
	sender            *cubicSender
	clock             *mockClock
	rttStats          *utils.RTTStats
	bytesInFlight     protocol.ByteCount
	packetNumber      protocol.PacketNumber
	ackedPacketNumber protocol.PacketNumber
}

func newTestCubicSender(cubic bool) *testCubicSender {
	clock := mockClock{}
	rttStats := utils.RTTStats{}
	return &testCubicSender{
		clock:        &clock,
		rttStats:     &rttStats,
		packetNumber: 1,
		sender: newCubicSender(
			&clock,
			&rttStats,
			!cubic,
			protocol.InitialPacketSize,
			initialCongestionWindowPackets*maxDatagramSize,
			MaxCongestionWindow,
			nil,
		),
	}
}

func (s *testCubicSender) SendAvailableSendWindowLen(packetLength protocol.ByteCount) int {
	var packetsSent int
	for s.sender.CanSend(s.bytesInFlight) {
		s.sender.OnPacketSent(s.clock.Now(), s.bytesInFlight, s.packetNumber, packetLength, true)
		s.packetNumber++
		packetsSent++
		s.bytesInFlight += packetLength
	}
	return packetsSent
}

func (s *testCubicSender) AckNPackets(n int) {
	s.rttStats.UpdateRTT(60*time.Millisecond, 0)
	s.sender.MaybeExitSlowStart()
	for range n {
		s.ackedPacketNumber++
		s.sender.OnPacketAcked(s.ackedPacketNumber, maxDatagramSize, s.bytesInFlight, s.clock.Now())
	}
	s.bytesInFlight -= protocol.ByteCount(n) * maxDatagramSize
	s.clock.Advance(time.Millisecond)
}

func (s *testCubicSender) LoseNPacketsLen(n int, packetLength protocol.ByteCount) {
	for range n {
		s.ackedPacketNumber++
		s.sender.OnCongestionEvent(s.ackedPacketNumber, packetLength, s.bytesInFlight)
	}
	s.bytesInFlight -= protocol.ByteCount(n) * packetLength
}

func (s *testCubicSender) LosePacket(number protocol.PacketNumber) {
	s.sender.OnCongestionEvent(number, maxDatagramSize, s.bytesInFlight)
	s.bytesInFlight -= maxDatagramSize
}

func (s *testCubicSender) SendAvailableSendWindow() int {
	return s.SendAvailableSendWindowLen(maxDatagramSize)
}

func (s *testCubicSender) LoseNPackets(n int) {
	s.LoseNPacketsLen(n, maxDatagramSize)
}

func TestCubicSenderStartup(t *testing.T) {
	sender := newTestCubicSender(false)

	// At startup make sure we are at the default.
	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())

	// Make sure we can send.
	require.Zero(t, sender.sender.TimeUntilSend(0))
	require.True(t, sender.sender.CanSend(sender.bytesInFlight))

	// And that window is un-affected.
	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())

	// Fill the send window with data, then verify that we can't send.
	sender.SendAvailableSendWindow()
	require.False(t, sender.sender.CanSend(sender.bytesInFlight))
}

func TestCubicSenderPacing(t *testing.T) {
	sender := newTestCubicSender(false)

	// Set up RTT and advance clock
	sender.rttStats.UpdateRTT(10*time.Millisecond, 0)
	sender.clock.Advance(time.Hour)

	// Fill the send window with data, then verify that we can't send.
	sender.SendAvailableSendWindow()
	sender.AckNPackets(1)

	// Check that we can't send immediately due to pacing
	delay := sender.sender.TimeUntilSend(sender.bytesInFlight)
	require.NotZero(t, delay)
	require.Less(t, delay.Sub(time.Time(*sender.clock)), time.Hour)
}

func TestCubicSenderApplicationLimitedSlowStart(t *testing.T) {
	sender := newTestCubicSender(false)

	// At startup make sure we can send.
	require.True(t, sender.sender.CanSend(0))
	require.Zero(t, sender.sender.TimeUntilSend(0))

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

func TestCubicSenderExponentialSlowStart(t *testing.T) {
	sender := newTestCubicSender(false)

	// At startup make sure we can send.
	require.True(t, sender.sender.CanSend(0))
	require.Zero(t, sender.sender.TimeUntilSend(0))
	require.Equal(t, infBandwidth, sender.sender.BandwidthEstimate())

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

func TestCubicSenderSlowStartPacketLoss(t *testing.T) {
	sender := newTestCubicSender(false)

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
	fmt.Println(numberOfPacketsInWindow)
	sender.AckNPackets(int(numberOfPacketsInWindow) - 2)
	sender.SendAvailableSendWindow()
	fmt.Println(sender.clock.Now())
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Next ack should increase cwnd by 1.
	sender.AckNPackets(1)
	expectedSendWindow += maxDatagramSize
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Now RTO and ensure slow start gets reset.
	require.True(t, sender.sender.hybridSlowStart.Started())
	sender.sender.OnRetransmissionTimeout(true)
	require.False(t, sender.sender.hybridSlowStart.Started())
}

func TestCubicSenderSlowStartPacketLossPRR(t *testing.T) {
	sender := newTestCubicSender(false)

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

	for i := protocol.ByteCount(0); i < remainingPacketsInRecovery; i++ {
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

func TestCubicSenderSlowStartBurstPacketLossPRR(t *testing.T) {
	sender := newTestCubicSender(false)

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

func TestCubicSenderRTOCongestionWindow(t *testing.T) {
	sender := newTestCubicSender(false)

	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())
	require.Equal(t, protocol.MaxByteCount, sender.sender.slowStartThreshold)

	// Expect the window to decrease to the minimum once the RTO fires
	// and slow start threshold to be set to 1/2 of the CWND.
	sender.sender.OnRetransmissionTimeout(true)
	require.Equal(t, 2*maxDatagramSize, sender.sender.GetCongestionWindow())
	require.Equal(t, 5*maxDatagramSize, sender.sender.slowStartThreshold)
}

func TestCubicSenderTCPCubicResetEpochOnQuiescence(t *testing.T) {
	sender := newTestCubicSender(true)

	const maxCongestionWindow = 50
	const maxCongestionWindowBytes = maxCongestionWindow * maxDatagramSize

	numSent := sender.SendAvailableSendWindow()

	// Make sure we fall out of slow start.
	savedCwnd := sender.sender.GetCongestionWindow()
	sender.LoseNPackets(1)
	require.Greater(t, savedCwnd, sender.sender.GetCongestionWindow())

	// Ack the rest of the outstanding packets to get out of recovery.
	for i := 1; i < numSent; i++ {
		sender.AckNPackets(1)
	}
	require.Zero(t, sender.bytesInFlight)

	// Send a new window of data and ack all; cubic growth should occur.
	savedCwnd = sender.sender.GetCongestionWindow()
	numSent = sender.SendAvailableSendWindow()
	for range numSent {
		sender.AckNPackets(1)
	}
	require.Less(t, savedCwnd, sender.sender.GetCongestionWindow())
	require.Greater(t, maxCongestionWindowBytes, sender.sender.GetCongestionWindow())
	require.Zero(t, sender.bytesInFlight)

	// Quiescent time of 100 seconds
	sender.clock.Advance(100 * time.Second)

	// Send new window of data and ack one packet. Cubic epoch should have
	// been reset; ensure cwnd increase is not dramatic.
	savedCwnd = sender.sender.GetCongestionWindow()
	sender.SendAvailableSendWindow()
	sender.AckNPackets(1)
	require.InDelta(t, float64(savedCwnd), float64(sender.sender.GetCongestionWindow()), float64(maxDatagramSize))
	require.Greater(t, maxCongestionWindowBytes, sender.sender.GetCongestionWindow())
}

func TestCubicSenderMultipleLossesInOneWindow(t *testing.T) {
	sender := newTestCubicSender(false)

	sender.SendAvailableSendWindow()
	initialWindow := sender.sender.GetCongestionWindow()
	sender.LosePacket(sender.ackedPacketNumber + 1)
	postLossWindow := sender.sender.GetCongestionWindow()
	require.True(t, initialWindow > postLossWindow)
	sender.LosePacket(sender.ackedPacketNumber + 3)
	require.Equal(t, postLossWindow, sender.sender.GetCongestionWindow())
	sender.LosePacket(sender.packetNumber - 1)
	require.Equal(t, postLossWindow, sender.sender.GetCongestionWindow())

	// Lose a later packet and ensure the window decreases.
	sender.LosePacket(sender.packetNumber)
	require.True(t, postLossWindow > sender.sender.GetCongestionWindow())
}

func TestCubicSender1ConnectionCongestionAvoidanceAtEndOfRecovery(t *testing.T) {
	sender := newTestCubicSender(false)

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

func TestCubicSenderNoPRR(t *testing.T) {
	sender := newTestCubicSender(false)

	sender.SendAvailableSendWindow()
	sender.LoseNPackets(9)
	sender.AckNPackets(1)

	require.Equal(t, protocol.ByteCount(renoBeta*float32(defaultWindowTCP)), sender.sender.GetCongestionWindow())
	windowInPackets := int(renoBeta * float32(defaultWindowTCP) / float32(maxDatagramSize))
	numSent := sender.SendAvailableSendWindow()
	require.Equal(t, windowInPackets, numSent)
}

func TestCubicSenderResetAfterConnectionMigration(t *testing.T) {
	sender := newTestCubicSender(false)

	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())
	require.Equal(t, protocol.MaxByteCount, sender.sender.slowStartThreshold)

	// Starts with slow start.
	const numberOfAcks = 10
	for range numberOfAcks {
		// Send our full send window.
		sender.SendAvailableSendWindow()
		sender.AckNPackets(2)
	}
	sender.SendAvailableSendWindow()
	expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())

	// Loses a packet to exit slow start.
	sender.LoseNPackets(1)

	// We should now have fallen out of slow start with a reduced window. Slow
	// start threshold is also updated.
	expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
	require.Equal(t, expectedSendWindow, sender.sender.GetCongestionWindow())
	require.Equal(t, expectedSendWindow, sender.sender.slowStartThreshold)

	// Resets cwnd and slow start threshold on connection migrations.
	sender.sender.OnConnectionMigration()
	require.Equal(t, defaultWindowTCP, sender.sender.GetCongestionWindow())
	require.Equal(t, MaxCongestionWindow, sender.sender.slowStartThreshold)
	require.False(t, sender.sender.hybridSlowStart.Started())
}

func TestCubicSenderSlowStartsUpToMaximumCongestionWindow(t *testing.T) {
	clock := mockClock{}
	rttStats := utils.RTTStats{}
	const initialMaxCongestionWindow = protocol.MaxCongestionWindowPackets * initialMaxDatagramSize
	sender := newCubicSender(
		&clock,
		&rttStats,
		true,
		protocol.InitialPacketSize,
		initialCongestionWindowPackets*maxDatagramSize,
		initialMaxCongestionWindow,
		nil,
	)

	for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
		sender.MaybeExitSlowStart()
		sender.OnPacketAcked(protocol.PacketNumber(i), 1350, sender.GetCongestionWindow(), clock.Now())
	}
	require.Equal(t, initialMaxCongestionWindow, sender.GetCongestionWindow())
}

func TestCubicSenderMaximumPacketSizeReduction(t *testing.T) {
	sender := newTestCubicSender(false)
	require.Panics(t, func() { sender.sender.SetMaxDatagramSize(initialMaxDatagramSize - 1) })
}

func TestCubicSenderSlowStartsPacketSizeIncrease(t *testing.T) {
	clock := mockClock{}
	rttStats := utils.RTTStats{}
	const initialMaxCongestionWindow = protocol.MaxCongestionWindowPackets * initialMaxDatagramSize
	sender := newCubicSender(
		&clock,
		&rttStats,
		true,
		protocol.InitialPacketSize,
		initialCongestionWindowPackets*maxDatagramSize,
		initialMaxCongestionWindow,
		nil,
	)
	const packetSize = initialMaxDatagramSize + 100
	sender.SetMaxDatagramSize(packetSize)
	for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
		sender.OnPacketAcked(protocol.PacketNumber(i), packetSize, sender.GetCongestionWindow(), clock.Now())
	}
	const maxCwnd = protocol.MaxCongestionWindowPackets * packetSize
	require.True(t, sender.GetCongestionWindow() > maxCwnd)
	require.True(t, sender.GetCongestionWindow() <= maxCwnd+packetSize)
}

func TestCubicSenderLimitCwndIncreaseInCongestionAvoidance(t *testing.T) {
	// Enable Cubic.
	clock := mockClock{}
	rttStats := utils.RTTStats{}
	sender := newCubicSender(
		&clock,
		&rttStats,
		false,
		protocol.InitialPacketSize,
		initialCongestionWindowPackets*maxDatagramSize,
		MaxCongestionWindow,
		nil,
	)
	testSender := &testCubicSender{
		sender:   sender,
		clock:    &clock,
		rttStats: &rttStats,
	}

	numSent := testSender.SendAvailableSendWindow()

	// Make sure we fall out of slow start.
	savedCwnd := sender.GetCongestionWindow()
	testSender.LoseNPackets(1)
	require.Greater(t, savedCwnd, sender.GetCongestionWindow())

	// Ack the rest of the outstanding packets to get out of recovery.
	for i := 1; i < numSent; i++ {
		testSender.AckNPackets(1)
	}
	require.Equal(t, protocol.ByteCount(0), testSender.bytesInFlight)

	savedCwnd = sender.GetCongestionWindow()
	testSender.SendAvailableSendWindow()

	// Ack packets until the CWND increases.
	for sender.GetCongestionWindow() == savedCwnd {
		testSender.AckNPackets(1)
		testSender.SendAvailableSendWindow()
	}
	// Bytes in flight may be larger than the CWND if the CWND isn't an exact
	// multiple of the packet sizes being sent.
	require.GreaterOrEqual(t, testSender.bytesInFlight, sender.GetCongestionWindow())
	savedCwnd = sender.GetCongestionWindow()

	// Advance time 2 seconds waiting for an ack.
	clock.Advance(2 * time.Second)

	// Ack two packets.  The CWND should increase by only one packet.
	testSender.AckNPackets(2)
	require.Equal(t, savedCwnd+maxDatagramSize, sender.GetCongestionWindow())
}
