package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

const MaxCongestionWindow protocol.ByteCount = 200 * maxDatagramSize

var _ = Describe("Cubic Sender", func() {
	var (
		sender            *cubicSender
		clock             mockClock
		bytesInFlight     protocol.ByteCount
		packetNumber      protocol.PacketNumber
		ackedPacketNumber protocol.PacketNumber
		rttStats          *utils.RTTStats
	)

	BeforeEach(func() {
		bytesInFlight = 0
		packetNumber = 1
		ackedPacketNumber = 0
		clock = mockClock{}
		rttStats = utils.NewRTTStats()
		sender = newCubicSender(
			&clock,
			rttStats,
			true, /*reno*/
			protocol.InitialPacketSizeIPv4,
			initialCongestionWindowPackets*maxDatagramSize,
			MaxCongestionWindow,
			nil,
		)
	})

	SendAvailableSendWindowLen := func(packetLength protocol.ByteCount) int {
		var packetsSent int
		for sender.CanSend(bytesInFlight) {
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, packetLength, true)
			packetNumber++
			packetsSent++
			bytesInFlight += packetLength
		}
		return packetsSent
	}

	// Normal is that TCP acks every other segment.
	AckNPackets := func(n int) {
		rttStats.UpdateRTT(60*time.Millisecond, 0, clock.Now())
		sender.MaybeExitSlowStart()
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			sender.OnPacketAcked(ackedPacketNumber, maxDatagramSize, bytesInFlight, clock.Now())
		}
		bytesInFlight -= protocol.ByteCount(n) * maxDatagramSize
		clock.Advance(time.Millisecond)
	}

	LoseNPacketsLen := func(n int, packetLength protocol.ByteCount) {
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			sender.OnPacketLost(ackedPacketNumber, packetLength, bytesInFlight)
		}
		bytesInFlight -= protocol.ByteCount(n) * packetLength
	}

	// Does not increment acked_packet_number_.
	LosePacket := func(number protocol.PacketNumber) {
		sender.OnPacketLost(number, maxDatagramSize, bytesInFlight)
		bytesInFlight -= maxDatagramSize
	}

	SendAvailableSendWindow := func() int { return SendAvailableSendWindowLen(maxDatagramSize) }
	LoseNPackets := func(n int) { LoseNPacketsLen(n, maxDatagramSize) }

	It("has the right values at startup", func() {
		// At startup make sure we are at the default.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.CanSend(bytesInFlight)).To(BeTrue())
		// And that window is un-affected.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		Expect(sender.CanSend(bytesInFlight)).To(BeFalse())
	})

	It("paces", func() {
		rttStats.UpdateRTT(10*time.Millisecond, 0, time.Now())
		clock.Advance(time.Hour)
		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		AckNPackets(1)
		delay := sender.TimeUntilSend(bytesInFlight)
		Expect(delay).ToNot(BeZero())
		Expect(delay).ToNot(Equal(utils.InfDuration))
	})

	It("application limited slow start", func() {
		// Send exactly 10 packets and ensure the CWND ends at 14 packets.
		const numberOfAcks = 5
		// At startup make sure we can send.
		Expect(sender.CanSend(0)).To(BeTrue())
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		SendAvailableSendWindow()
		for i := 0; i < numberOfAcks; i++ {
			AckNPackets(2)
		}
		bytesToSend := sender.GetCongestionWindow()
		// It's expected 2 acks will arrive when the bytes_in_flight are greater than
		// half the CWND.
		Expect(bytesToSend).To(Equal(defaultWindowTCP + maxDatagramSize*2*2))
	})

	It("exponential slow start", func() {
		const numberOfAcks = 20
		// At startup make sure we can send.
		Expect(sender.CanSend(0)).To(BeTrue())
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.BandwidthEstimate()).To(Equal(infBandwidth))
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		cwnd := sender.GetCongestionWindow()
		Expect(cwnd).To(Equal(defaultWindowTCP + maxDatagramSize*2*numberOfAcks))
		Expect(sender.BandwidthEstimate()).To(Equal(BandwidthFromDelta(cwnd, rttStats.SmoothedRTT())))
	})

	It("slow start packet loss", func() {
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start.
		LoseNPackets(1)
		packetsInRecoveryWindow := expectedSendWindow / maxDatagramSize

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		numberOfPacketsInWindow := expectedSendWindow / maxDatagramSize
		AckNPackets(int(packetsInRecoveryWindow))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// We need to ack an entire window before we increase CWND by 1.
		AckNPackets(int(numberOfPacketsInWindow) - 2)
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expectedSendWindow += maxDatagramSize
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.hybridSlowStart.Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.hybridSlowStart.Started()).To(BeFalse())
	})

	It("slow start packet loss PRR", func() {
		// Test based on the first example in RFC6937.
		// Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		sendWindowBeforeLoss := expectedSendWindow
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Testing TCP proportional rate reduction.
		// We should send packets paced over the received acks for the remaining
		// outstanding packets. The number of packets before we exit recovery is the
		// original CWND minus the packet that has been lost and the one which
		// triggered the loss.
		remainingPacketsInRecovery := sendWindowBeforeLoss/maxDatagramSize - 2

		for i := protocol.ByteCount(0); i < remainingPacketsInRecovery; i++ {
			AckNPackets(1)
			SendAvailableSendWindow()
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// We need to ack another window before we increase CWND by 1.
		numberOfPacketsInWindow := expectedSendWindow / maxDatagramSize
		for i := protocol.ByteCount(0); i < numberOfPacketsInWindow; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		AckNPackets(1)
		expectedSendWindow += maxDatagramSize
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("slow start burst packet loss PRR", func() {
		// Test based on the second example in RFC6937, though we also implement
		// forward acknowledgements, so the first two incoming acks will trigger
		// PRR immediately.
		// Ack 20 packets in 10 acks to raise the CWND to 30.
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose one more than the congestion window reduction, so that after loss,
		// bytes_in_flight is lesser than the congestion window.
		sendWindowAfterLoss := protocol.ByteCount(renoBeta * float32(expectedSendWindow))
		numPacketsToLose := (expectedSendWindow-sendWindowAfterLoss)/maxDatagramSize + 1
		LoseNPackets(int(numPacketsToLose))
		// Immediately after the loss, ensure at least one packet can be sent.
		// Losses without subsequent acks can occur with timer based loss detection.
		Expect(sender.CanSend(bytesInFlight)).To(BeTrue())
		AckNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Only 2 packets should be allowed to be sent, per PRR-SSRB
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Ack the next packet, which triggers another loss.
		LoseNPackets(1)
		AckNPackets(1)

		// Send 2 packets to simulate PRR-SSRB.
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Ack the next packet, which triggers another loss.
		LoseNPackets(1)
		AckNPackets(1)

		// Send 2 packets to simulate PRR-SSRB.
		Expect(SendAvailableSendWindow()).To(Equal(2))

		// Exit recovery and return to sending at the new rate.
		for i := 0; i < numberOfAcks; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
		}
	})

	It("RTO congestion window", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.slowStartThreshold).To(Equal(protocol.MaxByteCount))

		// Expect the window to decrease to the minimum once the RTO fires
		// and slow start threshold to be set to 1/2 of the CWND.
		sender.OnRetransmissionTimeout(true)
		Expect(sender.GetCongestionWindow()).To(Equal(2 * maxDatagramSize))
		Expect(sender.slowStartThreshold).To(Equal(5 * maxDatagramSize))
	})

	It("RTO congestion window no retransmission", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Expect the window to remain unchanged if the RTO fires but no
		// packets are retransmitted.
		sender.OnRetransmissionTimeout(false)
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
	})

	It("tcp cubic reset epoch on quiescence", func() {
		const maxCongestionWindow = 50
		const maxCongestionWindowBytes = maxCongestionWindow * maxDatagramSize
		sender = newCubicSender(&clock, rttStats, false, protocol.InitialPacketSizeIPv4, initialCongestionWindowPackets*maxDatagramSize, maxCongestionWindowBytes, nil)

		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		savedCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(savedCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		savedCwnd = sender.GetCongestionWindow()
		numSent = SendAvailableSendWindow()
		for i := 0; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(savedCwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		savedCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(savedCwnd).To(BeNumerically("~", sender.GetCongestionWindow(), maxDatagramSize))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("multiple losses in one window", func() {
		SendAvailableSendWindow()
		initialWindow := sender.GetCongestionWindow()
		LosePacket(ackedPacketNumber + 1)
		postLossWindow := sender.GetCongestionWindow()
		Expect(initialWindow).To(BeNumerically(">", postLossWindow))
		LosePacket(ackedPacketNumber + 3)
		Expect(sender.GetCongestionWindow()).To(Equal(postLossWindow))
		LosePacket(packetNumber - 1)
		Expect(sender.GetCongestionWindow()).To(Equal(postLossWindow))

		// Lose a later packet and ensure the window decreases.
		LosePacket(packetNumber)
		Expect(postLossWindow).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("1 connection congestion avoidance at end of recovery", func() {
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// No congestion window growth should occur in recovery phase, i.e., until the
		// currently outstanding 20 packets are acked.
		for i := 0; i < 10; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			Expect(sender.InRecovery()).To(BeTrue())
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}
		Expect(sender.InRecovery()).To(BeFalse())

		// Out of recovery now. Congestion window should not grow during RTT.
		for i := protocol.ByteCount(0); i < expectedSendWindow/maxDatagramSize-2; i += 2 {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += maxDatagramSize
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("no PRR", func() {
		SendAvailableSendWindow()
		LoseNPackets(9)
		AckNPackets(1)

		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(renoBeta * float32(defaultWindowTCP))))
		windowInPackets := renoBeta * float32(defaultWindowTCP) / float32(maxDatagramSize)
		numSent := SendAvailableSendWindow()
		Expect(numSent).To(BeEquivalentTo(windowInPackets))
	})

	It("reset after connection migration", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.slowStartThreshold).To(Equal(protocol.MaxByteCount))

		// Starts with slow start.
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (maxDatagramSize * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Loses a packet to exit slow start.
		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window. Slow
		// start threshold is also updated.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		Expect(sender.slowStartThreshold).To(Equal(expectedSendWindow))

		// Resets cwnd and slow start threshold on connection migrations.
		sender.OnConnectionMigration()
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.slowStartThreshold).To(Equal(MaxCongestionWindow))
		Expect(sender.hybridSlowStart.Started()).To(BeFalse())
	})

	It("slow starts up to the maximum congestion window", func() {
		const initialMaxCongestionWindow = protocol.MaxCongestionWindowPackets * initialMaxDatagramSize
		sender = newCubicSender(&clock, rttStats, true, protocol.InitialPacketSizeIPv4, initialCongestionWindowPackets*maxDatagramSize, initialMaxCongestionWindow, nil)

		for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
			sender.MaybeExitSlowStart()
			sender.OnPacketAcked(protocol.PacketNumber(i), 1350, sender.GetCongestionWindow(), clock.Now())
		}
		Expect(sender.GetCongestionWindow()).To(Equal(initialMaxCongestionWindow))
	})

	It("doesn't allow reductions of the maximum packet size", func() {
		Expect(func() { sender.SetMaxDatagramSize(initialMaxDatagramSize - 1) }).To(Panic())
	})

	It("slow starts up to maximum congestion window, if larger packets are sent", func() {
		const initialMaxCongestionWindow = protocol.MaxCongestionWindowPackets * initialMaxDatagramSize
		sender = newCubicSender(&clock, rttStats, true, protocol.InitialPacketSizeIPv4, initialCongestionWindowPackets*maxDatagramSize, initialMaxCongestionWindow, nil)
		const packetSize = initialMaxDatagramSize + 100
		sender.SetMaxDatagramSize(packetSize)
		for i := 1; i < protocol.MaxCongestionWindowPackets; i++ {
			sender.OnPacketAcked(protocol.PacketNumber(i), packetSize, sender.GetCongestionWindow(), clock.Now())
		}
		const maxCwnd = protocol.MaxCongestionWindowPackets * packetSize
		Expect(sender.GetCongestionWindow()).To(And(
			BeNumerically(">", maxCwnd),
			BeNumerically("<=", maxCwnd+packetSize),
		))
	})

	It("limit cwnd increase in congestion avoidance", func() {
		// Enable Cubic.
		sender = newCubicSender(&clock, rttStats, false, protocol.InitialPacketSizeIPv4, initialCongestionWindowPackets*maxDatagramSize, MaxCongestionWindow, nil)
		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		savedCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(savedCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		savedCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()

		// Ack packets until the CWND increases.
		for sender.GetCongestionWindow() == savedCwnd {
			AckNPackets(1)
			SendAvailableSendWindow()
		}
		// Bytes in flight may be larger than the CWND if the CWND isn't an exact
		// multiple of the packet sizes being sent.
		Expect(bytesInFlight).To(BeNumerically(">=", sender.GetCongestionWindow()))
		savedCwnd = sender.GetCongestionWindow()

		// Advance time 2 seconds waiting for an ack.
		clock.Advance(2 * time.Second)

		// Ack two packets.  The CWND should increase by only one packet.
		AckNPackets(2)
		Expect(sender.GetCongestionWindow()).To(Equal(savedCwnd + maxDatagramSize))
	})
})
