package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const initialCongestionWindowPackets protocol.PacketNumber = 10
const defaultWindowTCP = protocol.ByteCount(initialCongestionWindowPackets) * protocol.DefaultTCPMSS

type mockClock time.Time

func (c *mockClock) Now() time.Time {
	return time.Time(*c)
}

func (c *mockClock) Advance(d time.Duration) {
	*c = mockClock(time.Time(*c).Add(d))
}

const MaxCongestionWindow = protocol.PacketNumber(200)

var _ = Describe("Cubic Sender", func() {
	var (
		sender            SendAlgorithmWithDebugInfo
		clock             mockClock
		bytesInFlight     protocol.ByteCount
		packetNumber      protocol.PacketNumber
		ackedPacketNumber protocol.PacketNumber
		rttStats          *RTTStats
	)

	BeforeEach(func() {
		bytesInFlight = 0
		packetNumber = 1
		ackedPacketNumber = 0
		clock = mockClock{}
		rttStats = NewRTTStats()
		sender = NewCubicSender(&clock, rttStats, true /*reno*/, initialCongestionWindowPackets, MaxCongestionWindow)
	})

	SendAvailableSendWindowLen := func(packetLength protocol.ByteCount) int {
		// Send as long as TimeUntilSend returns InfDuration.
		packetsSent := 0
		for bytesInFlight < sender.GetCongestionWindow() {
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, packetLength, true)
			packetNumber++
			packetsSent++
			bytesInFlight += packetLength
		}
		return packetsSent
	}

	// Normal is that TCP acks every other segment.
	AckNPacketsLen := func(n int, packetLength protocol.ByteCount) {
		rttStats.UpdateRTT(60*time.Millisecond, 0, clock.Now())
		sender.MaybeExitSlowStart()
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			sender.OnPacketAcked(ackedPacketNumber, packetLength, bytesInFlight)
		}
		bytesInFlight -= protocol.ByteCount(n) * packetLength
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
		sender.OnPacketLost(number, protocol.DefaultTCPMSS, bytesInFlight)
		bytesInFlight -= protocol.DefaultTCPMSS
	}

	SendAvailableSendWindow := func() int { return SendAvailableSendWindowLen(protocol.DefaultTCPMSS) }
	AckNPackets := func(n int) { AckNPacketsLen(n, protocol.DefaultTCPMSS) }
	LoseNPackets := func(n int) { LoseNPacketsLen(n, protocol.DefaultTCPMSS) }

	It("has the right values at startup", func() {
		// At startup make sure we are at the default.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		// And that window is un-affected.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
	})

	It("paces", func() {
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
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		SendAvailableSendWindow()
		for i := 0; i < numberOfAcks; i++ {
			AckNPackets(2)
		}
		bytesToSend := sender.GetCongestionWindow()
		// It's expected 2 acks will arrive when the bytes_in_flight are greater than
		// half the CWND.
		Expect(bytesToSend).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*2))
	})

	It("exponential slow start", func() {
		const numberOfAcks = 20
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.BandwidthEstimate()).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		cwnd := sender.GetCongestionWindow()
		Expect(cwnd).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*numberOfAcks))
		Expect(sender.BandwidthEstimate()).To(Equal(BandwidthFromDelta(cwnd, rttStats.SmoothedRTT())))
	})

	It("slow start packet loss", func() {
		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start.
		LoseNPackets(1)
		packetsInRecoveryWindow := expectedSendWindow / protocol.DefaultTCPMSS

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		AckNPackets(int(packetsInRecoveryWindow))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// We need to ack an entire window before we increase CWND by 1.
		AckNPackets(int(numberOfPacketsInWindow) - 2)
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expectedSendWindow -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose 5 packets in recovery and verify that congestion window is reduced
		// further.
		LoseNPackets(5)
		expectedSendWindow -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		packetsInRecoveryWindow := expectedSendWindow / protocol.DefaultTCPMSS

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		AckNPackets(int(packetsInRecoveryWindow))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// We need to ack the rest of the window before cwnd increases by 1.
		AckNPackets(int(numberOfPacketsInWindow - 1))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start half packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window in half sized packets.
			SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
			AckNPackets(2)
		}
		SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expectedSendWindow -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose 10 packets in recovery and verify that congestion window is reduced
		// by 5 packets.
		LoseNPacketsLen(10, protocol.DefaultTCPMSS/2)
		expectedSendWindow -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	// this test doesn't work any more after introducing the pacing needed for QUIC
	PIt("no PRR when less than one packet in flight", func() {
		SendAvailableSendWindow()
		LoseNPackets(int(initialCongestionWindowPackets) - 1)
		AckNPackets(1)
		// PRR will allow 2 packets for every ack during recovery.
		Expect(SendAvailableSendWindow()).To(Equal(2))
		// Simulate abandoning all packets by supplying a bytes_in_flight of 0.
		// PRR should now allow a packet to be sent, even though prr's state
		// variables believe it has sent enough packets.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
	})

	It("slow start packet loss PRR", func() {
		sender.SetNumEmulatedConnections(1)
		// Test based on the first example in RFC6937.
		// Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
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
		remainingPacketsInRecovery := sendWindowBeforeLoss/protocol.DefaultTCPMSS - 2

		for i := protocol.ByteCount(0); i < remainingPacketsInRecovery; i++ {
			AckNPackets(1)
			SendAvailableSendWindow()
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// We need to ack another window before we increase CWND by 1.
		numberOfPacketsInWindow := expectedSendWindow / protocol.DefaultTCPMSS
		for i := protocol.ByteCount(0); i < numberOfPacketsInWindow; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		AckNPackets(1)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("slow start burst packet loss PRR", func() {
		sender.SetNumEmulatedConnections(1)
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
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Lose one more than the congestion window reduction, so that after loss,
		// bytes_in_flight is lesser than the congestion window.
		sendWindowAfterLoss := protocol.ByteCount(renoBeta * float32(expectedSendWindow))
		numPacketsToLose := (expectedSendWindow-sendWindowAfterLoss)/protocol.DefaultTCPMSS + 1
		LoseNPackets(int(numPacketsToLose))
		// Immediately after the loss, ensure at least one packet can be sent.
		// Losses without subsequent acks can occur with timer based loss detection.
		Expect(sender.TimeUntilSend(bytesInFlight)).To(BeZero())
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
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))

		// Expect the window to decrease to the minimum once the RTO fires
		// and slow start threshold to be set to 1/2 of the CWND.
		sender.OnRetransmissionTimeout(true)
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(2 * protocol.DefaultTCPMSS)))
		Expect(sender.SlowstartThreshold()).To(Equal(protocol.PacketNumber(5)))
	})

	It("RTO congestion window no retransmission", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Expect the window to remain unchanged if the RTO fires but no
		// packets are retransmitted.
		sender.OnRetransmissionTimeout(false)
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
	})

	It("retransmission delay", func() {
		const rtt = 10 * time.Millisecond
		const deviation = 3 * time.Millisecond
		Expect(sender.RetransmissionDelay()).To(BeZero())

		rttStats.UpdateRTT(rtt, 0, clock.Now())

		// Initial value is to set the median deviation to half of the initial
		// rtt, the median in then multiplied by a factor of 4 and finally the
		// smoothed rtt is added which is the initial rtt.
		expectedDelay := rtt + rtt/2*4
		Expect(sender.RetransmissionDelay()).To(Equal(expectedDelay))

		for i := 0; i < 100; i++ {
			// run to make sure that we converge.
			rttStats.UpdateRTT(rtt+deviation, 0, clock.Now())
			rttStats.UpdateRTT(rtt-deviation, 0, clock.Now())
		}
		expectedDelay = rtt + deviation*4

		Expect(rttStats.SmoothedRTT()).To(BeNumerically("~", rtt, time.Millisecond))
		Expect(sender.RetransmissionDelay()).To(BeNumerically("~", expectedDelay, time.Millisecond))
		Expect(sender.BandwidthEstimate() / BytesPerSecond).To(Equal(Bandwidth(
			sender.GetCongestionWindow() * protocol.ByteCount(time.Second) / protocol.ByteCount(rttStats.SmoothedRTT()),
		)))
	})

	It("slow start max send window", func() {
		const maxCongestionWindowTCP = 50
		const numberOfAcks = 100
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, maxCongestionWindowTCP)

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		expectedSendWindow := maxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expectedSendWindow)))
	})

	It("tcp reno max congestion window", func() {
		const maxCongestionWindowTCP = 50
		const numberOfAcks = 1000
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, maxCongestionWindowTCP)

		SendAvailableSendWindow()
		AckNPackets(2)
		// Make sure we fall out of slow start.
		LoseNPackets(1)

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}

		expectedSendWindow := maxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expectedSendWindow)))
	})

	It("tcp cubic max congestion window", func() {
		const maxCongestionWindowTCP = 50
		// Set to 10000 to compensate for small cubic alpha.
		const numberOfAcks = 10000

		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, maxCongestionWindowTCP)

		SendAvailableSendWindow()
		AckNPackets(2)
		// Make sure we fall out of slow start.
		LoseNPackets(1)

		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}

		expectedSendWindow := maxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expectedSendWindow)))
	})

	It("tcp cubic reset epoch on quiescence", func() {
		const maxCongestionWindow = 50
		const maxCongestionWindowBytes = maxCongestionWindow * protocol.DefaultTCPMSS
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, maxCongestionWindow)

		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		saveCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(saveCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		saveCwnd = sender.GetCongestionWindow()
		numSent = SendAvailableSendWindow()
		for i := 0; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(saveCwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		saveCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(saveCwnd).To(BeNumerically("~", sender.GetCongestionWindow(), protocol.DefaultTCPMSS))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("tcp cubic shifted epoch on quiescence", func() {
		const maxCongestionWindow = 50
		const maxCongestionWindowBytes = maxCongestionWindow * protocol.DefaultTCPMSS
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, maxCongestionWindow)

		numSent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		saveCwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(saveCwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		saveCwnd = sender.GetCongestionWindow()
		numSent = SendAvailableSendWindow()
		for i := 0; i < numSent; i++ {
			AckNPackets(1)
		}
		Expect(saveCwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(maxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		saveCwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(saveCwnd).To(BeNumerically("~", sender.GetCongestionWindow(), protocol.DefaultTCPMSS))
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

	It("don't track ack packets", func() {
		// Send a packet with no retransmittable data, and ensure it's not tracked.
		Expect(sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, protocol.DefaultTCPMSS, false)).To(BeFalse())
		packetNumber++

		// Send a data packet with retransmittable data, and ensure it is tracked.
		Expect(sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, protocol.DefaultTCPMSS, true)).To(BeTrue())
	})

	// TEST_F(TcpCubicSenderPacketsTest, ConfigureInitialWindow) {
	//   QuicConfig config;
	//
	//   QuicTagVector options;
	//   options.push_back(kIW03);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   Expect( sender.congestion_window()).To(Equal(3u))
	//
	//   options.clear();
	//   options.push_back(kIW10);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   Expect( sender.congestion_window()).To(Equal(10u))
	//
	//   options.clear();
	//   options.push_back(kIW20);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   Expect( sender.congestion_window()).To(Equal(20u))
	//
	//   options.clear();
	//   options.push_back(kIW50);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   Expect( sender.congestion_window()).To(Equal(50u))
	// }
	//
	// TEST_F(TcpCubicSenderPacketsTest, ConfigureMinimumWindow) {
	//   QuicConfig config;
	//
	//   // Verify that kCOPT: kMIN1 forces the min CWND to 1 packet.
	//   QuicTagVector options;
	//   options.push_back(kMIN1);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   sender.OnRetransmissionTimeout(true);
	//   Expect( sender.congestion_window()).To(Equal(1u))
	// }

	It("2 connection congestion avoidance at end of recovery", func() {
		sender.SetNumEmulatedConnections(2)
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * sender.RenoBeta())
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

		// Out of recovery now. Congestion window should not grow for half an RTT.
		packetsInSendWindow := expectedSendWindow / protocol.DefaultTCPMSS
		SendAvailableSendWindow()
		AckNPackets(int(packetsInSendWindow/2 - 2))
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should increase congestion window by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		packetsInSendWindow++
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Congestion window should remain steady again for half an RTT.
		SendAvailableSendWindow()
		AckNPackets(int(packetsInSendWindow/2 - 1))
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	It("1 connection congestion avoidance at end of recovery", func() {
		sender.SetNumEmulatedConnections(1)
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const numberOfAcks = 5
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
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
		for i := protocol.ByteCount(0); i < expectedSendWindow/protocol.DefaultTCPMSS-2; i += 2 {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		}

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expectedSendWindow += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
	})

	// TEST_F(TcpCubicSenderPacketsTest, BandwidthResumption) {
	//   // Test that when provided with CachedNetworkParameters and opted in to the
	//   // bandwidth resumption experiment, that the TcpCubicSenderPackets sets
	//   // initial CWND appropriately.
	//
	//   // Set some common values.
	//   CachedNetworkParameters cached_network_params;
	//   const QuicPacketCount kNumberOfPackets = 123;
	//   const int kBandwidthEstimateBytesPerSecond =
	//       kNumberOfPackets * protocol.DefaultTCPMSS;
	//   cached_network_params.set_bandwidth_estimate_bytes_per_second(
	//       kBandwidthEstimateBytesPerSecond);
	//   cached_network_params.set_min_rtt_ms(1000);
	//
	//   // Make sure that a bandwidth estimate results in a changed CWND.
	//   cached_network_params.set_timestamp(clock.WallNow().ToUNIXSeconds() -
	//                                       (kNumSecondsPerHour - 1));
	//   sender.ResumeConnectionState(cached_network_params, false);
	//   Expect( sender.congestion_window()).To(Equal(kNumberOfPackets))
	//
	//   // Resumed CWND is limited to be in a sensible range.
	//   cached_network_params.set_bandwidth_estimate_bytes_per_second(
	//       (maxCongestionWindow + 1) * protocol.DefaultTCPMSS);
	//   sender.ResumeConnectionState(cached_network_params, false);
	//   Expect( sender.congestion_window()).To(Equal(maxCongestionWindow))
	//
	//   cached_network_params.set_bandwidth_estimate_bytes_per_second(
	//       (kMinCongestionWindowForBandwidthResumption - 1) * protocol.DefaultTCPMSS);
	//   sender.ResumeConnectionState(cached_network_params, false);
	//   EXPECT_EQ(kMinCongestionWindowForBandwidthResumption,
	//             sender.congestion_window());
	//
	//   // Resume to the max value.
	//   cached_network_params.set_max_bandwidth_estimate_bytes_per_second(
	//       (kMinCongestionWindowForBandwidthResumption + 10) * protocol.DefaultTCPMSS);
	//   sender.ResumeConnectionState(cached_network_params, true);
	//   EXPECT_EQ((kMinCongestionWindowForBandwidthResumption + 10) * protocol.DefaultTCPMSS,
	//             sender.GetCongestionWindow());
	// }
	//
	// TEST_F(TcpCubicSenderPacketsTest, PaceBelowCWND) {
	//   QuicConfig config;
	//
	//   // Verify that kCOPT: kMIN4 forces the min CWND to 1 packet, but allows up
	//   // to 4 to be sent.
	//   QuicTagVector options;
	//   options.push_back(kMIN4);
	//   QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
	//   sender.SetFromConfig(config, Perspective::IS_SERVER);
	//   sender.OnRetransmissionTimeout(true);
	//   Expect( sender.congestion_window()).To(Equal(1u))
	//   EXPECT_TRUE(
	//       sender.TimeUntilSend(QuicTime::Zero(), protocol.DefaultTCPMSS).IsZero());
	//   EXPECT_TRUE(
	//       sender.TimeUntilSend(QuicTime::Zero(), 2 * protocol.DefaultTCPMSS).IsZero());
	//   EXPECT_TRUE(
	//       sender.TimeUntilSend(QuicTime::Zero(), 3 * protocol.DefaultTCPMSS).IsZero());
	//   EXPECT_FALSE(
	//       sender.TimeUntilSend(QuicTime::Zero(), 4 * protocol.DefaultTCPMSS).IsZero());
	// }

	It("reset after connection migration", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))

		// Starts with slow start.
		sender.SetNumEmulatedConnections(1)
		const numberOfAcks = 10
		for i := 0; i < numberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expectedSendWindow := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * numberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))

		// Loses a packet to exit slow start.
		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window. Slow
		// start threshold is also updated.
		expectedSendWindow = protocol.ByteCount(float32(expectedSendWindow) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expectedSendWindow))
		Expect(sender.SlowstartThreshold()).To(Equal(protocol.PacketNumber(expectedSendWindow / protocol.DefaultTCPMSS)))

		// Resets cwnd and slow start threshold on connection migrations.
		sender.OnConnectionMigration()
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})
})
