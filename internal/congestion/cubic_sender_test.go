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
		packets_sent := 0
		for bytesInFlight < sender.GetCongestionWindow() {
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, packetLength, true)
			packetNumber++
			packets_sent++
			bytesInFlight += packetLength
		}
		return packets_sent
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
		const kNumberOfAcks = 5
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		SendAvailableSendWindow()
		for i := 0; i < kNumberOfAcks; i++ {
			AckNPackets(2)
		}
		bytesToSend := sender.GetCongestionWindow()
		// It's expected 2 acks will arrive when the bytes_in_flight are greater than
		// half the CWND.
		Expect(bytesToSend).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*2))
	})

	It("exponential slow start", func() {
		const kNumberOfAcks = 20
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())
		Expect(sender.BandwidthEstimate()).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(0)).To(BeZero())

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		cwnd := sender.GetCongestionWindow()
		Expect(cwnd).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*kNumberOfAcks))
		Expect(sender.BandwidthEstimate()).To(Equal(BandwidthFromDelta(cwnd, rttStats.SmoothedRTT())))
	})

	It("slow start packet loss", func() {
		sender.SetNumEmulatedConnections(1)
		const kNumberOfAcks = 10
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose a packet to exit slow start.
		LoseNPackets(1)
		packets_in_recovery_window := expected_send_window / protocol.DefaultTCPMSS

		// We should now have fallen out of slow start with a reduced window.
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		number_of_packets_in_window := expected_send_window / protocol.DefaultTCPMSS
		AckNPackets(int(packets_in_recovery_window))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// We need to ack an entire window before we increase CWND by 1.
		AckNPackets(int(number_of_packets_in_window) - 2)
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const kNumberOfAcks = 10
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expected_send_window -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose 5 packets in recovery and verify that congestion window is reduced
		// further.
		LoseNPackets(5)
		expected_send_window -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		packets_in_recovery_window := expected_send_window / protocol.DefaultTCPMSS

		// Recovery phase. We need to ack every packet in the recovery window before
		// we exit recovery.
		number_of_packets_in_window := expected_send_window / protocol.DefaultTCPMSS
		AckNPackets(int(packets_in_recovery_window))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// We need to ack the rest of the window before cwnd increases by 1.
		AckNPackets(int(number_of_packets_in_window - 1))
		SendAvailableSendWindow()
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Next ack should increase cwnd by 1.
		AckNPackets(1)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Now RTO and ensure slow start gets reset.
		Expect(sender.HybridSlowStart().Started()).To(BeTrue())
		sender.OnRetransmissionTimeout(true)
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})

	It("slow start half packet loss with large reduction", func() {
		sender.SetSlowStartLargeReduction(true)

		sender.SetNumEmulatedConnections(1)
		const kNumberOfAcks = 10
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window in half sized packets.
			SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
			AckNPackets(2)
		}
		SendAvailableSendWindowLen(protocol.DefaultTCPMSS / 2)
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose a packet to exit slow start. We should now have fallen out of
		// slow start with a window reduced by 1.
		LoseNPackets(1)
		expected_send_window -= protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose 10 packets in recovery and verify that congestion window is reduced
		// by 5 packets.
		LoseNPacketsLen(10, protocol.DefaultTCPMSS/2)
		expected_send_window -= 5 * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
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
		const kNumberOfAcks = 5
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		send_window_before_loss := expected_send_window
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Testing TCP proportional rate reduction.
		// We should send packets paced over the received acks for the remaining
		// outstanding packets. The number of packets before we exit recovery is the
		// original CWND minus the packet that has been lost and the one which
		// triggered the loss.
		remaining_packets_in_recovery := send_window_before_loss/protocol.DefaultTCPMSS - 2

		for i := protocol.ByteCount(0); i < remaining_packets_in_recovery; i++ {
			AckNPackets(1)
			SendAvailableSendWindow()
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}

		// We need to ack another window before we increase CWND by 1.
		number_of_packets_in_window := expected_send_window / protocol.DefaultTCPMSS
		for i := protocol.ByteCount(0); i < number_of_packets_in_window; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}

		AckNPackets(1)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
	})

	It("slow start burst packet loss PRR", func() {
		sender.SetNumEmulatedConnections(1)
		// Test based on the second example in RFC6937, though we also implement
		// forward acknowledgements, so the first two incoming acks will trigger
		// PRR immediately.
		// Ack 20 packets in 10 acks to raise the CWND to 30.
		const kNumberOfAcks = 10
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Lose one more than the congestion window reduction, so that after loss,
		// bytes_in_flight is lesser than the congestion window.
		send_window_after_loss := protocol.ByteCount(renoBeta * float32(expected_send_window))
		num_packets_to_lose := (expected_send_window-send_window_after_loss)/protocol.DefaultTCPMSS + 1
		LoseNPackets(int(num_packets_to_lose))
		// Immediately after the loss, ensure at least one packet can be sent.
		// Losses without subsequent acks can occur with timer based loss detection.
		Expect(sender.TimeUntilSend(bytesInFlight)).To(BeZero())
		AckNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

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
		for i := 0; i < kNumberOfAcks; i++ {
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
		const kRttMs = 10 * time.Millisecond
		const kDeviationMs = 3 * time.Millisecond
		Expect(sender.RetransmissionDelay()).To(BeZero())

		rttStats.UpdateRTT(kRttMs, 0, clock.Now())

		// Initial value is to set the median deviation to half of the initial
		// rtt, the median in then multiplied by a factor of 4 and finally the
		// smoothed rtt is added which is the initial rtt.
		expected_delay := kRttMs + kRttMs/2*4
		Expect(sender.RetransmissionDelay()).To(Equal(expected_delay))

		for i := 0; i < 100; i++ {
			// run to make sure that we converge.
			rttStats.UpdateRTT(kRttMs+kDeviationMs, 0, clock.Now())
			rttStats.UpdateRTT(kRttMs-kDeviationMs, 0, clock.Now())
		}
		expected_delay = kRttMs + kDeviationMs*4

		Expect(rttStats.SmoothedRTT()).To(BeNumerically("~", kRttMs, time.Millisecond))
		Expect(sender.RetransmissionDelay()).To(BeNumerically("~", expected_delay, time.Millisecond))
		Expect(sender.BandwidthEstimate() / BytesPerSecond).To(Equal(Bandwidth(
			sender.GetCongestionWindow() * protocol.ByteCount(time.Second) / protocol.ByteCount(rttStats.SmoothedRTT()),
		)))
	})

	It("slow start max send window", func() {
		const kMaxCongestionWindowTCP = 50
		const kNumberOfAcks = 100
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		expected_send_window := kMaxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expected_send_window)))
	})

	It("tcp reno max congestion window", func() {
		const kMaxCongestionWindowTCP = 50
		const kNumberOfAcks = 1000
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

		SendAvailableSendWindow()
		AckNPackets(2)
		// Make sure we fall out of slow start.
		LoseNPackets(1)

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}

		expected_send_window := kMaxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expected_send_window)))
	})

	It("tcp cubic max congestion window", func() {
		const kMaxCongestionWindowTCP = 50
		// Set to 10000 to compensate for small cubic alpha.
		const kNumberOfAcks = 10000

		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

		SendAvailableSendWindow()
		AckNPackets(2)
		// Make sure we fall out of slow start.
		LoseNPackets(1)

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}

		expected_send_window := kMaxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(protocol.ByteCount(expected_send_window)))
	})

	It("tcp cubic reset epoch on quiescence", func() {
		const kMaxCongestionWindow = 50
		const kMaxCongestionWindowBytes = kMaxCongestionWindow * protocol.DefaultTCPMSS
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindow)

		num_sent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		saved_cwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(saved_cwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < num_sent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		saved_cwnd = sender.GetCongestionWindow()
		num_sent = SendAvailableSendWindow()
		for i := 0; i < num_sent; i++ {
			AckNPackets(1)
		}
		Expect(saved_cwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(kMaxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		saved_cwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(saved_cwnd).To(BeNumerically("~", sender.GetCongestionWindow(), protocol.DefaultTCPMSS))
		Expect(kMaxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("tcp cubic shifted epoch on quiescence", func() {
		const kMaxCongestionWindow = 50
		const kMaxCongestionWindowBytes = kMaxCongestionWindow * protocol.DefaultTCPMSS
		sender = NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindow)

		num_sent := SendAvailableSendWindow()

		// Make sure we fall out of slow start.
		saved_cwnd := sender.GetCongestionWindow()
		LoseNPackets(1)
		Expect(saved_cwnd).To(BeNumerically(">", sender.GetCongestionWindow()))

		// Ack the rest of the outstanding packets to get out of recovery.
		for i := 1; i < num_sent; i++ {
			AckNPackets(1)
		}
		Expect(bytesInFlight).To(BeZero())

		// Send a new window of data and ack all; cubic growth should occur.
		saved_cwnd = sender.GetCongestionWindow()
		num_sent = SendAvailableSendWindow()
		for i := 0; i < num_sent; i++ {
			AckNPackets(1)
		}
		Expect(saved_cwnd).To(BeNumerically("<", sender.GetCongestionWindow()))
		Expect(kMaxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
		Expect(bytesInFlight).To(BeZero())

		// Quiescent time of 100 seconds
		clock.Advance(100 * time.Second)

		// Send new window of data and ack one packet. Cubic epoch should have
		// been reset; ensure cwnd increase is not dramatic.
		saved_cwnd = sender.GetCongestionWindow()
		SendAvailableSendWindow()
		AckNPackets(1)
		Expect(saved_cwnd).To(BeNumerically("~", sender.GetCongestionWindow(), protocol.DefaultTCPMSS))
		Expect(kMaxCongestionWindowBytes).To(BeNumerically(">", sender.GetCongestionWindow()))
	})

	It("multiple losses in one window", func() {
		SendAvailableSendWindow()
		initial_window := sender.GetCongestionWindow()
		LosePacket(ackedPacketNumber + 1)
		post_loss_window := sender.GetCongestionWindow()
		Expect(initial_window).To(BeNumerically(">", post_loss_window))
		LosePacket(ackedPacketNumber + 3)
		Expect(sender.GetCongestionWindow()).To(Equal(post_loss_window))
		LosePacket(packetNumber - 1)
		Expect(sender.GetCongestionWindow()).To(Equal(post_loss_window))

		// Lose a later packet and ensure the window decreases.
		LosePacket(packetNumber)
		Expect(post_loss_window).To(BeNumerically(">", sender.GetCongestionWindow()))
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
		const kNumberOfAcks = 5
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * sender.RenoBeta())
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// No congestion window growth should occur in recovery phase, i.e., until the
		// currently outstanding 20 packets are acked.
		for i := 0; i < 10; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			Expect(sender.InRecovery()).To(BeTrue())
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}
		Expect(sender.InRecovery()).To(BeFalse())

		// Out of recovery now. Congestion window should not grow for half an RTT.
		packets_in_send_window := expected_send_window / protocol.DefaultTCPMSS
		SendAvailableSendWindow()
		AckNPackets(int(packets_in_send_window/2 - 2))
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Next ack should increase congestion window by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expected_send_window += protocol.DefaultTCPMSS
		packets_in_send_window += 1
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Congestion window should remain steady again for half an RTT.
		SendAvailableSendWindow()
		AckNPackets(int(packets_in_send_window/2 - 1))
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
	})

	It("1 connection congestion avoidance at end of recovery", func() {
		sender.SetNumEmulatedConnections(1)
		// Ack 10 packets in 5 acks to raise the CWND to 20.
		const kNumberOfAcks = 5
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window.
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// No congestion window growth should occur in recovery phase, i.e., until the
		// currently outstanding 20 packets are acked.
		for i := 0; i < 10; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			Expect(sender.InRecovery()).To(BeTrue())
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}
		Expect(sender.InRecovery()).To(BeFalse())

		// Out of recovery now. Congestion window should not grow during RTT.
		for i := protocol.ByteCount(0); i < expected_send_window/protocol.DefaultTCPMSS-2; i += 2 {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}

		// Next ack should cause congestion window to grow by 1MSS.
		SendAvailableSendWindow()
		AckNPackets(2)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
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
	//       (kMaxCongestionWindow + 1) * protocol.DefaultTCPMSS);
	//   sender.ResumeConnectionState(cached_network_params, false);
	//   Expect( sender.congestion_window()).To(Equal(kMaxCongestionWindow))
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
		const kNumberOfAcks = 10
		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		SendAvailableSendWindow()
		expected_send_window := defaultWindowTCP + (protocol.DefaultTCPMSS * 2 * kNumberOfAcks)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Loses a packet to exit slow start.
		LoseNPackets(1)

		// We should now have fallen out of slow start with a reduced window. Slow
		// start threshold is also updated.
		expected_send_window = protocol.ByteCount(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		Expect(sender.SlowstartThreshold()).To(Equal(protocol.PacketNumber(expected_send_window / protocol.DefaultTCPMSS)))

		// Resets cwnd and slow start threshold on connection migrations.
		sender.OnConnectionMigration()
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(MaxCongestionWindow))
		Expect(sender.HybridSlowStart().Started()).To(BeFalse())
	})
})
