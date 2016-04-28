package congestion_test

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const initialCongestionWindowPackets protocol.PacketNumber = 10
const defaultWindowTCP = uint64(initialCongestionWindowPackets * protocol.DefaultTCPMSS)
const renoBeta float32 = 0.7 // Reno backoff factor.

type mockClock time.Time

func (c *mockClock) Now() time.Time {
	return time.Time(*c)
}

func (c *mockClock) Advance(d time.Duration) {
	*c = mockClock(time.Time(*c).Add(d))
}

var _ = Describe("Cubic Sender", func() {
	var (
		sender            congestion.SendAlgorithm
		clock             mockClock
		bytesInFlight     uint64
		packetNumber      protocol.PacketNumber
		ackedPacketNumber protocol.PacketNumber
		rttStats          *congestion.RTTStats
	)

	BeforeEach(func() {
		bytesInFlight = 0
		packetNumber = 1
		ackedPacketNumber = 0
		clock = mockClock{}
		rttStats = congestion.NewRTTStats()
		sender = congestion.NewCubicSender(&clock, rttStats, true /*reno*/, initialCongestionWindowPackets, protocol.MaxCongestionWindow)
	})

	SendAvailableSendWindow := func() int {
		// Send as long as TimeUntilSend returns Zero.
		packets_sent := 0
		can_send := sender.TimeUntilSend(clock.Now(), bytesInFlight) == 0
		for can_send {
			packetNumber++
			sender.OnPacketSent(clock.Now(), bytesInFlight, packetNumber, protocol.DefaultTCPMSS, true)
			packets_sent++
			bytesInFlight += protocol.DefaultTCPMSS
			can_send = sender.TimeUntilSend(clock.Now(), bytesInFlight) == 0
		}
		return packets_sent
	}

	// Normal is that TCP acks every other segment.
	AckNPackets := func(n int) {
		rttStats.UpdateRTT(60*time.Millisecond, 0, clock.Now())
		var ackedPackets congestion.PacketVector
		var lostPackets congestion.PacketVector
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: ackedPacketNumber, Length: protocol.DefaultTCPMSS})
		}
		sender.OnCongestionEvent(true, bytesInFlight, ackedPackets, lostPackets)
		bytesInFlight -= uint64(n) * protocol.DefaultTCPMSS
		clock.Advance(time.Millisecond)
	}

	LoseNPackets := func(n int) {
		packetLength := uint64(protocol.DefaultTCPMSS)
		var ackedPackets congestion.PacketVector
		var lostPackets congestion.PacketVector
		for i := 0; i < n; i++ {
			ackedPacketNumber++
			lostPackets = append(lostPackets, congestion.PacketInfo{Number: ackedPacketNumber, Length: packetLength})
		}
		sender.OnCongestionEvent(false, bytesInFlight, ackedPackets, lostPackets)
		bytesInFlight -= uint64(n) * packetLength
	}

	It("simpler sender", func() {
		// At startup make sure we are at the default.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
		// And that window is un-affected.
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Fill the send window with data, then verify that we can't send.
		SendAvailableSendWindow()
		Expect(sender.TimeUntilSend(clock.Now(), sender.GetCongestionWindow())).ToNot(BeZero())
	})

	It("application limited slow start", func() {
		// Send exactly 10 packets and ensure the CWND ends at 14 packets.
		const kNumberOfAcks = 5
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())

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
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
		Expect(sender.BandwidthEstimate()).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		cwnd := sender.GetCongestionWindow()
		Expect(cwnd).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*kNumberOfAcks))
		Expect(sender.BandwidthEstimate()).To(Equal(congestion.BandwidthFromDelta(cwnd, rttStats.SmoothedRTT())))
	})

	PIt("slow start packet loss", func() {
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
		expected_send_window = uint64(float32(expected_send_window) * renoBeta)
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

	It("no PRR when less than one packet in flight", func() {
		SendAvailableSendWindow()
		LoseNPackets(int(initialCongestionWindowPackets) - 1)
		AckNPackets(1)
		// PRR will allow 2 packets for every ack during recovery.
		Expect(SendAvailableSendWindow()).To(Equal(2))
		// Simulate abandoning all packets by supplying a bytes_in_flight of 0.
		// PRR should now allow a packet to be sent, even though prr's state
		// variables believe it has sent enough packets.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
	})

	PIt("slow start packet loss PRR", func() {
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
		expected_send_window = uint64(float32(expected_send_window) * renoBeta)
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))

		// Testing TCP proportional rate reduction.
		// We should send packets paced over the received acks for the remaining
		// outstanding packets. The number of packets before we exit recovery is the
		// original CWND minus the packet that has been lost and the one which
		// triggered the loss.
		remaining_packets_in_recovery := send_window_before_loss/protocol.DefaultTCPMSS - 2

		for i := uint64(0); i < remaining_packets_in_recovery; i++ {
			AckNPackets(1)
			SendAvailableSendWindow()
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}

		// We need to ack another window before we increase CWND by 1.
		number_of_packets_in_window := expected_send_window / protocol.DefaultTCPMSS
		for i := uint64(0); i < number_of_packets_in_window; i++ {
			AckNPackets(1)
			Expect(SendAvailableSendWindow()).To(Equal(1))
			Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
		}

		AckNPackets(1)
		expected_send_window += protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(expected_send_window))
	})

	It("RTO congestion window", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
		Expect(sender.SlowstartThreshold()).To(Equal(protocol.MaxCongestionWindow))

		// Expect the window to decrease to the minimum once the RTO fires
		// and slow start threshold to be set to 1/2 of the CWND.
		sender.OnRetransmissionTimeout(true)
		Expect(sender.GetCongestionWindow()).To(Equal(uint64(2 * protocol.DefaultTCPMSS)))
		Expect(sender.SlowstartThreshold()).To(Equal(protocol.PacketNumber(5)))
	})

	It("RTO congestion window no retransmission", func() {
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))

		// Expect the window to remain unchanged if the RTO fires but no
		// packets are retransmitted.
		sender.OnRetransmissionTimeout(false)
		Expect(sender.GetCongestionWindow()).To(Equal(defaultWindowTCP))
	})

	It("slow start max send window", func() {
		const kMaxCongestionWindowTCP = 50
		const kNumberOfAcks = 100
		sender = congestion.NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

		for i := 0; i < kNumberOfAcks; i++ {
			// Send our full send window.
			SendAvailableSendWindow()
			AckNPackets(2)
		}
		expected_send_window := kMaxCongestionWindowTCP * protocol.DefaultTCPMSS
		Expect(sender.GetCongestionWindow()).To(Equal(uint64(expected_send_window)))
	})

	It("tcp reno max congestion window", func() {
		const kMaxCongestionWindowTCP = 50
		const kNumberOfAcks = 1000
		sender = congestion.NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

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
		Expect(sender.GetCongestionWindow()).To(Equal(uint64(expected_send_window)))
	})

	It("tcp cubic max congestion window", func() {
		const kMaxCongestionWindowTCP = 50
		// Set to 10000 to compensate for small cubic alpha.
		const kNumberOfAcks = 10000

		sender = congestion.NewCubicSender(&clock, rttStats, false, initialCongestionWindowPackets, kMaxCongestionWindowTCP)

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
		Expect(sender.GetCongestionWindow()).To(Equal(uint64(expected_send_window)))
	})
})
