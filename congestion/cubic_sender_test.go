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
		clock = mockClock{}
		rttStats = congestion.NewRTTStats()
		sender = congestion.NewCubicSender(&clock, rttStats, initialCongestionWindowPackets)
	})

	SendAvailableSendWindow := func(packetLength uint64) int {
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
		SendAvailableSendWindow(protocol.DefaultTCPMSS)
		Expect(sender.TimeUntilSend(clock.Now(), sender.GetCongestionWindow())).ToNot(BeZero())
	})

	It("application limited slow start", func() {
		// Send exactly 10 packets and ensure the CWND ends at 14 packets.
		const kNumberOfAcks = 5
		// At startup make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())
		// Make sure we can send.
		Expect(sender.TimeUntilSend(clock.Now(), 0)).To(BeZero())

		SendAvailableSendWindow(protocol.DefaultTCPMSS)
		for i := 0; i < kNumberOfAcks; i++ {
			AckNPackets(2)
		}
		bytesToSend := sender.GetCongestionWindow()
		// It's expected 2 acks will arrive when the bytes_in_flight are greater than
		// half the CWND.
		Expect(bytesToSend).To(Equal(defaultWindowTCP + protocol.DefaultTCPMSS*2*2))
	})
})
