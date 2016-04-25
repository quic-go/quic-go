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
		sender        congestion.SendAlgorithm
		clock         mockClock
		bytesInFlight uint64
		packetNumber  protocol.PacketNumber
	)

	BeforeEach(func() {
		bytesInFlight = 0
		clock = mockClock{}
		sender = congestion.NewCubicSender(initialCongestionWindowPackets)
		packetNumber = 1
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

	It("works with default values", func() {
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
})
