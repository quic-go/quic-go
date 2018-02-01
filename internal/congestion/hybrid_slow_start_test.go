package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hybrid slow start", func() {
	var (
		slowStart HybridSlowStart
	)

	BeforeEach(func() {
		slowStart = HybridSlowStart{}
	})

	It("works in a simple case", func() {
		packet_number := protocol.PacketNumber(1)
		end_packet_number := protocol.PacketNumber(3)
		slowStart.StartReceiveRound(end_packet_number)

		packet_number++
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeFalse())

		// Test duplicates.
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeFalse())

		packet_number++
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeFalse())
		packet_number++
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeTrue())

		// Test without a new registered end_packet_number;
		packet_number++
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeTrue())

		end_packet_number = 20
		slowStart.StartReceiveRound(end_packet_number)
		for packet_number < end_packet_number {
			packet_number++
			Expect(slowStart.IsEndOfRound(packet_number)).To(BeFalse())
		}
		packet_number++
		Expect(slowStart.IsEndOfRound(packet_number)).To(BeTrue())
	})

	It("works with delay", func() {
		rtt := 60 * time.Millisecond
		// We expect to detect the increase at +1/8 of the RTT; hence at a typical
		// RTT of 60ms the detection will happen at 67.5 ms.
		const kHybridStartMinSamples = 8 // Number of acks required to trigger.

		end_packet_number := protocol.PacketNumber(1)
		end_packet_number++
		slowStart.StartReceiveRound(end_packet_number)

		// Will not trigger since our lowest RTT in our burst is the same as the long
		// term RTT provided.
		for n := 0; n < kHybridStartMinSamples; n++ {
			Expect(slowStart.ShouldExitSlowStart(rtt+time.Duration(n)*time.Millisecond, rtt, 100)).To(BeFalse())
		}
		end_packet_number++
		slowStart.StartReceiveRound(end_packet_number)
		for n := 1; n < kHybridStartMinSamples; n++ {
			Expect(slowStart.ShouldExitSlowStart(rtt+(time.Duration(n)+10)*time.Millisecond, rtt, 100)).To(BeFalse())
		}
		// Expect to trigger since all packets in this burst was above the long term
		// RTT provided.
		Expect(slowStart.ShouldExitSlowStart(rtt+10*time.Millisecond, rtt, 100)).To(BeTrue())
	})

})
