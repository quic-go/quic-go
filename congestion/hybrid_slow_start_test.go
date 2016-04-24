package congestion_test

import (
	"github.com/lucas-clemente/quic-go/congestion"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hybrid slow start", func() {
	var (
		slowStart congestion.HybridSlowStart
	)

	BeforeEach(func() {
		slowStart = congestion.HybridSlowStart{}
	})

	It("works in a simple case", func() {
		packet_number := uint64(1)
		end_packet_number := uint64(3)
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
})
