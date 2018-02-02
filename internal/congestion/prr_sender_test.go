package congestion

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var _ = Describe("PRR sender", func() {
	var (
		prr PrrSender
	)

	BeforeEach(func() {
		prr = PrrSender{}
	})

	It("single loss results in send on every other ack", func() {
		num_packets_in_flight := protocol.ByteCount(50)
		bytes_in_flight := num_packets_in_flight * protocol.DefaultTCPMSS
		ssthresh_after_loss := num_packets_in_flight / 2
		congestion_window := ssthresh_after_loss * protocol.DefaultTCPMSS

		prr.OnPacketLost(bytes_in_flight)
		// Ack a packet. PRR allows one packet to leave immediately.
		prr.OnPacketAcked(protocol.DefaultTCPMSS)
		bytes_in_flight -= protocol.DefaultTCPMSS
		Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(BeZero())
		// Send retransmission.
		prr.OnPacketSent(protocol.DefaultTCPMSS)
		// PRR shouldn't allow sending any more packets.
		Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(Equal(utils.InfDuration))

		// One packet is lost, and one ack was consumed above. PRR now paces
		// transmissions through the remaining 48 acks. PRR will alternatively
		// disallow and allow a packet to be sent in response to an ack.
		for i := protocol.ByteCount(0); i < ssthresh_after_loss-1; i++ {
			// Ack a packet. PRR shouldn't allow sending a packet in response.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytes_in_flight -= protocol.DefaultTCPMSS
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(Equal(utils.InfDuration))
			// Ack another packet. PRR should now allow sending a packet in response.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytes_in_flight -= protocol.DefaultTCPMSS
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(BeZero())
			// Send a packet in response.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytes_in_flight += protocol.DefaultTCPMSS
		}

		// Since bytes_in_flight is now equal to congestion_window, PRR now maintains
		// packet conservation, allowing one packet to be sent in response to an ack.
		Expect(bytes_in_flight).To(Equal(congestion_window))
		for i := 0; i < 10; i++ {
			// Ack a packet.
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytes_in_flight -= protocol.DefaultTCPMSS
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(BeZero())
			// Send a packet in response, since PRR allows it.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytes_in_flight += protocol.DefaultTCPMSS

			// Since bytes_in_flight is equal to the congestion_window,
			// PRR disallows sending.
			Expect(bytes_in_flight).To(Equal(congestion_window))
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(Equal(utils.InfDuration))
		}

	})

	It("burst loss results in slow start", func() {
		bytes_in_flight := protocol.ByteCount(20 * protocol.DefaultTCPMSS)
		const num_packets_lost = 13
		const ssthresh_after_loss = 10
		const congestion_window = ssthresh_after_loss * protocol.DefaultTCPMSS

		// Lose 13 packets.
		bytes_in_flight -= num_packets_lost * protocol.DefaultTCPMSS
		prr.OnPacketLost(bytes_in_flight)

		// PRR-SSRB will allow the following 3 acks to send up to 2 packets.
		for i := 0; i < 3; i++ {
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytes_in_flight -= protocol.DefaultTCPMSS
			// PRR-SSRB should allow two packets to be sent.
			for j := 0; j < 2; j++ {
				Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(BeZero())
				// Send a packet in response.
				prr.OnPacketSent(protocol.DefaultTCPMSS)
				bytes_in_flight += protocol.DefaultTCPMSS
			}
			// PRR should allow no more than 2 packets in response to an ack.
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(Equal(utils.InfDuration))
		}

		// Out of SSRB mode, PRR allows one send in response to each ack.
		for i := 0; i < 10; i++ {
			prr.OnPacketAcked(protocol.DefaultTCPMSS)
			bytes_in_flight -= protocol.DefaultTCPMSS
			Expect(prr.TimeUntilSend(congestion_window, bytes_in_flight, ssthresh_after_loss*protocol.DefaultTCPMSS)).To(BeZero())
			// Send a packet in response.
			prr.OnPacketSent(protocol.DefaultTCPMSS)
			bytes_in_flight += protocol.DefaultTCPMSS
		}
	})
})
