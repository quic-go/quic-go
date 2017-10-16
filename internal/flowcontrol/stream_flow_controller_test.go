package flowcontrol

import (
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Flow controller", func() {
	var controller *streamFlowController

	BeforeEach(func() {
		controller = &streamFlowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}

		It("sets the send and receive windows", func() {
			receiveWindow := protocol.ByteCount(2000)
			maxReceiveWindow := protocol.ByteCount(3000)
			sendWindow := protocol.ByteCount(4000)

			fc := newStreamFlowController(5, true, receiveWindow, maxReceiveWindow, sendWindow, rttStats)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowIncrement).To(Equal(maxReceiveWindow))
			Expect(fc.sendWindow).To(Equal(sendWindow))
		})

		It("says if it contributes to connection-level flow control", func() {
			fc := newStreamFlowController(1, false, protocol.MaxByteCount, protocol.MaxByteCount, protocol.MaxByteCount, rttStats)
			Expect(fc.ContributesToConnection()).To(BeFalse())
			fc = newStreamFlowController(5, true, protocol.MaxByteCount, protocol.MaxByteCount, protocol.MaxByteCount, rttStats)
			Expect(fc.ContributesToConnection()).To(BeTrue())
		})
	})

	Context("receive flow control", func() {
		var receiveWindow protocol.ByteCount = 10000
		var receiveWindowIncrement protocol.ByteCount = 600

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowIncrement = receiveWindowIncrement
		})

		It("updates the highestReceived", func() {
			controller.highestReceived = 1337
			increment, err := controller.UpdateHighestReceived(1338)
			Expect(err).ToNot(HaveOccurred())
			Expect(increment).To(Equal(protocol.ByteCount(1338 - 1337)))
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
		})

		It("does not decrease the highestReceived", func() {
			controller.highestReceived = 1337
			increment, err := controller.UpdateHighestReceived(1000)
			Expect(err).To(MatchError(ErrReceivedSmallerByteOffset))
			Expect(increment).To(BeZero())
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
		})

		It("does not error when setting the same byte offset", func() {
			controller.highestReceived = 1337
			increment, err := controller.UpdateHighestReceived(1337)
			Expect(err).ToNot(HaveOccurred())
			Expect(increment).To(BeZero())
		})

		It("detects a flow control violation", func() {
			controller.UpdateHighestReceived(receiveWindow + 1)
			Expect(controller.CheckFlowControlViolation()).To(BeTrue())
		})

		It("does not give a flow control violation when using the window completely", func() {
			controller.UpdateHighestReceived(receiveWindow)
			Expect(controller.CheckFlowControlViolation()).To(BeFalse())
		})
	})
})
