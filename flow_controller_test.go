package quic

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow controller", func() {
	var controller *flowController

	BeforeEach(func() {
		controller = &flowController{}
	})

	Context("send flow control", func() {
		It("adds bytes sent", func() {
			controller.bytesSent = 5
			controller.AddBytesSent(6)
			Expect(controller.bytesSent).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("gets the size of the remaining flow control window", func() {
			controller.bytesSent = 5
			controller.sendFlowControlWindow = 12
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(12 - 5)))
		})

		It("updates the size of the flow control window", func() {
			controller.bytesSent = 5
			updateSuccessful := controller.UpdateSendWindow(15)
			Expect(updateSuccessful).To(BeTrue())
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(15 - 5)))
		})

		It("does not decrease the flow control window", func() {
			updateSuccessful := controller.UpdateSendWindow(20)
			Expect(updateSuccessful).To(BeTrue())
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(20)))
			updateSuccessful = controller.UpdateSendWindow(10)
			Expect(updateSuccessful).To(BeFalse())
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(20)))
		})

		Context("Blocked", func() {
			var sendFlowControlWindow protocol.ByteCount = 20

			BeforeEach(func() {
				controller.sendFlowControlWindow = sendFlowControlWindow
			})

			It("sends a Blocked when there's no space left in the window", func() {
				controller.bytesSent = sendFlowControlWindow
				Expect(controller.MaybeTriggerBlocked()).To(BeTrue())
			})

			It("does not send a Blocked when there's still space in the window", func() {
				controller.bytesSent = sendFlowControlWindow - 1
				Expect(controller.MaybeTriggerBlocked()).To(BeFalse())
			})

			It("only sends one Blocked for one offset", func() {
				controller.bytesSent = sendFlowControlWindow
				Expect(controller.MaybeTriggerBlocked()).To(BeTrue())
				Expect(controller.MaybeTriggerBlocked()).To(BeFalse())
				updateSuccessfull := controller.UpdateSendWindow(sendFlowControlWindow + 1)
				Expect(updateSuccessfull).To(BeTrue())
				controller.bytesSent = sendFlowControlWindow + 1
				Expect(controller.MaybeTriggerBlocked()).To(BeTrue())
			})
		})
	})

	Context("receive flow control", func() {
		var receiveFlowControlWindow protocol.ByteCount = 1337
		var receiveWindowUpdateThreshold protocol.ByteCount = 500
		var receiveFlowControlWindowIncrement protocol.ByteCount = 600

		BeforeEach(func() {
			controller.receiveFlowControlWindow = receiveFlowControlWindow
			controller.receiveWindowUpdateThreshold = receiveWindowUpdateThreshold
			controller.receiveFlowControlWindowIncrement = receiveFlowControlWindowIncrement
		})

		It("adds bytes read", func() {
			controller.bytesRead = 5
			controller.AddBytesRead(6)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("triggers a window update when necessary", func() {
			readPosition := receiveFlowControlWindow - receiveWindowUpdateThreshold + 1
			controller.bytesRead = readPosition
			updateNecessary, offset := controller.MaybeTriggerWindowUpdate()
			Expect(updateNecessary).To(BeTrue())
			Expect(offset).To(Equal(readPosition + receiveFlowControlWindowIncrement))
		})

		It("triggers a window update when not necessary", func() {
			readPosition := receiveFlowControlWindow - receiveWindowUpdateThreshold - 1
			controller.bytesRead = readPosition
			updateNecessary, _ := controller.MaybeTriggerWindowUpdate()
			Expect(updateNecessary).To(BeFalse())
		})

		It("updates the highestReceived", func() {
			controller.highestReceived = 1337
			controller.UpdateHighestReceived(1338)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
		})

		It("does not decrease the highestReceived", func() {
			controller.highestReceived = 1337
			controller.UpdateHighestReceived(1000)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
		})

		It("detects a flow control violation", func() {
			controller.UpdateHighestReceived(receiveFlowControlWindow + 1)
			Expect(controller.CheckFlowControlViolation()).To(BeTrue())
		})

		It("does not give a flow control violation when using the window completely", func() {
			controller.UpdateHighestReceived(receiveFlowControlWindow)
			Expect(controller.CheckFlowControlViolation()).To(BeFalse())
		})
	})
})
