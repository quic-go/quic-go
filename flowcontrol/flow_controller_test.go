package flowcontrol

import (
	"reflect"
	"unsafe"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// set private variables of the ConnectionParametersManager
// those are normally read from the server parameter constants in the constructor of the ConnectionParametersManager
func setConnectionParametersManagerWindow(cpm *handshake.ConnectionParametersManager, name string, value protocol.ByteCount) {
	*(*protocol.ByteCount)(unsafe.Pointer(reflect.ValueOf(cpm).Elem().FieldByName(name).UnsafeAddr())) = value
}

var _ = Describe("Flow controller", func() {
	var controller *flowController

	BeforeEach(func() {
		controller = &flowController{}
	})

	Context("Constructor", func() {
		var cpm *handshake.ConnectionParametersManager
		var rttStats *congestion.RTTStats

		BeforeEach(func() {
			cpm = &handshake.ConnectionParametersManager{}
			rttStats = &congestion.RTTStats{}
			setConnectionParametersManagerWindow(cpm, "sendStreamFlowControlWindow", 1000)
			setConnectionParametersManagerWindow(cpm, "receiveStreamFlowControlWindow", 2000)
			setConnectionParametersManagerWindow(cpm, "sendConnectionFlowControlWindow", 3000)
			setConnectionParametersManagerWindow(cpm, "receiveConnectionFlowControlWindow", 4000)
		})

		It("reads the stream send and receive windows when acting as stream-level flow controller", func() {
			fc := newFlowController(5, cpm, rttStats)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveFlowControlWindow).To(Equal(protocol.ByteCount(2000)))
		})

		It("reads the stream send and receive windows when acting as stream-level flow controller", func() {
			fc := newFlowController(0, cpm, rttStats)
			Expect(fc.streamID).To(Equal(protocol.StreamID(0)))
			Expect(fc.receiveFlowControlWindow).To(Equal(protocol.ByteCount(4000)))
		})

		It("does not set the stream flow control windows for sending", func() {
			fc := newFlowController(5, cpm, rttStats)
			Expect(fc.sendFlowControlWindow).To(BeZero())
		})

		It("does not set the connection flow control windows for sending", func() {
			fc := newFlowController(0, cpm, rttStats)
			Expect(fc.sendFlowControlWindow).To(BeZero())
		})
	})

	Context("send flow control", func() {
		var cpm *handshake.ConnectionParametersManager

		BeforeEach(func() {
			cpm = &handshake.ConnectionParametersManager{}
			setConnectionParametersManagerWindow(cpm, "sendStreamFlowControlWindow", 1000)
			setConnectionParametersManagerWindow(cpm, "sendConnectionFlowControlWindow", 3000)
			controller.connectionParametersManager = cpm
		})

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

		It("gets the offset of the flow control window", func() {
			controller.bytesSent = 5
			controller.sendFlowControlWindow = 12
			Expect(controller.SendWindowOffset()).To(Equal(protocol.ByteCount(12)))
		})

		It("updates the size of the flow control window", func() {
			controller.bytesSent = 5
			updateSuccessful := controller.UpdateSendWindow(15)
			Expect(updateSuccessful).To(BeTrue())
			Expect(controller.SendWindowOffset()).To(Equal(protocol.ByteCount(15)))
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

		It("asks the ConnectionParametersManager for the stream flow control window size", func() {
			controller.streamID = 5
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(1000)))
			// make sure the value is not cached
			setConnectionParametersManagerWindow(cpm, "sendStreamFlowControlWindow", 2000)
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(2000)))
		})

		It("stops asking the ConnectionParametersManager for the flow control stream window size once a window update has arrived", func() {
			controller.streamID = 5
			Expect(controller.UpdateSendWindow(8000))
			setConnectionParametersManagerWindow(cpm, "sendStreamFlowControlWindow", 9000)
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(8000)))
		})

		It("asks the ConnectionParametersManager for the connection flow control window size", func() {
			controller.streamID = 0
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(3000)))
			// make sure the value is not cached
			setConnectionParametersManagerWindow(cpm, "sendConnectionFlowControlWindow", 5000)
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(5000)))
		})

		It("stops asking the ConnectionParametersManager for the connection flow control window size once a window update has arrived", func() {
			controller.streamID = 0
			Expect(controller.UpdateSendWindow(7000))
			setConnectionParametersManagerWindow(cpm, "sendConnectionFlowControlWindow", 9000)
			Expect(controller.getSendFlowControlWindow()).To(Equal(protocol.ByteCount(7000)))
		})
	})

	Context("receive flow control", func() {
		var receiveFlowControlWindow protocol.ByteCount = 10000
		var receiveFlowControlWindowIncrement protocol.ByteCount = 600

		BeforeEach(func() {
			controller.receiveFlowControlWindow = receiveFlowControlWindow
			controller.receiveFlowControlWindowIncrement = receiveFlowControlWindowIncrement
		})

		It("adds bytes read", func() {
			controller.bytesRead = 5
			controller.AddBytesRead(6)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("triggers a window update when necessary", func() {
			readPosition := receiveFlowControlWindow - receiveFlowControlWindowIncrement/2 + 1
			controller.bytesRead = readPosition
			updateNecessary, offset := controller.MaybeTriggerWindowUpdate()
			Expect(updateNecessary).To(BeTrue())
			Expect(offset).To(Equal(readPosition + receiveFlowControlWindowIncrement))
			Expect(controller.receiveFlowControlWindow).To(Equal(readPosition + receiveFlowControlWindowIncrement))
		})

		It("triggers a window update when not necessary", func() {
			readPosition := receiveFlowControlWindow - receiveFlowControlWindow/2 - 1
			controller.bytesRead = readPosition
			updateNecessary, _ := controller.MaybeTriggerWindowUpdate()
			Expect(updateNecessary).To(BeFalse())
		})

		It("updates the highestReceived", func() {
			controller.highestReceived = 1337
			increment := controller.UpdateHighestReceived(1338)
			Expect(increment).To(Equal(protocol.ByteCount(1338 - 1337)))
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
		})

		It("does not decrease the highestReceived", func() {
			controller.highestReceived = 1337
			increment := controller.UpdateHighestReceived(1000)
			Expect(increment).To(Equal(protocol.ByteCount(0)))
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
		})

		It("increases the highestReceived by a given increment", func() {
			controller.highestReceived = 1337
			controller.IncrementHighestReceived(123)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337 + 123)))
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
