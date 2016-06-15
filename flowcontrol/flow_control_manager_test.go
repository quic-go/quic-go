package flowcontrol

import (
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow Control Manager", func() {
	var fcm *flowControlManager
	var cpm *handshake.ConnectionParametersManager

	BeforeEach(func() {
		cpm = &handshake.ConnectionParametersManager{}
		setConnectionParametersManagerWindow(cpm, "receiveStreamFlowControlWindow", 0x100)
		setConnectionParametersManagerWindow(cpm, "receiveConnectionFlowControlWindow", 0x200)
		fcm = NewFlowControlManager(cpm).(*flowControlManager)
	})

	It("creates a connection level flow controller", func() {
		Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(0)))
		Expect(fcm.contributesToConnectionFlowControl).To(HaveKey(protocol.StreamID(0)))
	})

	Context("creating new streams", func() {
		It("creates a new stream", func() {
			fcm.NewStream(5, true)
			Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
			Expect(fcm.streamFlowController[5]).ToNot(BeNil())
			Expect(fcm.contributesToConnectionFlowControl).To(HaveKey(protocol.StreamID(5)))
			Expect(fcm.contributesToConnectionFlowControl[5]).To(BeTrue())
		})
	})

	Context("receiving data", func() {
		BeforeEach(func() {
			fcm.NewStream(1, false)
			fcm.NewStream(4, true)
			fcm.NewStream(6, true)
		})

		It("updates the connection level flow controller if the stream does not contribute", func() {
			err := fcm.UpdateHighestReceived(4, 0x100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].highestReceived).To(Equal(protocol.ByteCount(0x100)))
			Expect(fcm.streamFlowController[4].highestReceived).To(Equal(protocol.ByteCount(0x100)))
		})

		It("adds the offsets of multiple streams for the connection flow control window", func() {
			err := fcm.UpdateHighestReceived(4, 0x100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.UpdateHighestReceived(6, 0x50)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].highestReceived).To(Equal(protocol.ByteCount(0x100 + 0x50)))
		})

		It("does not update the connection level flow controller if the stream does not contribute", func() {
			err := fcm.UpdateHighestReceived(1, 0x100)
			// fcm.streamFlowController[4].receiveFlowControlWindow = 0x1000
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].highestReceived).To(Equal(protocol.ByteCount(0)))
			Expect(fcm.streamFlowController[1].highestReceived).To(Equal(protocol.ByteCount(0x100)))
		})

		Context("flow control violations", func() {
			It("errors when encountering a stream level flow control violation", func() {
				err := fcm.UpdateHighestReceived(4, 0x101)
				Expect(err).To(MatchError(ErrStreamFlowControlViolation))
			})

			It("errors when encountering a connection-level flow control violation", func() {
				fcm.streamFlowController[4].receiveFlowControlWindow = 0x300
				err := fcm.UpdateHighestReceived(4, 0x201)
				Expect(err).To(MatchError(ErrConnectionFlowControlViolation))
			})
		})

		Context("window updates", func() {
			It("gets stream level window updates", func() {
				err := fcm.UpdateHighestReceived(4, 0x100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(4, 0x100-0x10)
				Expect(err).ToNot(HaveOccurred())
				doIt, offset, err := fcm.MaybeTriggerStreamWindowUpdate(4)
				Expect(err).ToNot(HaveOccurred())
				Expect(doIt).To(BeTrue())
				Expect(offset).ToNot(Equal(protocol.ByteCount(0x100)))
			})

			It("gets connection level window updates", func() {
				err := fcm.UpdateHighestReceived(4, 0x100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.UpdateHighestReceived(6, 0x100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(4, 0x100-0x10)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(6, 0x100-0x10)
				Expect(err).ToNot(HaveOccurred())
				doIt, offset := fcm.MaybeTriggerConnectionWindowUpdate()
				Expect(err).ToNot(HaveOccurred())
				Expect(doIt).To(BeTrue())
				Expect(offset).ToNot(Equal(protocol.ByteCount(0x200)))
			})
		})
	})
})
