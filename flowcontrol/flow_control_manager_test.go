package flowcontrol

import (
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow Control Manager", func() {
	var fcm *flowControlManager
	var cpm handshake.ConnectionParametersManager

	BeforeEach(func() {
		cpm = &mockConnectionParametersManager{
			receiveStreamFlowControlWindow:     0x100,
			receiveConnectionFlowControlWindow: 0x200,
		}
		fcm = NewFlowControlManager(cpm, &congestion.RTTStats{}).(*flowControlManager)
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

	It("removes streams", func() {
		fcm.NewStream(5, true)
		Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
		fcm.RemoveStream(5)
		Expect(fcm.streamFlowController).ToNot(HaveKey(protocol.StreamID(5)))
		Expect(fcm.contributesToConnectionFlowControl).ToNot(HaveKey(protocol.StreamID(5)))
	})

	Context("receiving data", func() {
		BeforeEach(func() {
			fcm.NewStream(1, false)
			fcm.NewStream(4, true)
			fcm.NewStream(6, true)
		})

		It("updates the connection level flow controller if the stream contributes", func() {
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
			Expect(fcm.streamFlowController[0].highestReceived).To(BeZero())
			Expect(fcm.streamFlowController[1].highestReceived).To(Equal(protocol.ByteCount(0x100)))
		})

		It("returns an error when called with an unknown stream", func() {
			err := fcm.UpdateHighestReceived(1337, 0x1337)
			Expect(err).To(MatchError(errMapAccess))
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
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(1))
				Expect(updates[0].StreamID).To(Equal(protocol.StreamID(4)))
				Expect(updates[0].Offset).To(Equal(protocol.ByteCount(0x1f0)))
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
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(3))
				if updates[0].StreamID == 0 {
					Expect(updates[0].Offset).ToNot(Equal(protocol.ByteCount(0x200)))
				} else if updates[1].StreamID == 0 {
					Expect(updates[1].Offset).ToNot(Equal(protocol.ByteCount(0x200)))
				} else {
					Expect(updates[2].Offset).ToNot(Equal(protocol.ByteCount(0x200)))
				}
			})
		})
	})

	Context("resetting a stream", func() {
		BeforeEach(func() {
			fcm.NewStream(1, false)
			fcm.NewStream(4, true)
			fcm.NewStream(6, true)
		})

		It("updates the connection level flow controller if the stream contributes", func() {
			err := fcm.ResetStream(4, 0x100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].highestReceived).To(Equal(protocol.ByteCount(0x100)))
			Expect(fcm.streamFlowController[4].highestReceived).To(Equal(protocol.ByteCount(0x100)))
		})

		It("does not update the connection level flow controller if the stream does not contribute", func() {
			err := fcm.ResetStream(1, 0x100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].highestReceived).To(BeZero())
			Expect(fcm.streamFlowController[1].highestReceived).To(Equal(protocol.ByteCount(0x100)))
		})

		It("errors if the byteOffset is smaller than a byteOffset that set earlier", func() {
			err := fcm.UpdateHighestReceived(4, 0x100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.ResetStream(4, 0x50)
			Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
		})

		It("returns an error when called with an unknown stream", func() {
			err := fcm.ResetStream(1337, 0x1337)
			Expect(err).To(MatchError(errMapAccess))
		})

		Context("flow control violations", func() {
			It("errors when encountering a stream level flow control violation", func() {
				err := fcm.ResetStream(4, 0x101)
				Expect(err).To(MatchError(ErrStreamFlowControlViolation))
			})

			It("errors when encountering a connection-level flow control violation", func() {
				fcm.streamFlowController[4].receiveFlowControlWindow = 0x300
				err := fcm.ResetStream(4, 0x201)
				Expect(err).To(MatchError(ErrConnectionFlowControlViolation))
			})
		})
	})

	Context("sending data", func() {
		It("adds bytes sent for all stream contributing to connection level flow control", func() {
			fcm.NewStream(1, false)
			fcm.NewStream(3, true)
			fcm.NewStream(5, true)
			err := fcm.AddBytesSent(1, 0x100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.AddBytesSent(3, 0x200)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.AddBytesSent(5, 0x500)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.streamFlowController[0].bytesSent).To(Equal(protocol.ByteCount(0x200 + 0x500)))
		})

		Context("window updates", func() {
			It("updates the window for a normal stream", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(5, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
			})

			It("updates the connection level window", func() {
				updated, err := fcm.UpdateWindow(0, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
			})
		})

		Context("window sizes", func() {
			It("gets the window size of a stream", func() {
				fcm.NewStream(5, false)
				updated, err := fcm.UpdateWindow(5, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(5, 0x500)
				size, err := fcm.SendWindowSize(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(size).To(Equal(protocol.ByteCount(0x1000 - 0x500)))
			})

			It("gets the connection window size", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(0, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(5, 0x500)
				size := fcm.RemainingConnectionWindowSize()
				Expect(size).To(Equal(protocol.ByteCount(0x1000 - 0x500)))
			})

			It("limits the stream window size by the connection window size", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(0, 0x500)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				updated, err = fcm.UpdateWindow(5, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				size, err := fcm.SendWindowSize(5)
				Expect(err).NotTo(HaveOccurred())
				Expect(size).To(Equal(protocol.ByteCount(0x500)))
			})

			It("does not reduce the size of the connection level window, if the stream does not contribute", func() {
				fcm.NewStream(3, false)
				updated, err := fcm.UpdateWindow(0, 0x1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(3, 0x456) // WindowSize should return the same value no matter how much was sent
				size := fcm.RemainingConnectionWindowSize()
				Expect(size).To(Equal(protocol.ByteCount(0x1000)))
			})
		})
	})
})
