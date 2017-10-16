package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow Control Manager", func() {
	var fcm *flowControlManager

	BeforeEach(func() {
		fcm = NewFlowControlManager(
			0x2000, // maxReceiveStreamWindow
			0x4000, // maxReceiveConnectionWindow
			&congestion.RTTStats{},
		).(*flowControlManager)
	})

	It("creates a connection level flow controller", func() {
		Expect(fcm.streamFlowController).To(BeEmpty())
		Expect(fcm.connFlowController.sendWindow).To(BeZero())
		Expect(fcm.connFlowController.maxReceiveWindowIncrement).To(Equal(protocol.ByteCount(0x4000)))
	})

	Context("creating new streams", func() {
		It("creates a new stream", func() {
			fcm.NewStream(5, false)
			Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
			fc := fcm.streamFlowController[5]
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.ContributesToConnection()).To(BeFalse())
			// the transport parameters have not yet been received. Start with a window of size 0
			Expect(fc.sendWindow).To(BeZero())
			Expect(fc.maxReceiveWindowIncrement).To(Equal(protocol.ByteCount(0x2000)))
		})

		It("creates a new stream after it has received transport parameters", func() {
			fcm.UpdateTransportParameters(&handshake.TransportParameters{
				StreamFlowControlWindow: 0x3000,
			})
			fcm.NewStream(5, false)
			Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
			fc := fcm.streamFlowController[5]
			Expect(fc.sendWindow).To(Equal(protocol.ByteCount(0x3000)))
		})

		It("doesn't create a new flow controller if called for an existing stream", func() {
			fcm.NewStream(5, true)
			Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
			fcm.streamFlowController[5].bytesRead = 0x1337
			fcm.NewStream(5, false)
			fc := fcm.streamFlowController[5]
			Expect(fc.bytesRead).To(BeEquivalentTo(0x1337))
			Expect(fc.ContributesToConnection()).To(BeTrue())
		})
	})

	It("removes streams", func() {
		fcm.NewStream(5, true)
		Expect(fcm.streamFlowController).To(HaveKey(protocol.StreamID(5)))
		fcm.RemoveStream(5)
		Expect(fcm.streamFlowController).ToNot(HaveKey(protocol.StreamID(5)))
	})

	It("updates the send windows for existing streams when receiveing the transport parameters", func() {
		fcm.NewStream(5, false)
		fcm.UpdateTransportParameters(&handshake.TransportParameters{
			StreamFlowControlWindow:     0x3000,
			ConnectionFlowControlWindow: 0x6000,
		})
		Expect(fcm.connFlowController.sendWindow).To(Equal(protocol.ByteCount(0x6000)))
		Expect(fcm.streamFlowController[5].sendWindow).To(Equal(protocol.ByteCount(0x3000)))
	})

	Context("receiving data", func() {
		BeforeEach(func() {
			fcm.NewStream(1, false)
			fcm.NewStream(4, true)
			fcm.NewStream(6, true)

			for _, fc := range fcm.streamFlowController {
				fc.receiveWindow = 100
				fc.receiveWindowIncrement = 100
			}
			fcm.connFlowController.receiveWindow = 200
			fcm.connFlowController.receiveWindowIncrement = 200
		})

		It("updates the connection level flow controller if the stream contributes", func() {
			err := fcm.UpdateHighestReceived(4, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.highestReceived).To(Equal(protocol.ByteCount(100)))
			Expect(fcm.streamFlowController[4].highestReceived).To(Equal(protocol.ByteCount(100)))
		})

		It("adds the offsets of multiple streams for the connection flow control window", func() {
			err := fcm.UpdateHighestReceived(4, 100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.UpdateHighestReceived(6, 50)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.highestReceived).To(Equal(protocol.ByteCount(100 + 50)))
		})

		It("does not update the connection level flow controller if the stream does not contribute", func() {
			err := fcm.UpdateHighestReceived(1, 100)
			// fcm.streamFlowController[4].receiveWindow = 0x1000
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.highestReceived).To(BeZero())
			Expect(fcm.streamFlowController[1].highestReceived).To(Equal(protocol.ByteCount(100)))
		})

		It("returns an error when called with an unknown stream", func() {
			err := fcm.UpdateHighestReceived(1337, 0x1337)
			Expect(err).To(MatchError(errMapAccess))
		})

		It("gets the offset of the receive window", func() {
			offset, err := fcm.GetReceiveWindow(4)
			Expect(err).ToNot(HaveOccurred())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
		})

		It("errors when asked for the receive window of a stream that doesn't exist", func() {
			_, err := fcm.GetReceiveWindow(17)
			Expect(err).To(MatchError(errMapAccess))
		})

		It("gets the offset of the connection-level receive window", func() {
			offset, err := fcm.GetReceiveWindow(0)
			Expect(err).ToNot(HaveOccurred())
			Expect(offset).To(Equal(protocol.ByteCount(200)))
		})

		Context("flow control violations", func() {
			It("errors when encountering a stream level flow control violation", func() {
				err := fcm.UpdateHighestReceived(4, 101)
				Expect(err).To(MatchError(qerr.Error(qerr.FlowControlReceivedTooMuchData, "Received 101 bytes on stream 4, allowed 100 bytes")))
			})

			It("errors when encountering a connection-level flow control violation", func() {
				fcm.streamFlowController[4].receiveWindow = 300
				fcm.streamFlowController[6].receiveWindow = 300
				err := fcm.UpdateHighestReceived(6, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.UpdateHighestReceived(4, 103)
				Expect(err).To(MatchError(qerr.Error(qerr.FlowControlReceivedTooMuchData, "Received 203 bytes for the connection, allowed 200 bytes")))
			})
		})

		Context("window updates", func() {
			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				for _, controller := range fcm.streamFlowController {
					controller.rttStats.UpdateRTT(t, 0, time.Now())
					Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
				}
			}

			It("gets stream level window updates", func() {
				err := fcm.UpdateHighestReceived(4, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(4, 90)
				Expect(err).ToNot(HaveOccurred())
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(1))
				Expect(updates[0]).To(Equal(WindowUpdate{StreamID: 4, Offset: 190}))
			})

			It("gets connection level window updates", func() {
				err := fcm.UpdateHighestReceived(4, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.UpdateHighestReceived(6, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(4, 90)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(6, 90)
				Expect(err).ToNot(HaveOccurred())
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(3))
				Expect(updates).ToNot(ContainElement(WindowUpdate{StreamID: 0, Offset: 200}))
			})

			It("errors when AddBytesRead is called for a stream doesn't exist", func() {
				err := fcm.AddBytesRead(17, 1000)
				Expect(err).To(MatchError(errMapAccess))
			})

			It("increases the connection-level window, when a stream window was increased by autotuning", func() {
				setRtt(10 * time.Millisecond)
				fcm.streamFlowController[4].lastWindowUpdateTime = time.Now().Add(-1 * time.Millisecond)
				err := fcm.UpdateHighestReceived(4, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(4, 90)
				Expect(err).ToNot(HaveOccurred())
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(2))
				connLevelIncrement := protocol.ByteCount(protocol.ConnectionFlowControlMultiplier * 200) // 300
				Expect(updates).To(ContainElement(WindowUpdate{StreamID: 4, Offset: 290}))
				Expect(updates).To(ContainElement(WindowUpdate{StreamID: 0, Offset: 90 + connLevelIncrement}))
			})

			It("doesn't increase the connection-level window, when a non-contributing stream window was increased by autotuning", func() {
				setRtt(10 * time.Millisecond)
				fcm.streamFlowController[1].lastWindowUpdateTime = time.Now().Add(-1 * time.Millisecond)
				err := fcm.UpdateHighestReceived(1, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.AddBytesRead(1, 90)
				Expect(err).ToNot(HaveOccurred())
				updates := fcm.GetWindowUpdates()
				Expect(updates).To(HaveLen(1))
				Expect(updates).To(ContainElement(WindowUpdate{StreamID: 1, Offset: 290}))
				// the only window update is for stream 1, thus there's no connection-level window update
			})
		})
	})

	Context("resetting a stream", func() {
		BeforeEach(func() {
			fcm.NewStream(1, false)
			fcm.NewStream(4, true)
			fcm.NewStream(6, true)
			fcm.streamFlowController[1].bytesSent = 41
			fcm.streamFlowController[4].bytesSent = 42

			for _, fc := range fcm.streamFlowController {
				fc.receiveWindow = 100
				fc.receiveWindowIncrement = 100
			}
			fcm.connFlowController.receiveWindow = 200
			fcm.connFlowController.receiveWindowIncrement = 200
		})

		It("updates the connection level flow controller if the stream contributes", func() {
			err := fcm.ResetStream(4, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.highestReceived).To(Equal(protocol.ByteCount(100)))
			Expect(fcm.streamFlowController[4].highestReceived).To(Equal(protocol.ByteCount(100)))
		})

		It("does not update the connection level flow controller if the stream does not contribute", func() {
			err := fcm.ResetStream(1, 100)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.highestReceived).To(BeZero())
			Expect(fcm.streamFlowController[1].highestReceived).To(Equal(protocol.ByteCount(100)))
		})

		It("errors if the byteOffset is smaller than a byteOffset that set earlier", func() {
			err := fcm.UpdateHighestReceived(4, 100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.ResetStream(4, 50)
			Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
		})

		It("returns an error when called with an unknown stream", func() {
			err := fcm.ResetStream(1337, 0x1337)
			Expect(err).To(MatchError(errMapAccess))
		})

		Context("flow control violations", func() {
			It("errors when encountering a stream level flow control violation", func() {
				err := fcm.ResetStream(4, 101)
				Expect(err).To(MatchError(qerr.Error(qerr.FlowControlReceivedTooMuchData, "Received 101 bytes on stream 4, allowed 100 bytes")))
			})

			It("errors when encountering a connection-level flow control violation", func() {
				fcm.streamFlowController[4].receiveWindow = 300
				fcm.streamFlowController[6].receiveWindow = 300
				err := fcm.ResetStream(4, 100)
				Expect(err).ToNot(HaveOccurred())
				err = fcm.ResetStream(6, 101)
				Expect(err).To(MatchError(qerr.Error(qerr.FlowControlReceivedTooMuchData, "Received 201 bytes for the connection, allowed 200 bytes")))
			})
		})
	})

	Context("sending data", func() {
		It("adds bytes sent for all stream contributing to connection level flow control", func() {
			fcm.NewStream(1, false)
			fcm.NewStream(3, true)
			fcm.NewStream(5, true)
			err := fcm.AddBytesSent(1, 100)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.AddBytesSent(3, 200)
			Expect(err).ToNot(HaveOccurred())
			err = fcm.AddBytesSent(5, 500)
			Expect(err).ToNot(HaveOccurred())
			Expect(fcm.connFlowController.bytesSent).To(Equal(protocol.ByteCount(200 + 500)))
		})

		It("errors when called for a stream doesn't exist", func() {
			err := fcm.AddBytesSent(17, 1000)
			Expect(err).To(MatchError(errMapAccess))
		})

		Context("window updates", func() {
			It("updates the window for a normal stream", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(5, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
			})

			It("updates the connection level window", func() {
				updated, err := fcm.UpdateWindow(0, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
			})

			It("errors when called for a stream that doesn't exist", func() {
				_, err := fcm.UpdateWindow(17, 1000)
				Expect(err).To(MatchError(errMapAccess))
			})
		})

		Context("window sizes", func() {
			It("gets the window size of a stream", func() {
				fcm.NewStream(5, false)
				updated, err := fcm.UpdateWindow(5, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(5, 500)
				size, err := fcm.SendWindowSize(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(size).To(Equal(protocol.ByteCount(1000 - 500)))
			})

			It("gets the connection window size", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(0, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(5, 500)
				size := fcm.RemainingConnectionWindowSize()
				Expect(size).To(Equal(protocol.ByteCount(1000 - 500)))
			})

			It("erros when asked for the send window size of a stream that doesn't exist", func() {
				_, err := fcm.SendWindowSize(17)
				Expect(err).To(MatchError(errMapAccess))
			})

			It("limits the stream window size by the connection window size", func() {
				fcm.NewStream(5, true)
				updated, err := fcm.UpdateWindow(0, 500)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				updated, err = fcm.UpdateWindow(5, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				size, err := fcm.SendWindowSize(5)
				Expect(err).NotTo(HaveOccurred())
				Expect(size).To(Equal(protocol.ByteCount(500)))
			})

			It("does not reduce the size of the connection level window, if the stream does not contribute", func() {
				fcm.NewStream(3, false)
				updated, err := fcm.UpdateWindow(0, 1000)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue())
				fcm.AddBytesSent(3, 456) // WindowSize should return the same value no matter how much was sent
				size := fcm.RemainingConnectionWindowSize()
				Expect(size).To(Equal(protocol.ByteCount(1000)))
			})
		})
	})
})
