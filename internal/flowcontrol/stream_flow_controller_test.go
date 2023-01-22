package flowcontrol

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Flow controller", func() {
	var (
		controller         *streamFlowController
		queuedWindowUpdate bool
	)

	BeforeEach(func() {
		queuedWindowUpdate = false
		rttStats := &utils.RTTStats{}
		controller = &streamFlowController{
			streamID: 10,
			connection: NewConnectionFlowController(
				1000,
				1000,
				func() {},
				func(protocol.ByteCount) bool { return true },
				rttStats,
				utils.DefaultLogger,
			).(*connectionFlowController),
		}
		controller.maxReceiveWindowSize = 10000
		controller.rttStats = rttStats
		controller.logger = utils.DefaultLogger
		controller.queueWindowUpdate = func() { queuedWindowUpdate = true }
	})

	Context("Constructor", func() {
		rttStats := &utils.RTTStats{}
		const receiveWindow protocol.ByteCount = 2000
		const maxReceiveWindow protocol.ByteCount = 3000
		const sendWindow protocol.ByteCount = 4000

		It("sets the send and receive windows", func() {
			cc := NewConnectionFlowController(0, 0, nil, func(protocol.ByteCount) bool { return true }, nil, utils.DefaultLogger)
			fc := NewStreamFlowController(5, cc, receiveWindow, maxReceiveWindow, sendWindow, nil, rttStats, utils.DefaultLogger).(*streamFlowController)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowSize).To(Equal(maxReceiveWindow))
			Expect(fc.sendWindow).To(Equal(sendWindow))
		})

		It("queues window updates with the correct stream ID", func() {
			var queued bool
			queueWindowUpdate := func(id protocol.StreamID) {
				Expect(id).To(Equal(protocol.StreamID(5)))
				queued = true
			}

			cc := NewConnectionFlowController(receiveWindow, maxReceiveWindow, func() {}, func(protocol.ByteCount) bool { return true }, nil, utils.DefaultLogger)
			fc := NewStreamFlowController(5, cc, receiveWindow, maxReceiveWindow, sendWindow, queueWindowUpdate, rttStats, utils.DefaultLogger).(*streamFlowController)
			fc.AddBytesRead(receiveWindow)
			Expect(queued).To(BeTrue())
		})
	})

	Context("receiving data", func() {
		Context("registering received offsets", func() {
			var receiveWindow protocol.ByteCount = 10000
			var receiveWindowSize protocol.ByteCount = 600

			BeforeEach(func() {
				controller.receiveWindow = receiveWindow
				controller.receiveWindowSize = receiveWindowSize
			})

			It("updates the highestReceived", func() {
				controller.highestReceived = 1337
				Expect(controller.UpdateHighestReceived(1338, false)).To(Succeed())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
			})

			It("informs the connection flow controller about received data", func() {
				controller.highestReceived = 10
				controller.connection.(*connectionFlowController).highestReceived = 100
				Expect(controller.UpdateHighestReceived(20, false)).To(Succeed())
				Expect(controller.connection.(*connectionFlowController).highestReceived).To(Equal(protocol.ByteCount(100 + 10)))
			})

			It("does not decrease the highestReceived", func() {
				controller.highestReceived = 1337
				Expect(controller.UpdateHighestReceived(1000, false)).To(Succeed())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
			})

			It("does nothing when setting the same byte offset", func() {
				controller.highestReceived = 1337
				Expect(controller.UpdateHighestReceived(1337, false)).To(Succeed())
			})

			It("does not give a flow control violation when using the window completely", func() {
				controller.connection.(*connectionFlowController).receiveWindow = receiveWindow
				Expect(controller.UpdateHighestReceived(receiveWindow, false)).To(Succeed())
			})

			It("detects a flow control violation", func() {
				Expect(controller.UpdateHighestReceived(receiveWindow+1, false)).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.FlowControlError,
					ErrorMessage: "received 10001 bytes on stream 10, allowed 10000 bytes",
				}))
			})

			It("accepts a final offset higher than the highest received", func() {
				Expect(controller.UpdateHighestReceived(100, false)).To(Succeed())
				Expect(controller.UpdateHighestReceived(101, true)).To(Succeed())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(101)))
			})

			It("errors when receiving a final offset smaller than the highest offset received so far", func() {
				controller.UpdateHighestReceived(100, false)
				Expect(controller.UpdateHighestReceived(50, true)).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.FinalSizeError,
					ErrorMessage: "received final offset 50 for stream 10, but already received offset 100 before",
				}))
			})

			It("accepts delayed data after receiving a final offset", func() {
				Expect(controller.UpdateHighestReceived(300, true)).To(Succeed())
				Expect(controller.UpdateHighestReceived(250, false)).To(Succeed())
			})

			It("errors when receiving a higher offset after receiving a final offset", func() {
				Expect(controller.UpdateHighestReceived(200, true)).To(Succeed())
				Expect(controller.UpdateHighestReceived(250, false)).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.FinalSizeError,
					ErrorMessage: "received offset 250 for stream 10, but final offset was already received at 200",
				}))
			})

			It("accepts duplicate final offsets", func() {
				Expect(controller.UpdateHighestReceived(200, true)).To(Succeed())
				Expect(controller.UpdateHighestReceived(200, true)).To(Succeed())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(200)))
			})

			It("errors when receiving inconsistent final offsets", func() {
				Expect(controller.UpdateHighestReceived(200, true)).To(Succeed())
				Expect(controller.UpdateHighestReceived(201, true)).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.FinalSizeError,
					ErrorMessage: "received inconsistent final offset for stream 10 (old: 200, new: 201 bytes)",
				}))
			})

			It("tells the connection flow controller when a stream is abandoned", func() {
				controller.AddBytesRead(5)
				Expect(controller.UpdateHighestReceived(100, true)).To(Succeed())
				controller.Abandon()
				Expect(controller.connection.(*connectionFlowController).bytesRead).To(Equal(protocol.ByteCount(100)))
			})
		})

		It("saves when data is read", func() {
			controller.AddBytesRead(200)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(200)))
			Expect(controller.connection.(*connectionFlowController).bytesRead).To(Equal(protocol.ByteCount(200)))
		})

		Context("generating window updates", func() {
			var oldWindowSize protocol.ByteCount

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			BeforeEach(func() {
				controller.receiveWindow = 100
				controller.receiveWindowSize = 60
				controller.bytesRead = 100 - 60
				controller.connection.(*connectionFlowController).receiveWindow = 100
				controller.connection.(*connectionFlowController).receiveWindowSize = 120
				oldWindowSize = controller.receiveWindowSize
			})

			It("queues window updates", func() {
				controller.AddBytesRead(1)
				Expect(queuedWindowUpdate).To(BeFalse())
				controller.AddBytesRead(29)
				Expect(queuedWindowUpdate).To(BeTrue())
				Expect(controller.GetWindowUpdate()).ToNot(BeZero())
				queuedWindowUpdate = false
				controller.AddBytesRead(1)
				Expect(queuedWindowUpdate).To(BeFalse())
			})

			It("tells the connection flow controller when the window was auto-tuned", func() {
				var allowed protocol.ByteCount
				controller.connection.(*connectionFlowController).allowWindowIncrease = func(size protocol.ByteCount) bool {
					allowed = size
					return true
				}
				oldOffset := controller.bytesRead
				setRtt(scaleDuration(20 * time.Millisecond))
				controller.epochStartOffset = oldOffset
				controller.epochStartTime = time.Now().Add(-time.Millisecond)
				controller.AddBytesRead(55)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(oldOffset + 55 + 2*oldWindowSize))
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize))
				Expect(allowed).To(Equal(oldWindowSize))
				Expect(controller.connection.(*connectionFlowController).receiveWindowSize).To(Equal(protocol.ByteCount(float64(controller.receiveWindowSize) * protocol.ConnectionFlowControlMultiplier)))
			})

			It("doesn't increase the connection flow control window if it's not allowed", func() {
				oldOffset := controller.bytesRead
				oldConnectionSize := controller.connection.(*connectionFlowController).receiveWindowSize
				controller.connection.(*connectionFlowController).allowWindowIncrease = func(protocol.ByteCount) bool { return false }
				setRtt(scaleDuration(20 * time.Millisecond))
				controller.epochStartOffset = oldOffset
				controller.epochStartTime = time.Now().Add(-time.Millisecond)
				controller.AddBytesRead(55)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(oldOffset + 55 + 2*oldWindowSize))
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize))
				Expect(controller.connection.(*connectionFlowController).receiveWindowSize).To(Equal(oldConnectionSize))
			})

			It("sends a connection-level window update when a large stream is abandoned", func() {
				Expect(controller.UpdateHighestReceived(90, true)).To(Succeed())
				Expect(controller.connection.GetWindowUpdate()).To(BeZero())
				controller.Abandon()
				Expect(controller.connection.GetWindowUpdate()).ToNot(BeZero())
			})

			It("doesn't increase the window after a final offset was already received", func() {
				Expect(controller.UpdateHighestReceived(90, true)).To(Succeed())
				controller.AddBytesRead(30)
				Expect(queuedWindowUpdate).To(BeFalse())
				offset := controller.GetWindowUpdate()
				Expect(offset).To(BeZero())
			})
		})
	})

	Context("sending data", func() {
		It("gets the size of the send window", func() {
			controller.connection.UpdateSendWindow(1000)
			controller.UpdateSendWindow(15)
			controller.AddBytesSent(5)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(10)))
		})

		It("makes sure that it doesn't overflow the connection-level window", func() {
			controller.connection.UpdateSendWindow(12)
			controller.UpdateSendWindow(20)
			controller.AddBytesSent(10)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(2)))
		})

		It("doesn't say that it's blocked, if only the connection is blocked", func() {
			controller.connection.UpdateSendWindow(50)
			controller.UpdateSendWindow(100)
			controller.AddBytesSent(50)
			blocked, _ := controller.connection.IsNewlyBlocked()
			Expect(blocked).To(BeTrue())
			Expect(controller.IsNewlyBlocked()).To(BeFalse())
		})
	})
})
