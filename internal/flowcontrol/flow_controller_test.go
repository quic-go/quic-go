package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Flow controller", func() {
	var controller *flowController

	BeforeEach(func() {
		controller = &flowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("Constructor", func() {
		var rttStats *congestion.RTTStats
		var mockCpm *mocks.MockConnectionParametersManager

		BeforeEach(func() {
			mockCpm = mocks.NewMockConnectionParametersManager(mockCtrl)
			mockCpm.EXPECT().GetSendStreamFlowControlWindow().AnyTimes().Return(protocol.ByteCount(1000))
			mockCpm.EXPECT().GetReceiveStreamFlowControlWindow().AnyTimes().Return(protocol.ByteCount(2000))
			mockCpm.EXPECT().GetSendConnectionFlowControlWindow().AnyTimes().Return(protocol.ByteCount(3000))
			mockCpm.EXPECT().GetReceiveConnectionFlowControlWindow().AnyTimes().Return(protocol.ByteCount(4000))
			mockCpm.EXPECT().GetMaxReceiveStreamFlowControlWindow().AnyTimes().Return(protocol.ByteCount(8000))
			mockCpm.EXPECT().GetMaxReceiveConnectionFlowControlWindow().AnyTimes().Return(protocol.ByteCount(9000))
			rttStats = &congestion.RTTStats{}
		})

		It("reads the stream send and receive windows when acting as stream-level flow controller", func() {
			fc := newFlowController(5, true, mockCpm, rttStats)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveWindow).To(Equal(protocol.ByteCount(2000)))
			Expect(fc.maxReceiveWindowIncrement).To(Equal(mockCpm.GetMaxReceiveStreamFlowControlWindow()))
		})

		It("reads the stream send and receive windows when acting as connection-level flow controller", func() {
			fc := newFlowController(0, false, mockCpm, rttStats)
			Expect(fc.streamID).To(Equal(protocol.StreamID(0)))
			Expect(fc.receiveWindow).To(Equal(protocol.ByteCount(4000)))
			Expect(fc.maxReceiveWindowIncrement).To(Equal(mockCpm.GetMaxReceiveConnectionFlowControlWindow()))
		})

		It("does not set the stream flow control windows for sending", func() {
			fc := newFlowController(5, true, mockCpm, rttStats)
			Expect(fc.sendWindow).To(BeZero())
		})

		It("does not set the connection flow control windows for sending", func() {
			fc := newFlowController(0, false, mockCpm, rttStats)
			Expect(fc.sendWindow).To(BeZero())
		})

		It("says if it contributes to connection-level flow control", func() {
			fc := newFlowController(1, false, mockCpm, rttStats)
			Expect(fc.ContributesToConnection()).To(BeFalse())
			fc = newFlowController(5, true, mockCpm, rttStats)
			Expect(fc.ContributesToConnection()).To(BeTrue())
		})
	})

	Context("send flow control", func() {
		var mockCpm *mocks.MockConnectionParametersManager

		BeforeEach(func() {
			mockCpm = mocks.NewMockConnectionParametersManager(mockCtrl)
			controller.connectionParameters = mockCpm
		})

		It("adds bytes sent", func() {
			controller.bytesSent = 5
			controller.AddBytesSent(6)
			Expect(controller.bytesSent).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("gets the size of the remaining flow control window", func() {
			controller.bytesSent = 5
			controller.sendWindow = 12
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(12 - 5)))
		})

		It("gets the offset of the flow control window", func() {
			controller.bytesSent = 5
			controller.sendWindow = 12
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
			mockCpm.EXPECT().GetSendStreamFlowControlWindow().Return(protocol.ByteCount(1000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(1000)))
			// make sure the value is not cached
			mockCpm.EXPECT().GetSendStreamFlowControlWindow().Return(protocol.ByteCount(2000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(2000)))
		})

		It("stops asking the ConnectionParametersManager for the flow control stream window size once a window update has arrived", func() {
			controller.streamID = 5
			Expect(controller.UpdateSendWindow(8000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(8000)))
		})

		It("asks the ConnectionParametersManager for the connection flow control window size", func() {
			controller.streamID = 0
			mockCpm.EXPECT().GetSendConnectionFlowControlWindow().Return(protocol.ByteCount(3000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(3000)))
			// make sure the value is not cached
			mockCpm.EXPECT().GetSendConnectionFlowControlWindow().Return(protocol.ByteCount(5000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(5000)))
		})

		It("stops asking the ConnectionParametersManager for the connection flow control window size once a window update has arrived", func() {
			controller.streamID = 0
			Expect(controller.UpdateSendWindow(7000))
			Expect(controller.getSendWindow()).To(Equal(protocol.ByteCount(7000)))
		})
	})

	Context("receive flow control", func() {
		var receiveWindow protocol.ByteCount = 10000
		var receiveWindowIncrement protocol.ByteCount = 600

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowIncrement = receiveWindowIncrement
		})

		It("adds bytes read", func() {
			controller.bytesRead = 5
			controller.AddBytesRead(6)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("triggers a window update when necessary", func() {
			controller.lastWindowUpdateTime = time.Now().Add(-time.Hour)
			readPosition := receiveWindow - receiveWindowIncrement/2 + 1
			controller.bytesRead = readPosition
			updateNecessary, _, offset := controller.MaybeUpdateWindow()
			Expect(updateNecessary).To(BeTrue())
			Expect(offset).To(Equal(readPosition + receiveWindowIncrement))
			Expect(controller.receiveWindow).To(Equal(readPosition + receiveWindowIncrement))
			Expect(controller.lastWindowUpdateTime).To(BeTemporally("~", time.Now(), 20*time.Millisecond))
		})

		It("doesn't trigger a window update when not necessary", func() {
			lastWindowUpdateTime := time.Now().Add(-time.Hour)
			controller.lastWindowUpdateTime = lastWindowUpdateTime
			readPosition := receiveWindow - receiveWindow/2 - 1
			controller.bytesRead = readPosition
			updateNecessary, _, _ := controller.MaybeUpdateWindow()
			Expect(updateNecessary).To(BeFalse())
			Expect(controller.lastWindowUpdateTime).To(Equal(lastWindowUpdateTime))
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

		It("increases the highestReceived by a given increment", func() {
			controller.highestReceived = 1337
			controller.IncrementHighestReceived(123)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337 + 123)))
		})

		It("detects a flow control violation", func() {
			controller.UpdateHighestReceived(receiveWindow + 1)
			Expect(controller.CheckFlowControlViolation()).To(BeTrue())
		})

		It("does not give a flow control violation when using the window completely", func() {
			controller.UpdateHighestReceived(receiveWindow)
			Expect(controller.CheckFlowControlViolation()).To(BeFalse())
		})

		Context("receive window increment auto-tuning", func() {
			var oldIncrement protocol.ByteCount

			BeforeEach(func() {
				oldIncrement = controller.receiveWindowIncrement
				controller.maxReceiveWindowIncrement = 3000
			})

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			It("doesn't increase the increment for a new stream", func() {
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
			})

			It("doesn't increase the increment when no RTT estimate is available", func() {
				setRtt(0)
				controller.lastWindowUpdateTime = time.Now()
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
			})

			It("increases the increment when the last WindowUpdate was sent less than two RTTs ago", func() {
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-35 * time.Millisecond)
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(2 * oldIncrement))
			})

			It("doesn't increase the increase increment when the last WindowUpdate was sent more than two RTTs ago", func() {
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-45 * time.Millisecond)
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
			})

			It("doesn't increase the increment to a value higher than the maxReceiveWindowIncrement", func() {
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-35 * time.Millisecond)
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(2 * oldIncrement)) // 1200
				// because the lastWindowUpdateTime is updated by MaybeTriggerWindowUpdate(), we can just call maybeAdjustWindowIncrement() multiple times and get an increase of the increment every time
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(2 * 2 * oldIncrement)) // 2400
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(controller.maxReceiveWindowIncrement)) // 3000
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(controller.maxReceiveWindowIncrement)) // 3000
			})

			It("returns the new increment when updating the window", func() {
				setRtt(20 * time.Millisecond)
				controller.AddBytesRead(9900) // receive window is 10000
				controller.lastWindowUpdateTime = time.Now().Add(-35 * time.Millisecond)
				necessary, newIncrement, offset := controller.MaybeUpdateWindow()
				Expect(necessary).To(BeTrue())
				Expect(newIncrement).To(Equal(2 * oldIncrement))
				Expect(controller.receiveWindowIncrement).To(Equal(newIncrement))
				Expect(offset).To(Equal(protocol.ByteCount(9900 + newIncrement)))
			})

			It("increases the increment sent in the first WindowUpdate, if data is read fast enough", func() {
				setRtt(20 * time.Millisecond)
				controller.AddBytesRead(9900)
				necessary, newIncrement, _ := controller.MaybeUpdateWindow()
				Expect(necessary).To(BeTrue())
				Expect(newIncrement).To(Equal(2 * oldIncrement))
			})

			It("doesn't increamse the increment sent in the first WindowUpdate, if data is read slowly", func() {
				setRtt(5 * time.Millisecond)
				controller.AddBytesRead(9900)
				time.Sleep(15 * time.Millisecond) // more than 2x RTT
				necessary, newIncrement, _ := controller.MaybeUpdateWindow()
				Expect(necessary).To(BeTrue())
				Expect(newIncrement).To(BeZero())
			})

			It("only returns the increment if it was increased", func() {
				setRtt(20 * time.Millisecond)
				controller.AddBytesRead(9900) // receive window is 10000
				controller.lastWindowUpdateTime = time.Now().Add(-45 * time.Millisecond)
				necessary, newIncrement, offset := controller.MaybeUpdateWindow()
				Expect(necessary).To(BeTrue())
				Expect(newIncrement).To(BeZero())
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
				Expect(offset).To(Equal(protocol.ByteCount(9900 + oldIncrement)))
			})

			Context("setting the minimum increment", func() {
				It("sets the minimum window increment", func() {
					controller.EnsureMinimumWindowIncrement(1000)
					Expect(controller.receiveWindowIncrement).To(Equal(protocol.ByteCount(1000)))
				})

				It("doesn't reduce the window increment", func() {
					controller.EnsureMinimumWindowIncrement(1)
					Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
				})

				It("doens't increase the increment beyong the maxReceiveWindowIncrement", func() {
					max := controller.maxReceiveWindowIncrement
					controller.EnsureMinimumWindowIncrement(2 * max)
					Expect(controller.receiveWindowIncrement).To(Equal(max))
				})

				It("doesn't auto-tune the window after the increment was increased", func() {
					setRtt(20 * time.Millisecond)
					controller.bytesRead = 9900 // receive window is 10000
					controller.lastWindowUpdateTime = time.Now().Add(-20 * time.Millisecond)
					controller.EnsureMinimumWindowIncrement(912)
					necessary, newIncrement, offset := controller.MaybeUpdateWindow()
					Expect(necessary).To(BeTrue())
					Expect(newIncrement).To(BeZero()) // no auto-tuning
					Expect(offset).To(Equal(protocol.ByteCount(9900 + 912)))
				})
			})
		})
	})
})
