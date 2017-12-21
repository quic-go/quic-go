package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Base Flow controller", func() {
	var controller *baseFlowController

	BeforeEach(func() {
		controller = &baseFlowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("send flow control", func() {
		It("adds bytes sent", func() {
			controller.bytesSent = 5
			controller.AddBytesSent(6)
			Expect(controller.bytesSent).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("gets the size of the remaining flow control window", func() {
			controller.bytesSent = 5
			controller.sendWindow = 12
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(12 - 5)))
		})

		It("updates the size of the flow control window", func() {
			controller.AddBytesSent(5)
			controller.UpdateSendWindow(15)
			Expect(controller.sendWindow).To(Equal(protocol.ByteCount(15)))
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(15 - 5)))
		})

		It("says that the window size is 0 if we sent more than we were allowed to", func() {
			controller.AddBytesSent(15)
			controller.UpdateSendWindow(10)
			Expect(controller.sendWindowSize()).To(BeZero())
		})

		It("does not decrease the flow control window", func() {
			controller.UpdateSendWindow(20)
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(20)))
			controller.UpdateSendWindow(10)
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(20)))
		})

		It("says when it's blocked", func() {
			controller.UpdateSendWindow(100)
			Expect(controller.IsNewlyBlocked()).To(BeFalse())
			controller.AddBytesSent(100)
			blocked, offset := controller.IsNewlyBlocked()
			Expect(blocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
		})

		It("doesn't say that it's newly blocked multiple times for the same offset", func() {
			controller.UpdateSendWindow(100)
			controller.AddBytesSent(100)
			newlyBlocked, offset := controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
			newlyBlocked, _ = controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeFalse())
			controller.UpdateSendWindow(150)
			controller.AddBytesSent(150)
			newlyBlocked, offset = controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeTrue())
		})
	})

	Context("receive flow control", func() {
		var (
			receiveWindow     protocol.ByteCount = 10000
			receiveWindowSize protocol.ByteCount = 600
		)

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowSize = receiveWindowSize
		})

		It("adds bytes read", func() {
			controller.bytesRead = 5
			controller.AddBytesRead(6)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("triggers a window update when necessary", func() {
			controller.lastWindowUpdateTime = time.Now().Add(-time.Hour)
			bytesConsumed := float64(receiveWindowSize)*protocol.WindowUpdateThreshold + 1 // consumed 1 byte more than the threshold
			bytesRemaining := receiveWindowSize - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(Equal(readPosition + receiveWindowSize))
			Expect(controller.receiveWindow).To(Equal(readPosition + receiveWindowSize))
			Expect(controller.lastWindowUpdateTime).To(BeTemporally("~", time.Now(), 20*time.Millisecond))
		})

		It("doesn't trigger a window update when not necessary", func() {
			lastWindowUpdateTime := time.Now().Add(-time.Hour)
			controller.lastWindowUpdateTime = lastWindowUpdateTime
			bytesConsumed := float64(receiveWindowSize)*protocol.WindowUpdateThreshold - 1 // consumed 1 byte less than the threshold
			bytesRemaining := receiveWindowSize - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(BeZero())
			Expect(controller.lastWindowUpdateTime).To(Equal(lastWindowUpdateTime))
		})

		Context("receive window size auto-tuning", func() {
			var oldWindowSize protocol.ByteCount

			BeforeEach(func() {
				oldWindowSize = controller.receiveWindowSize
				controller.maxReceiveWindowSize = 3000
			})

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			It("doesn't increase the window size for a new stream", func() {
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})

			It("doesn't increase the window size when no RTT estimate is available", func() {
				setRtt(0)
				controller.lastWindowUpdateTime = time.Now()
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})

			It("increases the window size when the last WindowUpdate was sent less than (4 * threshold) RTTs ago", func() {
				rtt := 20 * time.Millisecond
				setRtt(rtt)
				controller.AddBytesRead(9900) // receive window is 10000
				controller.lastWindowUpdateTime = time.Now().Add(-4*protocol.WindowUpdateThreshold*rtt + time.Millisecond)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				// check that the window size was increased
				newWindowSize := controller.receiveWindowSize
				Expect(newWindowSize).To(Equal(2 * oldWindowSize))
				// check that the new window size was used to increase the offset
				Expect(offset).To(Equal(protocol.ByteCount(9900 + newWindowSize)))
			})

			It("doesn't increase the increase window size when the last WindowUpdate was sent more than (4 * threshold) RTTs ago", func() {
				rtt := 20 * time.Millisecond
				setRtt(rtt)
				controller.lastWindowUpdateTime = time.Now().Add(-4*protocol.WindowUpdateThreshold*rtt - time.Millisecond)
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})

			It("doesn't increase the window size to a value higher than the maxReceiveWindowSize", func() {
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-time.Millisecond)
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize)) // 1200
				// because the lastWindowUpdateTime is updated by MaybeTriggerWindowUpdate(), we can just call maybeAdjustWindowSize() multiple times and get an increase of the window size every time
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(2 * 2 * oldWindowSize)) // 2400
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(controller.maxReceiveWindowSize)) // 3000
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(controller.maxReceiveWindowSize)) // 3000
			})

			It("increases the window size sent in the first WindowUpdate, if data is read fast enough", func() {
				setRtt(20 * time.Millisecond)
				controller.AddBytesRead(9900)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize))
			})

			It("doesn't increase the window size sent in the first WindowUpdate, if data is read slowly", func() {
				setRtt(5 * time.Millisecond)
				controller.AddBytesRead(9900)
				time.Sleep(15 * time.Millisecond) // more than 2x RTT
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})
		})
	})
})
