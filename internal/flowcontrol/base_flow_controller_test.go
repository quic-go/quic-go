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
			Expect(controller.IsBlocked()).To(BeFalse())
			controller.AddBytesSent(100)
			blocked, offset := controller.IsBlocked()
			Expect(blocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
		})
	})

	Context("receive flow control", func() {
		var (
			receiveWindow          protocol.ByteCount = 10000
			receiveWindowIncrement protocol.ByteCount = 600
		)

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
			bytesConsumed := float64(receiveWindowIncrement)*protocol.WindowUpdateThreshold + 1 // consumed 1 byte more than the threshold
			bytesRemaining := receiveWindowIncrement - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(Equal(readPosition + receiveWindowIncrement))
			Expect(controller.receiveWindow).To(Equal(readPosition + receiveWindowIncrement))
			Expect(controller.lastWindowUpdateTime).To(BeTemporally("~", time.Now(), 20*time.Millisecond))
		})

		It("doesn't trigger a window update when not necessary", func() {
			lastWindowUpdateTime := time.Now().Add(-time.Hour)
			controller.lastWindowUpdateTime = lastWindowUpdateTime
			bytesConsumed := float64(receiveWindowIncrement)*protocol.WindowUpdateThreshold - 1 // consumed 1 byte less than the threshold
			bytesRemaining := receiveWindowIncrement - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(BeZero())
			Expect(controller.lastWindowUpdateTime).To(Equal(lastWindowUpdateTime))
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

			It("increases the increment when the last WindowUpdate was sent less than (4 * threshold) RTTs ago", func() {
				rtt := 20 * time.Millisecond
				setRtt(rtt)
				controller.AddBytesRead(9900) // receive window is 10000
				controller.lastWindowUpdateTime = time.Now().Add(-4*protocol.WindowUpdateThreshold*rtt + time.Millisecond)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				// check that the increment was increased
				newIncrement := controller.receiveWindowIncrement
				Expect(newIncrement).To(Equal(2 * oldIncrement))
				// check that the new increment was used to increase the offset
				Expect(offset).To(Equal(protocol.ByteCount(9900 + newIncrement)))
			})

			It("doesn't increase the increase increment when the last WindowUpdate was sent more than (4 * threshold) RTTs ago", func() {
				rtt := 20 * time.Millisecond
				setRtt(rtt)
				controller.lastWindowUpdateTime = time.Now().Add(-4*protocol.WindowUpdateThreshold*rtt - time.Millisecond)
				controller.maybeAdjustWindowIncrement()
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
			})

			It("doesn't increase the increment to a value higher than the maxReceiveWindowIncrement", func() {
				setRtt(20 * time.Millisecond)
				controller.lastWindowUpdateTime = time.Now().Add(-time.Millisecond)
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

			It("increases the increment sent in the first WindowUpdate, if data is read fast enough", func() {
				setRtt(20 * time.Millisecond)
				controller.AddBytesRead(9900)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowIncrement).To(Equal(2 * oldIncrement))
			})

			It("doesn't increamse the increment sent in the first WindowUpdate, if data is read slowly", func() {
				setRtt(5 * time.Millisecond)
				controller.AddBytesRead(9900)
				time.Sleep(15 * time.Millisecond) // more than 2x RTT
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
			})
		})
	})
})
