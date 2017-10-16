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
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(12 - 5)))
		})

		It("gets the offset of the flow control window", func() {
			controller.bytesSent = 5
			controller.sendWindow = 12
			Expect(controller.sendWindow).To(Equal(protocol.ByteCount(12)))
		})

		It("updates the size of the flow control window", func() {
			controller.bytesSent = 5
			updateSuccessful := controller.UpdateSendWindow(15)
			Expect(updateSuccessful).To(BeTrue())
			Expect(controller.sendWindow).To(Equal(protocol.ByteCount(15)))
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
		})
	})
})
