package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection Flow controller", func() {
	var controller *connectionFlowController

	BeforeEach(func() {
		controller = &connectionFlowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}

		It("sets the send and receive windows", func() {
			receiveWindow := protocol.ByteCount(2000)
			maxReceiveWindow := protocol.ByteCount(3000)
			sendWindow := protocol.ByteCount(4000)

			fc := newConnectionFlowController(receiveWindow, maxReceiveWindow, sendWindow, rttStats)
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowIncrement).To(Equal(maxReceiveWindow))
			Expect(fc.sendWindow).To(Equal(sendWindow))
		})
	})

	Context("receive flow control", func() {
		It("increases the highestReceived by a given increment", func() {
			controller.highestReceived = 1337
			controller.IncrementHighestReceived(123)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337 + 123)))
		})
	})

	Context("setting the minimum increment", func() {
		var oldIncrement protocol.ByteCount
		var receiveWindow protocol.ByteCount = 10000
		var receiveWindowIncrement protocol.ByteCount = 600

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowIncrement = receiveWindowIncrement
			oldIncrement = controller.receiveWindowIncrement
			controller.maxReceiveWindowIncrement = 3000
		})

		// update the congestion such that it returns a given value for the smoothed RTT
		setRtt := func(t time.Duration) {
			controller.rttStats.UpdateRTT(t, 0, time.Now())
			Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
		}

		It("sets the minimum window increment", func() {
			controller.EnsureMinimumWindowIncrement(1000)
			Expect(controller.receiveWindowIncrement).To(Equal(protocol.ByteCount(1000)))
		})

		It("doesn't reduce the window increment", func() {
			controller.EnsureMinimumWindowIncrement(1)
			Expect(controller.receiveWindowIncrement).To(Equal(oldIncrement))
		})

		It("doens't increase the increment beyond the maxReceiveWindowIncrement", func() {
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
