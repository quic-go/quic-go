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

	// update the congestion such that it returns a given value for the smoothed RTT
	setRtt := func(t time.Duration) {
		controller.rttStats.UpdateRTT(t, 0, time.Now())
		Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
	}

	BeforeEach(func() {
		controller = &connectionFlowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}

		It("sets the send and receive windows", func() {
			receiveWindow := protocol.ByteCount(2000)
			maxReceiveWindow := protocol.ByteCount(3000)

			fc := NewConnectionFlowController(receiveWindow, maxReceiveWindow, rttStats).(*connectionFlowController)
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowSize).To(Equal(maxReceiveWindow))
		})
	})

	Context("receive flow control", func() {
		It("increases the highestReceived by a given window size", func() {
			controller.highestReceived = 1337
			controller.IncrementHighestReceived(123)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337 + 123)))
		})

		Context("getting window updates", func() {
			BeforeEach(func() {
				controller.receiveWindow = 100
				controller.receiveWindowSize = 60
				controller.maxReceiveWindowSize = 1000
			})

			It("gets a window update", func() {
				controller.AddBytesRead(80)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(protocol.ByteCount(80 + 60)))
			})

			It("autotunes the window", func() {
				controller.AddBytesRead(80)
				rtt := 20 * time.Millisecond
				setRtt(rtt)
				controller.lastWindowUpdateTime = time.Now().Add(-4*protocol.WindowUpdateThreshold*rtt + time.Millisecond)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(protocol.ByteCount(80 + 2*60)))
			})
		})
	})

	Context("setting the minimum window size", func() {
		var (
			oldWindowSize     protocol.ByteCount
			receiveWindow     protocol.ByteCount = 10000
			receiveWindowSize protocol.ByteCount = 600
		)

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowSize = receiveWindowSize
			oldWindowSize = controller.receiveWindowSize
			controller.maxReceiveWindowSize = 3000
		})

		It("sets the minimum window window size", func() {
			controller.EnsureMinimumWindowSize(1000)
			Expect(controller.receiveWindowSize).To(Equal(protocol.ByteCount(1000)))
		})

		It("doesn't reduce the window window size", func() {
			controller.EnsureMinimumWindowSize(1)
			Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
		})

		It("doens't increase the window size beyond the maxReceiveWindowSize", func() {
			max := controller.maxReceiveWindowSize
			controller.EnsureMinimumWindowSize(2 * max)
			Expect(controller.receiveWindowSize).To(Equal(max))
		})

		It("doesn't auto-tune the window after the window size was increased", func() {
			setRtt(20 * time.Millisecond)
			controller.bytesRead = 9900 // receive window is 10000
			controller.lastWindowUpdateTime = time.Now().Add(-20 * time.Millisecond)
			controller.EnsureMinimumWindowSize(912)
			offset := controller.getWindowUpdate()
			Expect(controller.receiveWindowSize).To(Equal(protocol.ByteCount(912))) // no auto-tuning
			Expect(offset).To(Equal(protocol.ByteCount(9900 + 912)))
		})
	})
})
