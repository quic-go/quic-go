package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type connectionFlowController struct {
	baseFlowController
}

// newConnectionFlowController gets a new flow controller for the connection
func newConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	initialSendWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
) *connectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:                  rttStats,
			receiveWindow:             receiveWindow,
			receiveWindowIncrement:    receiveWindow,
			maxReceiveWindowIncrement: maxReceiveWindow,
			sendWindow:                initialSendWindow,
		},
	}
}

// EnsureMinimumWindowIncrement sets a minimum window increment
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowIncrement(inc protocol.ByteCount) {
	if inc > c.receiveWindowIncrement {
		c.receiveWindowIncrement = utils.MinByteCount(inc, c.maxReceiveWindowIncrement)
		c.lastWindowUpdateTime = time.Time{} // disables autotuning for the next window update
	}
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount) {
	c.highestReceived += increment
}

func (c *connectionFlowController) MaybeUpdateWindow() (bool, protocol.ByteCount, protocol.ByteCount) {
	oldWindowSize := c.receiveWindowIncrement
	updated, newIncrement, newOffset := c.baseFlowController.MaybeUpdateWindow()
	// debug log, if the window size was actually increased
	if oldWindowSize < c.receiveWindowIncrement {
		utils.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowIncrement/(1<<10))
	}
	return updated, newIncrement, newOffset
}
