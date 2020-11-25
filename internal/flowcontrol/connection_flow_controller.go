package flowcontrol

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type connectionFlowController struct {
	baseFlowController

	queueWindowUpdate func()
}

var _ ConnectionFlowController = &connectionFlowController{}

// NewConnectionFlowController gets a new flow controller for the connection
// It is created before we receive the peer's transport paramenters, thus it starts with a sendWindow of 0.
func NewConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	queueWindowUpdate func(),
	rttStats *utils.RTTStats,
	logger utils.Logger,
) ConnectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
			logger:               logger,
		},
		queueWindowUpdate: queueWindowUpdate,
	}
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	return c.baseFlowController.sendWindowSize()
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.highestReceived += increment
	if c.checkFlowControlViolation() {
		return qerr.NewError(qerr.FlowControlError, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow))
	}
	return nil
}

func (c *connectionFlowController) AddBytesRead(n protocol.ByteCount) {
	c.mutex.Lock()
	c.baseFlowController.addBytesRead(n)
	shouldQueueWindowUpdate := c.hasWindowUpdate()
	c.mutex.Unlock()
	if shouldQueueWindowUpdate {
		c.queueWindowUpdate()
	}
}

func (c *connectionFlowController) GetWindowUpdate() protocol.ByteCount {
	c.mutex.Lock()
	oldWindowSize := c.receiveWindowSize
	offset := c.getWindowUpdate()
	if oldWindowSize < c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowSize/(1<<10))
	}
	c.mutex.Unlock()
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount) {
	c.mutex.Lock()
	if inc > c.receiveWindowSize {
		c.logger.Debugf("Increasing receive flow control window for the connection to %d kB, in response to stream flow control window increase", c.receiveWindowSize/(1<<10))
		c.receiveWindowSize = utils.MinByteCount(inc, c.maxReceiveWindowSize)
		c.startNewAutoTuningEpoch(time.Now())
	}
	c.mutex.Unlock()
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *connectionFlowController) getWindowUpdate() protocol.ByteCount {
	if !c.hasWindowUpdate() {
		return 0
	}

	c.maybeAdjustWindowSize()
	c.receiveWindow = c.bytesRead + c.receiveWindowSize
	return c.receiveWindow
}

// maybeAdjustWindowSize increases the receiveWindowSize if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
func (c *connectionFlowController) maybeAdjustWindowSize() {
	bytesReadInEpoch := c.bytesRead - c.epochStartOffset
	// don't do anything if less than half the window has been consumed
	if bytesReadInEpoch <= c.receiveWindowSize/2 {
		return
	}
	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	fraction := float64(bytesReadInEpoch) / float64(c.receiveWindowSize)
	now := time.Now()
	if now.Sub(c.epochStartTime) < time.Duration(4*fraction*float64(rtt)) {
		// window is consumed too fast, try to increase the window size
		c.receiveWindowSize = utils.MinByteCount(2*c.receiveWindowSize, c.maxReceiveWindowSize)
	}
	c.startNewAutoTuningEpoch(now)
}
