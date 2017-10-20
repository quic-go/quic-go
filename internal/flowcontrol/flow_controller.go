package flowcontrol

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type flowController struct {
	streamID                protocol.StreamID
	contributesToConnection bool // does the stream contribute to connection level flow control

	rttStats *congestion.RTTStats

	bytesSent  protocol.ByteCount
	sendWindow protocol.ByteCount

	lastWindowUpdateTime time.Time

	bytesRead                 protocol.ByteCount
	highestReceived           protocol.ByteCount
	receiveWindow             protocol.ByteCount
	receiveWindowIncrement    protocol.ByteCount
	maxReceiveWindowIncrement protocol.ByteCount
}

// ErrReceivedSmallerByteOffset occurs if the ByteOffset received is smaller than a ByteOffset that was set previously
var ErrReceivedSmallerByteOffset = errors.New("Received a smaller byte offset")

// newFlowController gets a new flow controller
func newFlowController(
	streamID protocol.StreamID,
	contributesToConnection bool,
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	initialSendWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
) *flowController {
	return &flowController{
		streamID:                  streamID,
		contributesToConnection:   contributesToConnection,
		rttStats:                  rttStats,
		receiveWindow:             receiveWindow,
		receiveWindowIncrement:    receiveWindow,
		maxReceiveWindowIncrement: maxReceiveWindow,
		sendWindow:                initialSendWindow,
	}
}

func (c *flowController) ContributesToConnection() bool {
	return c.contributesToConnection
}

func (c *flowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *flowController) UpdateSendWindow(newOffset protocol.ByteCount) bool {
	if newOffset > c.sendWindow {
		c.sendWindow = newOffset
		return true
	}
	return false
}

func (c *flowController) SendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

// UpdateHighestReceived updates the highestReceived value, if the byteOffset is higher
// Should **only** be used for the stream-level FlowController
// it returns an ErrReceivedSmallerByteOffset if the received byteOffset is smaller than any byteOffset received before
// This error occurs every time StreamFrames get reordered and has to be ignored in that case
// It should only be treated as an error when resetting a stream
func (c *flowController) UpdateHighestReceived(byteOffset protocol.ByteCount) (protocol.ByteCount, error) {
	if byteOffset == c.highestReceived {
		return 0, nil
	}
	if byteOffset > c.highestReceived {
		increment := byteOffset - c.highestReceived
		c.highestReceived = byteOffset
		return increment, nil
	}
	return 0, ErrReceivedSmallerByteOffset
}

// IncrementHighestReceived adds an increment to the highestReceived value
// Should **only** be used for the connection-level FlowController
func (c *flowController) IncrementHighestReceived(increment protocol.ByteCount) {
	c.highestReceived += increment
}

func (c *flowController) AddBytesRead(n protocol.ByteCount) {
	// pretend we sent a WindowUpdate when reading the first byte
	// this way auto-tuning of the window increment already works for the first WindowUpdate
	if c.bytesRead == 0 {
		c.lastWindowUpdateTime = time.Now()
	}
	c.bytesRead += n
}

// MaybeUpdateWindow updates the receive window, if necessary
// if the receive window increment is changed, the new value is returned, otherwise a 0
// the last return value is the new offset of the receive window
func (c *flowController) MaybeUpdateWindow() (bool, protocol.ByteCount /* new increment */, protocol.ByteCount /* new offset */) {
	diff := c.receiveWindow - c.bytesRead

	// Chromium implements the same threshold
	if diff < (c.receiveWindowIncrement / 2) {
		var newWindowIncrement protocol.ByteCount
		oldWindowIncrement := c.receiveWindowIncrement

		c.maybeAdjustWindowIncrement()
		if c.receiveWindowIncrement != oldWindowIncrement {
			newWindowIncrement = c.receiveWindowIncrement
		}

		c.lastWindowUpdateTime = time.Now()
		c.receiveWindow = c.bytesRead + c.receiveWindowIncrement
		return true, newWindowIncrement, c.receiveWindow
	}

	return false, 0, 0
}

// maybeAdjustWindowIncrement increases the receiveWindowIncrement if we're sending WindowUpdates too often
func (c *flowController) maybeAdjustWindowIncrement() {
	if c.lastWindowUpdateTime.IsZero() {
		return
	}

	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	timeSinceLastWindowUpdate := time.Since(c.lastWindowUpdateTime)

	// interval between the window updates is sufficiently large, no need to increase the increment
	if timeSinceLastWindowUpdate >= 2*rtt {
		return
	}

	oldWindowSize := c.receiveWindowIncrement
	c.receiveWindowIncrement = utils.MinByteCount(2*c.receiveWindowIncrement, c.maxReceiveWindowIncrement)

	// debug log, if the window size was actually increased
	if oldWindowSize < c.receiveWindowIncrement {
		newWindowSize := c.receiveWindowIncrement / (1 << 10)
		if c.streamID == 0 {
			utils.Debugf("Increasing receive flow control window for the connection to %d kB", newWindowSize)
		} else {
			utils.Debugf("Increasing receive flow control window increment for stream %d to %d kB", c.streamID, newWindowSize)
		}
	}
}

// EnsureMinimumWindowIncrement sets a minimum window increment
// it is intended be used for the connection-level flow controller
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *flowController) EnsureMinimumWindowIncrement(inc protocol.ByteCount) {
	if inc > c.receiveWindowIncrement {
		c.receiveWindowIncrement = utils.MinByteCount(inc, c.maxReceiveWindowIncrement)
		c.lastWindowUpdateTime = time.Time{} // disables autotuning for the next window update
	}
}

func (c *flowController) CheckFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
