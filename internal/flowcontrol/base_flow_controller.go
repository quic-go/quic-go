package flowcontrol

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type baseFlowController struct {
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

func (c *baseFlowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *baseFlowController) UpdateSendWindow(newOffset protocol.ByteCount) bool {
	if newOffset > c.sendWindow {
		c.sendWindow = newOffset
		return true
	}
	return false
}

func (c *baseFlowController) SendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

func (c *baseFlowController) AddBytesRead(n protocol.ByteCount) {
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
func (c *baseFlowController) MaybeUpdateWindow() (bool, protocol.ByteCount /* new increment */, protocol.ByteCount /* new offset */) {
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
func (c *baseFlowController) maybeAdjustWindowIncrement() {
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
	c.receiveWindowIncrement = utils.MinByteCount(2*c.receiveWindowIncrement, c.maxReceiveWindowIncrement)
}

func (c *baseFlowController) CheckFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
