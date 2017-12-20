package flowcontrol

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type baseFlowController struct {
	// for sending data
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	// for receiving data
	mutex                     sync.RWMutex
	bytesRead                 protocol.ByteCount
	highestReceived           protocol.ByteCount
	receiveWindow             protocol.ByteCount
	receiveWindowIncrement    protocol.ByteCount
	maxReceiveWindowIncrement protocol.ByteCount
	lastWindowUpdateTime      time.Time
	rttStats                  *congestion.RTTStats
}

func (c *baseFlowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *baseFlowController) UpdateSendWindow(offset protocol.ByteCount) {
	if offset > c.sendWindow {
		c.sendWindow = offset
	}
}

func (c *baseFlowController) sendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

func (c *baseFlowController) AddBytesRead(n protocol.ByteCount) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// pretend we sent a WindowUpdate when reading the first byte
	// this way auto-tuning of the window increment already works for the first WindowUpdate
	if c.bytesRead == 0 {
		c.lastWindowUpdateTime = time.Now()
	}
	c.bytesRead += n
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *baseFlowController) getWindowUpdate() protocol.ByteCount {
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	if bytesRemaining >= protocol.ByteCount((float64(c.receiveWindowIncrement) * float64((1 - protocol.WindowUpdateThreshold)))) {
		return 0
	}

	c.maybeAdjustWindowIncrement()
	c.receiveWindow = c.bytesRead + c.receiveWindowIncrement
	c.lastWindowUpdateTime = time.Now()
	return c.receiveWindow
}

// IsBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *baseFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.sendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

// maybeAdjustWindowIncrement increases the receiveWindowIncrement if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1F2YfdDXKpy20WVKJueEf4abn_LVZHhMUMS5gX6Pgjl4/edit#heading=h.hcm2y5x4qmqt.
func (c *baseFlowController) maybeAdjustWindowIncrement() {
	if c.lastWindowUpdateTime.IsZero() {
		return
	}

	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	timeSinceLastWindowUpdate := time.Since(c.lastWindowUpdateTime)
	// interval between the updates is sufficiently large, no need to increase the increment
	if timeSinceLastWindowUpdate >= 4*protocol.WindowUpdateThreshold*rtt {
		return
	}
	c.receiveWindowIncrement = utils.MinByteCount(2*c.receiveWindowIncrement, c.maxReceiveWindowIncrement)
}

func (c *baseFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
