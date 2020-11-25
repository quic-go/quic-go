package flowcontrol

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type baseFlowController struct {
	// for sending data
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	// for receiving data
	//nolint:structcheck // The mutex is used both by the stream and the connection flow controller
	mutex                sync.Mutex
	bytesRead            protocol.ByteCount
	highestReceived      protocol.ByteCount
	receiveWindow        protocol.ByteCount
	receiveWindowSize    protocol.ByteCount
	maxReceiveWindowSize protocol.ByteCount

	epochStartTime   time.Time
	epochStartOffset protocol.ByteCount
	rttStats         *utils.RTTStats

	logger utils.Logger
}

// IsNewlyBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *baseFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.sendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
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

// needs to be called with locked mutex
func (c *baseFlowController) addBytesRead(n protocol.ByteCount) {
	// pretend we sent a WindowUpdate when reading the first byte
	// this way auto-tuning of the window size already works for the first WindowUpdate
	if c.bytesRead == 0 {
		c.startNewAutoTuningEpoch(time.Now())
	}
	c.bytesRead += n
}

func (c *baseFlowController) hasWindowUpdate() bool {
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	return bytesRemaining <= protocol.ByteCount(float64(c.receiveWindowSize)*(1-protocol.WindowUpdateThreshold))
}

func (c *baseFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}

func (c *baseFlowController) startNewAutoTuningEpoch(now time.Time) {
	c.epochStartTime = now
	c.epochStartOffset = c.bytesRead
}
