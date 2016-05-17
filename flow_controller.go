package quic

import (
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type flowController struct {
	streamID protocol.StreamID

	bytesSent                protocol.ByteCount
	sendFlowControlWindow    protocol.ByteCount
	lastBlockedSentForOffset protocol.ByteCount

	bytesRead                         protocol.ByteCount
	receiveWindowUpdateThreshold      protocol.ByteCount
	receiveFlowControlWindow          protocol.ByteCount
	receiveFlowControlWindowIncrement protocol.ByteCount
}

func newFlowController(connectionParametersManager *handshake.ConnectionParametersManager) *flowController {
	return &flowController{
		sendFlowControlWindow:             connectionParametersManager.GetSendStreamFlowControlWindow(),
		receiveFlowControlWindow:          connectionParametersManager.GetReceiveStreamFlowControlWindow(),
		receiveWindowUpdateThreshold:      protocol.WindowUpdateThreshold,
		receiveFlowControlWindowIncrement: protocol.ReceiveStreamFlowControlWindowIncrement,
	}
}

func (c *flowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *flowController) UpdateSendWindow(newOffset protocol.ByteCount) bool {
	if newOffset > c.sendFlowControlWindow {
		c.sendFlowControlWindow = newOffset
		return true
	}
	return false
}

func (c *flowController) SendWindowSize() protocol.ByteCount {
	if c.bytesSent > c.sendFlowControlWindow { // should never happen, but make sure we don't do an underflow here
		return 0
	}
	return c.sendFlowControlWindow - c.bytesSent
}

func (c *flowController) AddBytesRead(n protocol.ByteCount) {
	c.bytesRead += n
}

// MaybeTriggerBlocked determines if it is necessary to send a Blocked for this stream
// it makes sure that only one Blocked is sent for each offset
func (c *flowController) MaybeTriggerBlocked() bool {
	if c.SendWindowSize() != 0 {
		return false
	}

	if c.lastBlockedSentForOffset == c.sendFlowControlWindow {
		return false
	}

	c.lastBlockedSentForOffset = c.sendFlowControlWindow
	return true
}

// MaybeTriggerWindowUpdate determines if it is necessary to send a WindowUpdate
// if so, it returns true and the offset of the window
func (c *flowController) MaybeTriggerWindowUpdate() (bool, protocol.ByteCount) {
	diff := c.receiveFlowControlWindow - c.bytesRead
	if diff < c.receiveWindowUpdateThreshold {
		c.receiveFlowControlWindow += c.receiveFlowControlWindowIncrement
		return true, c.bytesRead + c.receiveFlowControlWindowIncrement
	}
	return false, 0
}

func (c *flowController) CheckFlowControlViolation(highestByte protocol.ByteCount) bool {
	if highestByte > c.receiveFlowControlWindow {
		return true
	}
	return false
}
