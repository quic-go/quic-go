package flowcontrol

import (
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type streamFlowController struct {
	baseFlowController

	streamID                protocol.StreamID
	contributesToConnection bool // does the stream contribute to connection level flow control
}

// newStreamFlowController gets a new flow controller for a stream
func newStreamFlowController(
	streamID protocol.StreamID,
	contributesToConnection bool,
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	initialSendWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
) *streamFlowController {
	return &streamFlowController{
		streamID:                streamID,
		contributesToConnection: contributesToConnection,
		baseFlowController: baseFlowController{
			rttStats:                  rttStats,
			receiveWindow:             receiveWindow,
			receiveWindowIncrement:    receiveWindow,
			maxReceiveWindowIncrement: maxReceiveWindow,
			sendWindow:                initialSendWindow,
		},
	}
}

func (c *streamFlowController) ContributesToConnection() bool {
	return c.contributesToConnection
}

// UpdateHighestReceived updates the highestReceived value, if the byteOffset is higher
// it returns an ErrReceivedSmallerByteOffset if the received byteOffset is smaller than any byteOffset received before
// This error occurs every time StreamFrames get reordered and has to be ignored in that case
// It should only be treated as an error when resetting a stream
func (c *streamFlowController) UpdateHighestReceived(byteOffset protocol.ByteCount) (protocol.ByteCount, error) {
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

func (c *streamFlowController) MaybeUpdateWindow() (bool, protocol.ByteCount, protocol.ByteCount) {
	oldWindowSize := c.receiveWindowIncrement
	updated, newIncrement, newOffset := c.baseFlowController.MaybeUpdateWindow()
	// debug log, if the window size was actually increased
	if oldWindowSize < c.receiveWindowIncrement {
		utils.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowIncrement/(1<<10))
	}
	return updated, newIncrement, newOffset
}
