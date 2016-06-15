package flowcontrol

import "github.com/lucas-clemente/quic-go/protocol"

// A FlowController handles the flow control
type FlowController interface {
	AddBytesSent(n protocol.ByteCount)
	UpdateSendWindow(newOffset protocol.ByteCount) bool
	SendWindowSize() protocol.ByteCount
	UpdateHighestReceived(byteOffset protocol.ByteCount) protocol.ByteCount
	IncrementHighestReceived(increment protocol.ByteCount)
	AddBytesRead(n protocol.ByteCount)
	MaybeTriggerBlocked() bool
	MaybeTriggerWindowUpdate() (bool, protocol.ByteCount)
	CheckFlowControlViolation() bool
	GetHighestReceived() protocol.ByteCount
}

// A FlowControlManager manages the flow control
type FlowControlManager interface {
	NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool)
	UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error
	AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error
	MaybeTriggerStreamWindowUpdate(streamID protocol.StreamID) (bool, protocol.ByteCount, error)
	MaybeTriggerConnectionWindowUpdate() (bool, protocol.ByteCount)
}
