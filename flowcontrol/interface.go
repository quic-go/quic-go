package flowcontrol

import "github.com/lucas-clemente/quic-go/protocol"

// A FlowControlManager manages the flow control
type FlowControlManager interface {
	NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool)
	// methods needed for receiving data
	UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error
	AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error
	MaybeTriggerStreamWindowUpdate(streamID protocol.StreamID) (bool, protocol.ByteCount, error)
	MaybeTriggerConnectionWindowUpdate() (bool, protocol.ByteCount)
	// methods needed for sending data
	AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error
	SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error)
	RemainingConnectionWindowSize() protocol.ByteCount
	UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error)
	StreamContributesToConnectionFlowControl(streamID protocol.StreamID) (bool, error)
}
