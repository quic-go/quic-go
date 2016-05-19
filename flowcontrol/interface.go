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
