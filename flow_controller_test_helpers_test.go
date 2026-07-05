package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

func newTestStreamFlowController(id protocol.StreamID) *streamFlowController {
	return newTestStreamFlowControllerWithSendWindow(id, 0)
}

func newTestStreamFlowControllerWithSendWindow(id protocol.StreamID, sendWindow protocol.ByteCount) *streamFlowController {
	return newTestStreamFlowControllerWithWindows(id, sendWindow, protocol.MaxByteCount, protocol.MaxByteCount)
}

func newTestStreamFlowControllerWithWindows(
	id protocol.StreamID,
	sendWindow protocol.ByteCount,
	streamReceiveWindow protocol.ByteCount,
	connReceiveWindow protocol.ByteCount,
) *streamFlowController {
	connFC := newConnectionFlowController(
		connReceiveWindow,
		protocol.MaxByteCount,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	connFC.UpdateSendWindow(protocol.MaxByteCount)
	return newStreamFlowController(
		id,
		connFC,
		streamReceiveWindow,
		protocol.MaxByteCount,
		sendWindow,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
}
