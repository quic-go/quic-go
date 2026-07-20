package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type QXPingFrame struct {
	SequenceNumber uint64
	IsResponse     bool
}

func parseQXPingFrame(frameType FrameType, b []byte, _ protocol.Version) (*QXPingFrame, int, error) {
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &QXPingFrame{
		SequenceNumber: seq,
		IsResponse:     frameType == FrameTypeQXPingResponse,
	}, l, nil
}

func (f *QXPingFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	frameType := FrameTypeQXPingRequest
	if f.IsResponse {
		frameType = FrameTypeQXPingResponse
	}
	b = quicvarint.Append(b, uint64(frameType))
	return quicvarint.Append(b, f.SequenceNumber), nil
}

func (f *QXPingFrame) Length(_ protocol.Version) protocol.ByteCount {
	frameType := FrameTypeQXPingRequest
	if f.IsResponse {
		frameType = FrameTypeQXPingResponse
	}
	return protocol.ByteCount(quicvarint.Len(uint64(frameType)) + quicvarint.Len(f.SequenceNumber))
}
