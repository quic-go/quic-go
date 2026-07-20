package wire

import (
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

type QXTransportParametersFrame struct {
	TransportParameters []byte
}

func parseQXTransportParametersFrame(b []byte, _ protocol.Version) (*QXTransportParametersFrame, int, error) {
	length, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if uint64(len(b)) < length {
		return nil, 0, io.EOF
	}
	if length == 0 {
		return nil, 0, fmt.Errorf("transport parameters must not be empty")
	}
	params := make([]byte, int(length))
	copy(params, b[:length])
	return &QXTransportParametersFrame{TransportParameters: params}, l + int(length), nil
}

func (f *QXTransportParametersFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeQXTransportParametersFrame))
	b = quicvarint.Append(b, uint64(len(f.TransportParameters)))
	b = append(b, f.TransportParameters...)
	return b, nil
}

func (f *QXTransportParametersFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(
		quicvarint.Len(uint64(FrameTypeQXTransportParametersFrame)) +
			quicvarint.Len(uint64(len(f.TransportParameters))) +
			len(f.TransportParameters),
	)
}
