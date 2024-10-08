package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A QoSPing is a PING frame
type QoSPing struct {
	SeqNo int
}

// this number is TBD
const qosPingFrameType = 0x3f5153300d0a1d0a

func (f *QoSPing) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, qosPingFrameType)
	b = quicvarint.Append(b, uint64(f.SeqNo))
	return b, nil
}

// Length of a written frame
func (f *QoSPing) Length(_ protocol.Version) protocol.ByteCount {
	return (protocol.ByteCount(quicvarint.Len(qosPingFrameType)) +
		protocol.ByteCount(quicvarint.Len(uint64(f.SeqNo))))
}
