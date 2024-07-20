package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A QoSTransportParameters is a PING frame
type QoSTransportParameters struct {
	Perspective protocol.Perspective
	Params      TransportParameters
}

const qosTransportParametersFrameType = 0x3f5153300d0a0d0a

func (f *QoSTransportParameters) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, qosTransportParametersFrameType)
	paramsB := f.Params.Marshal(f.Perspective)
	b = quicvarint.Append(b, uint64(len(paramsB)))
	b = append(b, paramsB...)
	return b, nil
}

// Length of a written frame
func (f *QoSTransportParameters) Length(_ protocol.Version) protocol.ByteCount {
	params := f.Params.Marshal(f.Perspective)
	return (protocol.ByteCount(quicvarint.Len(qosTransportParametersFrameType)) +
		protocol.ByteCount(quicvarint.Len(uint64(len(params)))) +
		protocol.ByteCount(len(params)))
}
