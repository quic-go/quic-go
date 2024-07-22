package wire

import (
	"errors"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A QoSTransportParameters is a PING frame
type QoSTransportParameters struct {
	Perspective protocol.Perspective
	Params      *TransportParameters
}

const qosTransportParametersFrameType = 0x3f5153300d0a0d0a

func (f *QoSTransportParameters) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, qosTransportParametersFrameType)
	paramsB := f.Params.MarshalQoS(f.Perspective)
	b = quicvarint.Append(b, uint64(len(paramsB)))
	b = append(b, paramsB...)
	return b, nil
}

func ReadQoSTransportParametersFrame(frame *QoSTransportParameters, rdr io.Reader, pers protocol.Perspective, _ protocol.Version) error {
	r := quicvarint.NewReader(rdr)
	fTyp, err := quicvarint.Read(r)
	if err != nil {
		return err
	}
	if fTyp != qosTransportParametersFrameType {
		return errors.New("invalid QoS transport parameters frame")
	}
	paramLen, err := quicvarint.Read(r)
	if err != nil {
		return err
	}
	if paramLen > 1024 {
		return errors.New("QoS transport parameters too long")
	}
	b := make([]byte, paramLen)
	io.ReadFull(r, b)
	t := TransportParameters{}
	err = t.Unmarshal(b, pers)
	if err != nil {
		return err
	}
	frame.Params = &t
	frame.Perspective = pers
	return nil
}

// Length of a written frame
func (f *QoSTransportParameters) Length(_ protocol.Version) protocol.ByteCount {
	params := f.Params.MarshalQoS(f.Perspective)
	return (protocol.ByteCount(quicvarint.Len(qosTransportParametersFrameType)) +
		protocol.ByteCount(quicvarint.Len(uint64(len(params)))) +
		protocol.ByteCount(len(params)))
}
