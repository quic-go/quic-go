package quic

import (
	"bytes"
	"io/ioutil"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	FinBit            bool
	DataLengthPresent bool
	OffsetLength      uint8
	StreamIDLength    uint8
	StreamID          uint32
	Offset            uint64
	DataLength        uint16
	Data              []byte
}

// ParseStreamFrame reads a stream frame. The type byte must not have been read yet.
func ParseStreamFrame(r *bytes.Reader) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.FinBit = typeByte&0x40 > 0
	frame.DataLengthPresent = typeByte&0x20 > 0
	frame.OffsetLength = typeByte & 0x1C >> 2
	if frame.OffsetLength != 0 {
		frame.OffsetLength++
	}
	frame.StreamIDLength = typeByte&0x03 + 1

	sid, err := readUint64(r, frame.StreamIDLength)
	if err != nil {
		return nil, err
	}
	frame.StreamID = uint32(sid)

	frame.Offset, err = readUint64(r, frame.OffsetLength)
	if err != nil {
		return nil, err
	}

	if frame.DataLengthPresent {
		var b1, b2 byte
		if b1, err = r.ReadByte(); err != nil {
			return nil, err
		}
		if b2, err = r.ReadByte(); err != nil {
			return nil, err
		}
		frame.DataLength = uint16(b1) + uint16(b2)<<8
	}

	if frame.DataLength == 0 {
		// The rest of the packet is data
		frame.Data, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
	} else {
		frame.Data = make([]byte, frame.DataLength)
		if _, err := r.Read(frame.Data); err != nil {
			return nil, err
		}
	}

	return frame, nil
}
