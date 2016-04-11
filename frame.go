package quic

import (
	"bytes"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/utils"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	FinBit   bool
	StreamID uint32
	Offset   uint64
	Data     []byte
}

// ParseStreamFrame reads a stream frame. The type byte must not have been read yet.
func ParseStreamFrame(r *bytes.Reader) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.FinBit = typeByte&0x40 > 0
	dataLenPresent := typeByte&0x20 > 0
	offsetLen := typeByte & 0x1C >> 2
	if offsetLen != 0 {
		offsetLen++
	}
	streamIDLen := typeByte&0x03 + 1

	sid, err := utils.ReadUintN(r, streamIDLen)
	if err != nil {
		return nil, err
	}
	frame.StreamID = uint32(sid)

	frame.Offset, err = utils.ReadUintN(r, offsetLen)
	if err != nil {
		return nil, err
	}

	var dataLen uint16
	if dataLenPresent {
		dataLen, err = utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	if dataLen == 0 {
		// The rest of the packet is data
		frame.Data, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
	} else {
		frame.Data = make([]byte, dataLen)
		if _, err := r.Read(frame.Data); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// WriteStreamFrame writes a stream frame.
func WriteStreamFrame(b *bytes.Buffer, f *StreamFrame) {
	typeByte := uint8(0x80)
	if f.FinBit {
		typeByte ^= 0x40
	}
	typeByte ^= 0x20
	if f.Offset != 0 {
		typeByte ^= 0x1c // TODO: Send shorter offset if possible
	}
	typeByte ^= 0x03 // TODO: Send shorter stream ID if possible
	b.WriteByte(typeByte)
	utils.WriteUint32(b, f.StreamID)
	if f.Offset != 0 {
		utils.WriteUint64(b, f.Offset)
	}
	utils.WriteUint16(b, uint16(len(f.Data)))
	b.Write(f.Data)
}

// An AckFrame in QUIC
type AckFrame struct {
	LargestObserved uint32 // TODO: change to uint64
}

// WriteAckFrame writes an ack frame.
func WriteAckFrame(b *bytes.Buffer, f *AckFrame) {
	typeByte := uint8(0x48)
	b.WriteByte(typeByte)
	b.WriteByte(0x00) // TODO: Entropy accumulation
	utils.WriteUint32(b, f.LargestObserved)
	utils.WriteUint16(b, 1) // TODO: Ack delay time
	b.WriteByte(0x01)       // Just one timestamp
	b.WriteByte(0x00)       // Largest observed
	utils.WriteUint32(b, 0) // First timestamp
}
