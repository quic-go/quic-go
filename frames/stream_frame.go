package frames

import (
	"bytes"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	FinBit   bool
	StreamID protocol.StreamID
	Offset   protocol.ByteCount
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
	frame.StreamID = protocol.StreamID(sid)

	offset, err := utils.ReadUintN(r, offsetLen)
	if err != nil {
		return nil, err
	}
	frame.Offset = protocol.ByteCount(offset)

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
func (f *StreamFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, version protocol.VersionNumber) error {
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
	utils.WriteUint32(b, uint32(f.StreamID))
	if f.Offset != 0 {
		utils.WriteUint64(b, uint64(f.Offset))
	}
	utils.WriteUint16(b, uint16(len(f.Data)))
	b.Write(f.Data)
	return nil
}

// MinLength of a written frame
func (f *StreamFrame) MinLength() protocol.ByteCount {
	return 1 + 4 + 8 + 2 + 1
}

// MaybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(n), nil is returned and nothing is modified.
func (f *StreamFrame) MaybeSplitOffFrame(n protocol.ByteCount) *StreamFrame {
	if n >= f.MinLength()-1+protocol.ByteCount(len(f.Data)) {
		return nil
	}
	n -= f.MinLength() - 1

	defer func() {
		f.Data = f.Data[n:]
		f.Offset += n
	}()

	return &StreamFrame{
		FinBit:   false,
		StreamID: f.StreamID,
		Offset:   f.Offset,
		Data:     f.Data[:n],
	}
}
