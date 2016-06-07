package frames

import (
	"bytes"
	"errors"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// A StreamFrame of QUIC
type StreamFrame struct {
	FinBit         bool
	StreamID       protocol.StreamID
	streamIDLen    protocol.ByteCount
	Offset         protocol.ByteCount
	Data           []byte
	DataLenPresent bool
}

var (
	errInvalidStreamIDLen = errors.New("StreamFrame: Invalid StreamID length")
	errInvalidOffsetLen   = errors.New("StreamFrame: Invalid offset length")
)

// ParseStreamFrame reads a stream frame. The type byte must not have been read yet.
func ParseStreamFrame(r *bytes.Reader) (*StreamFrame, error) {
	frame := &StreamFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.FinBit = typeByte&0x40 > 0
	frame.DataLenPresent = typeByte&0x20 > 0
	offsetLen := typeByte & 0x1C >> 2
	if offsetLen != 0 {
		offsetLen++
	}
	frame.streamIDLen = protocol.ByteCount(typeByte&0x03 + 1)

	sid, err := utils.ReadUintN(r, uint8(frame.streamIDLen))
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
	if frame.DataLenPresent {
		dataLen, err = utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	if dataLen > uint16(protocol.MaxPacketSize) {
		return nil, qerr.Error(qerr.InvalidStreamData, "data len too large")
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

	if !frame.FinBit && len(frame.Data) == 0 {
		return nil, qerr.EmptyStreamFrameNoFin
	}

	return frame, nil
}

// WriteStreamFrame writes a stream frame.
func (f *StreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x80) // sets the leftmost bit to 1

	if f.FinBit {
		typeByte ^= 0x40
	}

	if f.DataLenPresent {
		typeByte ^= 0x20
	}

	offsetLength := f.getOffsetLength()

	if offsetLength > 0 {
		typeByte ^= (uint8(offsetLength) - 1) << 2
	}

	if f.streamIDLen == 0 {
		f.calculateStreamIDLength()
	}
	typeByte ^= uint8(f.streamIDLen) - 1

	b.WriteByte(typeByte)

	switch f.streamIDLen {
	case 1:
		b.WriteByte(uint8(f.StreamID))
	case 2:
		utils.WriteUint16(b, uint16(f.StreamID))
	case 3:
		utils.WriteUint24(b, uint32(f.StreamID))
	case 4:
		utils.WriteUint32(b, uint32(f.StreamID))
	default:
		return errInvalidStreamIDLen
	}

	switch offsetLength {
	case 0:
	case 2:
		utils.WriteUint16(b, uint16(f.Offset))
	case 3:
		utils.WriteUint24(b, uint32(f.Offset))
	case 4:
		utils.WriteUint32(b, uint32(f.Offset))
	case 5:
		utils.WriteUint40(b, uint64(f.Offset))
	case 6:
		utils.WriteUint48(b, uint64(f.Offset))
	case 7:
		utils.WriteUint56(b, uint64(f.Offset))
	case 8:
		utils.WriteUint64(b, uint64(f.Offset))
	default:
		return errInvalidOffsetLen
	}

	if f.DataLenPresent {
		utils.WriteUint16(b, uint16(len(f.Data)))
	}

	b.Write(f.Data)

	return nil
}

func (f *StreamFrame) calculateStreamIDLength() {
	if f.StreamID < (1 << 8) {
		f.streamIDLen = 1
	} else if f.StreamID < (1 << 16) {
		f.streamIDLen = 2
	} else if f.StreamID < (1 << 24) {
		f.streamIDLen = 3
	} else {
		f.streamIDLen = 4
	}
}

func (f *StreamFrame) getOffsetLength() protocol.ByteCount {
	if f.Offset == 0 {
		return 0
	}
	if f.Offset < (1 << 16) {
		return 2
	}
	if f.Offset < (1 << 24) {
		return 3
	}
	if f.Offset < (1 << 32) {
		return 4
	}
	if f.Offset < (1 << 40) {
		return 5
	}
	if f.Offset < (1 << 48) {
		return 6
	}
	if f.Offset < (1 << 56) {
		return 7
	}
	return 8
}

// MinLength of a written frame
func (f *StreamFrame) MinLength() (protocol.ByteCount, error) {
	if f.streamIDLen == 0 {
		f.calculateStreamIDLength()
	}

	length := protocol.ByteCount(1) + f.streamIDLen + f.getOffsetLength()
	if f.DataLenPresent {
		length += 2
	}

	return length + 1, nil
}

// DataLen gives the length of data in bytes
func (f *StreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}
