package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A RstStreamFrame in QUIC
type RstStreamFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
	ErrorCode  uint32
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, version protocol.VersionNumber) error {
	panic("RstStreamFrame: Write not yet implemented")
}

// MinLength of a written frame
func (f *RstStreamFrame) MinLength() (protocol.ByteCount, error) {
	panic("RstStreamFrame: Write not yet implemented")
}

// ParseRstStreamFrame parses a RST_STREAM frame
func ParseRstStreamFrame(r *bytes.Reader) (*RstStreamFrame, error) {
	frame := &RstStreamFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	sid, err := utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	frame.StreamID = protocol.StreamID(sid)

	byteOffset, err := utils.ReadUint64(r)
	if err != nil {
		return nil, err
	}
	frame.ByteOffset = protocol.ByteCount(byteOffset)

	frame.ErrorCode, err = utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}

	return frame, nil
}
