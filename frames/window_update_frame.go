package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A WindowUpdateFrame in QUIC
type WindowUpdateFrame struct {
	StreamID   protocol.StreamID
	ByteOffset protocol.ByteCount
}

//Write writes a RST_STREAM frame
func (f *WindowUpdateFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen) error {
	panic("WindowUpdateFrame: Write not yet implemented")
}

// MinLength of a written frame
func (f *WindowUpdateFrame) MinLength() int {
	panic("WindowUpdateFrame: Write not yet implemented")
}

// ParseWindowUpdateFrame parses a RST_STREAM frame
func ParseWindowUpdateFrame(r *bytes.Reader) (*WindowUpdateFrame, error) {
	frame := &WindowUpdateFrame{}

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

	return frame, nil
}
