package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A RstStreamFrame in QUIC
type RstStreamFrame struct {
	StreamID   protocol.StreamID
	ByteOffset uint64
	ErrorCode  uint32
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer) error {
	panic("RstStreamFrame: Write not yet implemented")
}

// MaxLength of a written frame
func (f *RstStreamFrame) MaxLength() int {
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

	frame.ByteOffset, err = utils.ReadUint64(r)
	if err != nil {
		return nil, err
	}

	frame.ErrorCode, err = utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}

	return frame, nil
}
