package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A BlockedFrame in QUIC
type BlockedFrame struct {
	StreamID protocol.StreamID
}

//Write writes a RST_STREAM frame
func (f *BlockedFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, version protocol.VersionNumber) error {
	b.WriteByte(0x05)

	if f.StreamID == 0 {
		panic("Writing of connection level BlockedFrames not yet implemented.")
	}

	utils.WriteUint32(b, uint32(f.StreamID))

	return nil
}

// MinLength of a written frame
func (f *BlockedFrame) MinLength() protocol.ByteCount {
	return 1 + 4
}

// ParseBlockedFrame parses a BLOCKED frame
func ParseBlockedFrame(r *bytes.Reader) (*BlockedFrame, error) {
	frame := &BlockedFrame{}

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

	return frame, nil
}
