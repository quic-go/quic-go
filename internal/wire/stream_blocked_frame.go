package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A StreamBlockedFrame in QUIC
type StreamBlockedFrame struct {
	StreamID protocol.StreamID
}

// ParseStreamBlockedFrame parses a STREAM_BLOCKED frame
func ParseStreamBlockedFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamBlockedFrame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}
	sid, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	return &StreamBlockedFrame{StreamID: protocol.StreamID(sid)}, nil
}

// Write writes a STREAM_BLOCKED frame
func (f *StreamBlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	if !version.UsesIETFFrameFormat() {
		return (&blockedFrameLegacy{StreamID: f.StreamID}).Write(b, version)
	}
	b.WriteByte(0x09)
	utils.WriteVarInt(b, uint64(f.StreamID))
	return nil
}

// MinLength of a written frame
func (f *StreamBlockedFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesIETFFrameFormat() {
		return 1 + 4, nil
	}
	return 1 + utils.VarIntLen(uint64(f.StreamID)), nil
}
