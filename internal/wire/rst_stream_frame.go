package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A RstStreamFrame is a RST_STREAM frame in QUIC
type RstStreamFrame struct {
	StreamID   protocol.StreamID
	ErrorCode  protocol.ApplicationErrorCode
	ByteOffset protocol.ByteCount
}

// parseRstStreamFrame parses a RST_STREAM frame
func parseRstStreamFrame(r *bytes.Reader, version protocol.VersionNumber) (*RstStreamFrame, error) {
	if _, err := r.ReadByte(); err != nil { // read the TypeByte
		return nil, err
	}

	var streamID protocol.StreamID
	var errorCode uint16
	var byteOffset protocol.ByteCount
	sid, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	streamID = protocol.StreamID(sid)
	errorCode, err = utils.BigEndian.ReadUint16(r)
	if err != nil {
		return nil, err
	}
	bo, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	byteOffset = protocol.ByteCount(bo)

	return &RstStreamFrame{
		StreamID:   streamID,
		ErrorCode:  protocol.ApplicationErrorCode(errorCode),
		ByteOffset: byteOffset,
	}, nil
}

//Write writes a RST_STREAM frame
func (f *RstStreamFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x01)
	utils.WriteVarInt(b, uint64(f.StreamID))
	utils.BigEndian.WriteUint16(b, uint16(f.ErrorCode))
	utils.WriteVarInt(b, uint64(f.ByteOffset))
	return nil
}

// Length of a written frame
func (f *RstStreamFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return 1 + utils.VarIntLen(uint64(f.StreamID)) + 2 + utils.VarIntLen(uint64(f.ByteOffset))
}
