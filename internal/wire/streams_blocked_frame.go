package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A StreamsBlockedFrame is a STREAMS_BLOCKED frame
type StreamsBlockedFrame struct {
	Type        protocol.StreamType
	StreamLimit uint64
}

func parseStreamsBlockedFrame(r *bytes.Reader, _ protocol.VersionNumber) (*StreamsBlockedFrame, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	f := &StreamsBlockedFrame{}
	switch typeByte {
	case 0xa:
		f.Type = protocol.StreamTypeBidi
	case 0xb:
		f.Type = protocol.StreamTypeUni
	}
	streamLimit, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	f.StreamLimit = streamLimit

	return f, nil
}

func (f *StreamsBlockedFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	switch f.Type {
	case protocol.StreamTypeBidi:
		b.WriteByte(0xa)
	case protocol.StreamTypeUni:
		b.WriteByte(0xb)
	}
	utils.WriteVarInt(b, f.StreamLimit)
	return nil
}

// Length of a written frame
func (f *StreamsBlockedFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + utils.VarIntLen(f.StreamLimit)
}
