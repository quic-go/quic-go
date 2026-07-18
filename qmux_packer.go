package quic

import (
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

type qmuxPacker struct {
	state  *qmuxState
	framer *framer
}

var _ packer = &qmuxPacker{}

func (p *qmuxPacker) PackCoalescedPacket(bool, protocol.ByteCount, monotime.Time, protocol.Version) (*coalescedPacket, error) {
	return nil, nil
}

func (p *qmuxPacker) PackAckOnlyPacket(protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	return shortHeaderPacket{}, nil, errNothingToPack
}

func (p *qmuxPacker) AppendPacket(buf *packetBuffer, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, error) {
	maxRecordSize := min(p.state.maxRecordSize, maxSize)
	var frames []ackhandler.Frame
	var streamFrames []ackhandler.StreamFrame
	startLen := buf.Len()
	var recordStart, prefixLen int
	buf.Data, recordStart, prefixLen = appendQMuxRecordPrefix(buf.Data, maxRecordSize)

	if seq, ok := p.state.popPingResponse(); ok {
		f := &wire.QXPingFrame{SequenceNumber: seq, IsResponse: true}
		frames = append(frames, ackhandler.Frame{Frame: f})
		var err error
		buf.Data, err = f.Append(buf.Data, v)
		if err != nil {
			return shortHeaderPacket{}, err
		}
	}

	if p.framer.HasData() {
		payloadLen := protocol.ByteCount(len(buf.Data) - recordStart - prefixLen)
		remaining := maxRecordSize - payloadLen
		startLen := len(frames)
		frames, streamFrames, _ = p.framer.Append(frames, streamFrames, remaining, now, v)
		for _, f := range frames[startLen:] {
			var err error
			buf.Data, err = f.Frame.Append(buf.Data, v)
			if err != nil {
				return shortHeaderPacket{}, err
			}
		}
		for _, sf := range streamFrames {
			var err error
			buf.Data, err = sf.Frame.Append(buf.Data, v)
			if err != nil {
				return shortHeaderPacket{}, err
			}
		}
	}

	data, err := finishQMuxRecord(buf.Data, recordStart, maxRecordSize)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	buf.Data = data
	return shortHeaderPacket{
		PacketNumber:      0,
		PacketNumberLen:   protocol.PacketNumberLen1,
		Frames:            frames,
		StreamFrames:      streamFrames,
		Length:            buf.Len() - startLen,
		DestConnID:        protocol.ConnectionID{},
		KeyPhase:          protocol.KeyPhaseZero,
		IsPathProbePacket: false,
	}, nil
}

func (p *qmuxPacker) PackPTOProbePacket(protocol.EncryptionLevel, protocol.ByteCount, bool, monotime.Time, protocol.Version) (*coalescedPacket, error) {
	return nil, nil
}

func (p *qmuxPacker) PackConnectionClose(e *qerr.TransportError, _ protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {
	return p.packClose(&wire.ConnectionCloseFrame{
		ErrorCode:    uint64(e.ErrorCode),
		FrameType:    e.FrameType,
		ReasonPhrase: e.ErrorMessage,
	}, v)
}

func (p *qmuxPacker) PackApplicationClose(e *qerr.ApplicationError, _ protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {
	return p.packClose(&wire.ConnectionCloseFrame{
		IsApplicationError: true,
		ErrorCode:          uint64(e.ErrorCode),
		ReasonPhrase:       e.ErrorMessage,
	}, v)
}

func (p *qmuxPacker) packClose(f *wire.ConnectionCloseFrame, v protocol.Version) (*coalescedPacket, error) {
	payload, err := f.Append(nil, v)
	if err != nil {
		return nil, err
	}
	buf := getPacketBuffer()
	buf.Data, err = appendQMuxRecord(buf.Data, payload, p.state.maxRecordSize)
	if err != nil {
		buf.Release()
		return nil, err
	}
	return &coalescedPacket{
		buffer: buf,
		shortHdrPacket: &shortHeaderPacket{
			PacketNumber:    0,
			PacketNumberLen: protocol.PacketNumberLen1,
			Frames:          []ackhandler.Frame{{Frame: f}},
			Length:          buf.Len(),
		},
	}, nil
}

func (p *qmuxPacker) PackPathProbePacket(protocol.ConnectionID, []ackhandler.Frame, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	return shortHeaderPacket{}, nil, errNothingToPack
}

func (p *qmuxPacker) PackMTUProbePacket(ackhandler.Frame, protocol.ByteCount, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	return shortHeaderPacket{}, nil, errNothingToPack
}

func (p *qmuxPacker) SetToken([]byte) {}
