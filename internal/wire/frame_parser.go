package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// ParseNextFrame parses the next frame
// It skips PADDING frames.
func ParseNextFrame(r *bytes.Reader, hdr *Header, v protocol.VersionNumber) (Frame, error) {
	if r.Len() == 0 {
		return nil, nil
	}
	typeByte, _ := r.ReadByte()
	if typeByte == 0x0 { // PADDING frame
		return ParseNextFrame(r, hdr, v)
	}
	r.UnreadByte()

	if !v.UsesIETFFrameFormat() {
		return parseGQUICFrame(r, typeByte, hdr, v)
	}
	return parseIETFFrame(r, typeByte, v)
}

func parseIETFFrame(r *bytes.Reader, typeByte byte, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0xf8 == 0x10 {
		frame, err = ParseStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	}
	// TODO: implement all IETF QUIC frame types
	switch typeByte {
	case 0x1:
		frame, err = ParseRstStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = ParseConnectionCloseFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x4:
		frame, err = ParseMaxDataFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = ParseMaxStreamDataFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x6:
		frame, err = ParseMaxStreamIDFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0x7:
		frame, err = ParsePingFrame(r, v)
	case 0x8:
		frame, err = ParseBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x9:
		frame, err = ParseStreamBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0xa:
		frame, err = ParseStreamIDBlockedFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xc:
		frame, err = ParseStopSendingFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidFrameData, err.Error())
		}
	case 0xe:
		frame, err = ParseAckFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}

func parseGQUICFrame(r *bytes.Reader, typeByte byte, hdr *Header, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0x80 == 0x80 {
		frame, err = ParseStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStreamData, err.Error())
		}
		return frame, err
	} else if typeByte&0xc0 == 0x40 {
		frame, err = ParseAckFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidAckData, err.Error())
		}
		return frame, err
	}
	switch typeByte {
	case 0x1:
		frame, err = ParseRstStreamFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
		}
	case 0x2:
		frame, err = ParseConnectionCloseFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
		}
	case 0x3:
		frame, err = ParseGoawayFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidGoawayData, err.Error())
		}
	case 0x4:
		frame, err = ParseWindowUpdateFrame(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
		}
	case 0x5:
		frame, err = ParseBlockedFrameLegacy(r, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidBlockedData, err.Error())
		}
	case 0x6:
		frame, err = ParseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen, v)
		if err != nil {
			err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
		}
	case 0x7:
		frame, err = ParsePingFrame(r, v)
	default:
		err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
	}
	return frame, err
}
