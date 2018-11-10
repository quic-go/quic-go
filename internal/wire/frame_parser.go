package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
)

// ParseNextFrame parses the next frame
// It skips PADDING frames.
func ParseNextFrame(r *bytes.Reader, v protocol.VersionNumber) (Frame, error) {
	for r.Len() != 0 {
		typeByte, _ := r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		return parseFrame(r, typeByte, v)
	}
	return nil, nil
}

func parseFrame(r *bytes.Reader, typeByte byte, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0xf8 == 0x10 {
		frame, err = parseStreamFrame(r, v)
		if err != nil {
			return nil, qerr.Error(qerr.InvalidFrameData, err.Error())
		}
		return frame, nil
	}
	// TODO: implement all IETF QUIC frame types
	switch typeByte {
	case 0x1:
		frame, err = parseResetStreamFrame(r, v)
	case 0x2, 0x3:
		frame, err = parseConnectionCloseFrame(r, v)
	case 0x4:
		frame, err = parseMaxDataFrame(r, v)
	case 0x5:
		frame, err = parseMaxStreamDataFrame(r, v)
	case 0x7:
		frame, err = parsePingFrame(r, v)
	case 0x8:
		frame, err = parseDataBlockedFrame(r, v)
	case 0x9:
		frame, err = parseStreamDataBlockedFrame(r, v)
	case 0xa, 0xb:
		frame, err = parseStreamsBlockedFrame(r, v)
	case 0xc:
		frame, err = parseStopSendingFrame(r, v)
	case 0xe:
		frame, err = parsePathChallengeFrame(r, v)
	case 0xf:
		frame, err = parsePathResponseFrame(r, v)
	case 0x1a, 0x1b:
		frame, err = parseAckFrame(r, v)
	case 0x1c, 0x1d:
		frame, err = parseMaxStreamsFrame(r, v)
	case 0x18:
		frame, err = parseCryptoFrame(r, v)
	default:
		err = fmt.Errorf("unknown type byte 0x%x", typeByte)
	}
	if err != nil {
		return nil, qerr.Error(qerr.InvalidFrameData, err.Error())
	}
	return frame, nil
}
