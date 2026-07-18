package quic

import (
	"fmt"
	"io"
	"slices"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"
)

func appendQMuxRecord(b, frames []byte, maxRecordSize protocol.ByteCount) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errNothingToPack
	}
	if protocol.ByteCount(len(frames)) > maxRecordSize {
		return nil, fmt.Errorf("qmux record size %d exceeds peer max_record_size %d", len(frames), maxRecordSize)
	}
	b = quicvarint.Append(b, uint64(len(frames)))
	return append(b, frames...), nil
}

func appendQMuxRecordPrefix(b []byte, maxRecordSize protocol.ByteCount) ([]byte, int, int) {
	recordStart := len(b)
	prefixLen := quicvarint.Len(uint64(maxRecordSize))
	return slices.Grow(b, prefixLen)[:recordStart+prefixLen], recordStart, prefixLen
}

func finishQMuxRecord(b []byte, recordStart int, maxRecordSize protocol.ByteCount) ([]byte, error) {
	prefixLen := quicvarint.Len(uint64(maxRecordSize))
	payloadStart := recordStart + prefixLen
	payloadLen := len(b) - payloadStart
	if payloadLen == 0 {
		return b[:recordStart], errNothingToPack
	}
	if protocol.ByteCount(payloadLen) > maxRecordSize {
		return nil, fmt.Errorf("qmux record size %d exceeds peer max_record_size %d", payloadLen, maxRecordSize)
	}
	quicvarint.AppendWithLen(b[recordStart:recordStart], uint64(payloadLen), prefixLen)
	return b, nil
}

func readQMuxRecord(r io.Reader, maxRecordSize protocol.ByteCount, b []byte) ([]byte, error) {
	if protocol.ByteCount(cap(b)) < maxRecordSize {
		return nil, fmt.Errorf("qmux read buffer capacity %d is smaller than max_record_size %d", cap(b), maxRecordSize)
	}
	qr := quicvarint.NewReader(r)
	size, err := quicvarint.Read(qr)
	if err != nil {
		return nil, err
	}
	// Section 5.2 of draft-ietf-quic-qmux: records exceeding the declared maximum MUST be
	// treated as a connection error of type FRAME_ENCODING_ERROR.
	if protocol.ByteCount(size) > maxRecordSize {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			ErrorMessage: fmt.Sprintf("qmux record size %d exceeds max_record_size %d", size, maxRecordSize),
		}
	}
	// Section 3.2: the Frames field contains one or more QUIC frames, so an empty record is malformed.
	if size == 0 {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			ErrorMessage: "qmux record must contain at least one frame",
		}
	}
	b = b[:int(size)]
	_, err = io.ReadFull(qr, b)
	return b, err
}
