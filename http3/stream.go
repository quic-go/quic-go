package http3

import (
	"fmt"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

const (
	// https://www.ietf.org/archive/id/draft-ietf-quic-http-34.html#name-stream-types
	StreamTypeControl StreamType = 0x00
	StreamTypePush    StreamType = 0x01

	// https://www.ietf.org/archive/id/draft-ietf-quic-qpack-21.html#name-encoder-and-decoder-streams
	StreamTypeQPACKEncoder StreamType = 0x02
	StreamTypeQPACKDecoder StreamType = 0x03
)

// StreamType represents an HTTP/3 stream type.
type StreamType uint64

// String implements the Stringer interface.
func (t StreamType) String() string {
	switch t {
	case StreamTypeControl:
		return "Control Stream"
	case StreamTypePush:
		return "Push Stream"
	case StreamTypeQPACKEncoder:
		return "QPACK Encoder Stream"
	case StreamTypeQPACKDecoder:
		return "QPACK Decoder Stream"
	default:
		return fmt.Sprintf("0x%x", uint64(t))
	}
}

// Valid returns true if t is a valid stream type ([0,2^62-1]).
func (t StreamType) Valid() bool {
	return t <= quicvarint.Max
}

// Stream represents a bidirectional HTTP/3 stream.
type Stream interface {
	quic.Stream
	Conn() Conn
}

type bidiStream struct {
	quic.Stream
	conn Conn
}

var _ quic.Stream = &bidiStream{}

func (s *bidiStream) Conn() Conn {
	return s.conn
}
