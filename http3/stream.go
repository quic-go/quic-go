package http3

import (
	"fmt"

	"github.com/lucas-clemente/quic-go"
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

// Valid returns true if t is a valid stream type ([0,4611686018427387903]).
func (t StreamType) Valid() bool {
	return t <= 4611686018427387903
}

// ReadableStream represents the receiver side of a unidirectional HTTP/3 stream.
type ReadableStream interface {
	quic.ReceiveStream
	Conn() Conn
	StreamType() StreamType
}

type readableStream struct {
	quic.ReceiveStream
	conn       Conn
	streamType StreamType
}

func (s *readableStream) Conn() Conn {
	return s.conn
}

func (s *readableStream) StreamType() StreamType {
	return s.streamType
}

// WritableStream represents the sender side of a unidirectional HTTP/3 stream.
type WritableStream interface {
	quic.SendStream
	Conn() Conn
	StreamType() StreamType
}

type writableStream struct {
	quic.SendStream
	conn       Conn
	streamType StreamType
}

func (s *writableStream) Conn() Conn {
	return s.conn
}

func (s *writableStream) StreamType() StreamType {
	return s.streamType
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

func (s *bidiStream) Conn() Conn {
	return s.conn
}
