package http3

import (
	"fmt"

	"github.com/lucas-clemente/quic-go"
)

const (
	// A StreamTypeBidi is never represented on the wire as a varint.
	StreamTypeBidi StreamType = -1

	// https://www.ietf.org/archive/id/draft-ietf-quic-http-34.html#name-stream-types
	StreamTypeControl StreamType = 0x00
	StreamTypePush    StreamType = 0x01

	// https://www.ietf.org/archive/id/draft-ietf-quic-qpack-21.html#name-encoder-and-decoder-streams
	StreamTypeQPACKEncoder StreamType = 0x02
	StreamTypeQPACKDecoder StreamType = 0x03
)

// StreamType represents an HTTP/3 stream type.
type StreamType int64

// String implements the Stringer interface.
func (t StreamType) String() string {
	switch t {
	case StreamTypeBidi:
		return "bidirectional stream"
	case StreamTypeControl:
		return "Control Stream"
	case StreamTypePush:
		return "Push Stream"
	case StreamTypeQPACKEncoder:
		return "QPACK Encoder Stream"
	case StreamTypeQPACKDecoder:
		return "QPACK Decoder Stream"
	default:
		return fmt.Sprintf("0x%x", int64(t))
	}
}

// Valid returns true if t is a valid stream type ([0,4611686018427387903]).
// Note: StreamTypeBidi is "invalid".
func (t StreamType) Valid() bool {
	return t >= 0 && t <= 4611686018427387903
}

// A ReadableStream represents the receiver side of a unidirectional HTTP/3 stream.
type ReadableStream interface {
	Conn() Conn
	StreamType() StreamType
	quic.ReceiveStream
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

// A WritableStream represents the sender side of a unidirectional HTTP/3 stream.
type WritableStream interface {
	Conn() Conn
	StreamType() StreamType
	quic.SendStream
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

// A Stream represents a bidirectional HTTP/3 stream.
type Stream interface {
	ReadableStream
	WritableStream
	quic.Stream
}

type stream struct {
	quic.Stream
	conn Conn
}

func (s *stream) Conn() Conn {
	return s.conn
}

func (s *stream) StreamType() StreamType {
	return StreamTypeBidi
}
