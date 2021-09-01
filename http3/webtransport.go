package http3

import (
	"context"
	"io"

	"github.com/lucas-clemente/quic-go"
)

// A WebTransport SessionID is the same as the request stream ID.
type SessionID = quic.StreamID

// WebTransport is an interface to accept or open streams and read and write datagrams.
type WebTransport interface {
	SessionID() SessionID
	StreamHandler
	DatagramHandler
	io.Closer
}

// A StreamHandler can accept or open new QUIC streams.
type StreamHandler interface {
	// AcceptStream accepts the next incoming bidirectional stream.
	AcceptStream(context.Context) (quic.Stream, error)

	// AcceptUniStream accepts the next incoming unidirectional stream.
	AcceptUniStream(context.Context) (quic.ReceiveStream, error)

	// OpenStream opens a new stream.
	OpenStream() (quic.Stream, error)

	// OpenStreamSync opens a new stream, blocking until it is possible to open the stream.
	OpenStreamSync(context.Context) (quic.Stream, error)

	// OpenUniStream opens a new unidirectional stream.
	OpenUniStream() (quic.SendStream, error)

	// OpenUniStreamSync opens a new unidirectional stream.
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
}
