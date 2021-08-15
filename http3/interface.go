package http3

import (
	"context"
	"io"

	"github.com/lucas-clemente/quic-go"
)

// Conn is a base HTTP/3 connection.
// Callers should use either ServerConn or ClientConn.
type Conn interface {
	// Settings returns the HTTP/3 settings for this side of the connection.
	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// This will block until the peer’s settings have been received.
	PeerSettings() (Settings, error)
}

// ServerConn is a server connection. It accepts and processes HTTP/3 request sessions.
type ServerConn interface {
	Conn
	AcceptRequestStream(context.Context) (RequestStream, error)
}

// ClientConn is a client connection. It opens and processes HTTP/3 request sessions.
type ClientConn interface {
	Conn
	OpenRequestStream(context.Context) (RequestStream, error)
}

// A RequestStream is a QUIC stream for processing HTTP/3 requests.
// Instances of RequestStream may optionally vend datagram or WebTransport handlers.
type RequestStream interface {
	quic.Stream

	// AcceptDatagramContext receives a datagram context from a peer.
	// This allows a server, for instance, to start receiving datagrams on a
	// client-initiated datagram context.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-datagram-contexts.
	AcceptDatagramContext(context.Context) (DatagramContext, error)

	// RegisterDatagramContext allocates a new datagram context for the request.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_conte.
	RegisterDatagramContext() (DatagramContext, error)

	// DatagramNoContext signals to the server that datagrams associated with this request
	// will not use datagram context IDs.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// Multiple calls will return the same DatagramContext.
	// The returned DatagramContext will have a context ID of -1.
	// Calling DatagramContext after DatagramNoContext will return an error.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co.
	DatagramNoContext() (DatagramContext, error)

	// WebTransport returns a WebTransport interface for this session, if supported.
	WebTransport() (WebTransport, error)
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

// A DatagramHandler can read and write datagrams.
type DatagramHandler interface {
	// ReadDatagram reads a single datagram.
	ReadDatagram() ([]byte, error)

	// WriteDatagram writes a single datagram.
	WriteDatagram([]byte) error
}

// A DatagramContext is a datagram handler with a unique context ID.
// A DatagramContext with a context ID of -1 indicates "no context."
// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co.
type DatagramContext interface {
	ContextID() int64
	DatagramHandler
}

// A WebTransport can accept or open WebTransport streams and read and write WebTransport datagrams.
type WebTransport interface {
	StreamHandler
	DatagramHandler
	io.Closer
}
