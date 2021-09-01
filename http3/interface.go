package http3

import (
	"context"
	"io"
	"net"

	"github.com/lucas-clemente/quic-go"
	"github.com/marten-seemann/qpack"
)

// Conn is a base HTTP/3 connection.
// Callers should use either ServerConn or ClientConn.
type Conn interface {
	// Settings returns the HTTP/3 settings for this side of the connection.
	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// Returns nil if the peer’s settings have not been received.
	PeerSettings() (Settings, error)

	// PeerSettingsSync returns the peer’s HTTP/3 settings,
	// blocking until the peer’s settings have been received,
	// the underlying QUIC session is closed, or the context is canceled.
	PeerSettingsSync(context.Context) (Settings, error)

	// CloseWithError closes the connection with an error.
	// The error string will be sent to the peer.
	CloseWithError(quic.ApplicationErrorCode, string) error
}

// ServerConn is a server connection. It accepts and processes HTTP/3 request streams.
type ServerConn interface {
	Conn
	AcceptRequestStream(context.Context) (RequestStream, error)
}

// ClientConn is a client connection. It opens and processes HTTP/3 request streams.
type ClientConn interface {
	Conn
	OpenRequestStream(context.Context) (RequestStream, error)
}

// webTransportConn is an internal interface for implementing WebTransport.
type webTransportConn interface {
	acceptStream(context.Context, SessionID) (quic.Stream, error)
	acceptUniStream(context.Context, SessionID) (quic.ReceiveStream, error)
	openStream(SessionID) (quic.Stream, error)
	openStreamSync(context.Context, SessionID) (quic.Stream, error)
	openUniStream(SessionID) (quic.SendStream, error)
	openUniStreamSync(context.Context, SessionID) (quic.SendStream, error)
	readDatagram(context.Context, SessionID) ([]byte, error)
	writeDatagram(SessionID, []byte) error
}

// A RequestStream wraps a QUIC stream for processing HTTP/3 requests. It
// processes HEADERS and DATA frames, making these available to the caller via
// ReadHeaders and DataReader. It may also process other frame types or skip any
// unknown frame types. A caller can also bypass the framing methods and
// directly read from or write to the underlying quic.Stream.
type RequestStream interface {
	quic.Stream

	// LocalAddr returns the local address.
	LocalAddr() net.Addr

	// RemoteAddr returns the address of the peer.
	RemoteAddr() net.Addr

	// TODO: integrate QPACK encoding and decoding with dynamic tables.

	// ReadHeaders reads the next HEADERS frame, used for HTTP request and
	// response headers and trailers. An interim response (status 100-199)
	// must be followed by one or more additional HEADERS frames. If
	// ReadHeaders encounters a DATA frame or an otherwise unhandled frame,
	// it will return a FrameTypeError.
	ReadHeaders() ([]qpack.HeaderField, error)

	// WriteHeaders writes a single HEADERS frame, used for HTTP request and
	// response headers and trailers. It returns any errors that may occur,
	// including QPACK encoding or writes to the underlying quic.Stream.
	// WriteHeaders shoud not be called simultaneously with Write, ReadFrom,
	// or writes to the underlying quic.Stream.
	WriteHeaders([]qpack.HeaderField) error

	// DataReader returns an io.ReadCloser that reads DATA frames from the
	// underlying quic.Stream, used for reading an HTTP request or response
	// body. If Read encounters a HEADERS frame it will return a
	// FrameTypeError. If the write side of the stream closes, it will
	// return io.EOF. Closing DataReader will prevent further writes, but
	// will not close the stream.
	DataReader() io.ReadCloser

	// DataWriter returns an io.WriteCloser that writes DATA frames to the
	// underlying quic.Stream, used for writing an HTTP request or response
	// body. Write should not be called simultaneously with WriteHeaders.
	// Closing DataWriter will prevent further writes, but will not close
	// the stream.
	DataWriter() io.WriteCloser

	// WebTransport returns a WebTransport interface, if supported.
	WebTransport() (WebTransport, error)
}

// TODO: implement the DATAGRAM draft:
// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html
type DatagramRequestStream interface {
	RequestStream

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
}

// A DatagramContext is a datagram handler with a unique context ID.
// A DatagramContext with a context ID of -1 indicates "no context."
// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co.
type DatagramContext interface {
	DatagramHandler
	ContextID() int64
}

// A DatagramHandler can read and write datagrams.
type DatagramHandler interface {
	// ReadDatagram reads a single datagram.
	ReadDatagram(context.Context) ([]byte, error)

	// WriteDatagram writes a single datagram.
	WriteDatagram([]byte) error
}
