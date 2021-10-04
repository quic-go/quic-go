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
}

// DataStreamer lets the caller take over the underlying quic.Stream. After a
// call to DataStream, the server library will not do anything else with the
// stream.
//
// It becomes the caller’s responsibility to manage and close the stream.
//
// After a call to DataStream, the original Request.Body should not be used.
type DataStreamer interface {
	DataStream() quic.Stream
}

// A StreamHandler can accept or open new streams.
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

var _ StreamHandler = quic.Session(nil)