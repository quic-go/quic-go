package quic

import (
	"crypto/tls"
	"io"
	"net"

	"github.com/lucas-clemente/quic-go/protocol"
)

// Stream is the interface implemented by QUIC streams
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	StreamID() protocol.StreamID
	// Reset closes the stream with an error.
	Reset(error)
}

// A Session is a QUIC connection between two peers.
type Session interface {
	// AcceptStream returns the next stream opened by the peer, blocking until one is available.
	// Since stream 1 is reserved for the crypto stream, the first stream is either 2 (for a client) or 3 (for a server).
	AcceptStream() (Stream, error)
	// OpenStream opens a new QUIC stream, returning a special error when the peeer's concurrent stream limit is reached.
	// New streams always have the smallest possible stream ID.
	// TODO: Enable testing for the special error
	OpenStream() (Stream, error)
	// OpenStreamSync opens a new QUIC stream, blocking until the peer's concurrent stream limit allows a new stream to be opened.
	// It always picks the smallest possible stream ID.
	OpenStreamSync() (Stream, error)
	// LocalAddr returns the local address.
	LocalAddr() net.Addr
	// RemoteAddr returns the address of the peer.
	RemoteAddr() net.Addr
	// Close closes the connection. The error will be sent to the remote peer in a CONNECTION_CLOSE frame. An error value of nil is allowed and will cause a normal PeerGoingAway to be sent.
	Close(error) error
}

// ConnState is the status of the connection
type ConnState int

const (
	// ConnStateInitial is the initial state
	ConnStateInitial ConnState = iota
	// ConnStateVersionNegotiated means that version negotiation is complete
	ConnStateVersionNegotiated
	// ConnStateSecure means that the connection is encrypted
	ConnStateSecure
	// ConnStateForwardSecure means that the connection is forward secure
	ConnStateForwardSecure
)

// ConnStateCallback is called every time the connection moves to another connection state.
type ConnStateCallback func(Session, ConnState)

// Config contains all configuration data needed for a QUIC server or client.
// More config parameters (such as timeouts) will be added soon, see e.g. https://github.com/lucas-clemente/quic-go/issues/441.
type Config struct {
	TLSConfig *tls.Config
	// ConnStateCallback will be called when the QUIC version is successfully negotiated or when the encryption level changes.
	// If this field is not set, the Dial functions will return only when the connection is forward secure.
	// Callbacks have to be thread-safe, since they might be called in separate goroutines.
	ConnState ConnStateCallback
}

// A Listener for incoming QUIC connections
type Listener interface {
	// Close the server, sending CONNECTION_CLOSE frames to each peer.
	Close() error
	// Addr returns the local network addr that the server is listening on.
	Addr() net.Addr
	// Serve starts the main server loop, and blocks until a network error occurs or the server is closed.
	Serve() error
}
