package quic

import (
	"crypto/tls"
	"net"

	"github.com/lucas-clemente/quic-go/utils"
)

// A Session is a QUIC Session
type Session interface {
	// get the next stream opened by the client
	// first stream returned has StreamID 3
	AcceptStream() (utils.Stream, error)
	// guaranteed to return the smallest unopened stream
	// special error for "too many streams, retry later"
	OpenStream() (utils.Stream, error)
	// blocks until a new stream can be opened, if the maximum number of stream is opened
	OpenStreamSync() (utils.Stream, error)
	RemoteAddr() net.Addr
	Close(error) error
}

// ConnState is the status of the connection
type ConnState int

const (
	// ConnStateVersionNegotiated means that version negotiation is complete
	ConnStateVersionNegotiated ConnState = iota
	// ConnStateSecure means that the connection is encrypted
	ConnStateSecure
	// ConnStateForwardSecure means that the connection is forward secure
	ConnStateForwardSecure
)

// ConnStateCallback is called every time the connection moves to another connection state
// the callback is called in a new go routine
type ConnStateCallback func(Session, ConnState)

// Config is the configuration for QUIC
type Config struct {
	TLSConfig *tls.Config
	// will be called in a separate goroutine
	ConnState ConnStateCallback
}

// A Listener listens for incoming QUIC connections
type Listener interface {
	Close() error
	Addr() net.Addr
	ListenAddr(addr string) error
	Listen(conn net.PacketConn) error
}
