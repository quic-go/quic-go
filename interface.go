package quic

import (
	"net"

	"github.com/lucas-clemente/quic-go/protocol"
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
	// TODO: implement this
	// blocks until a new stream can be opened, if the maximum number of stream is opened
	// OpenStreamSync() (utils.Stream, error)
	RemoteAddr() net.Addr
	Close(error) error
	// TODO: remove this
	GetOrOpenStream(protocol.StreamID) (utils.Stream, error)
}
