package http3

import (
	"context"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"
)

type ServerConn interface {
	quic.Connection
	HandleRequestStream(quic.Stream)
	HandleUnidirectionalStream(receiveStream quic.ReceiveStream)
	// ReceivedSettings returns a channel that is closed once the client's SETTINGS frame was received.
	ReceivedSettings() <-chan struct{}
	// Settings returns the settings received on this connection.
	Settings() *Settings
}

type connection struct {
	quic.Connection

	perspective protocol.Perspective
	logger      utils.Logger

	enableDatagrams bool

	settings         *Settings
	receivedSettings chan struct{}

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
}

func newConnection(
	quicConn quic.Connection,
	enableDatagrams bool,
	perspective protocol.Perspective,
	logger utils.Logger,
) *connection {
	return &connection{
		Connection:       quicConn,
		perspective:      perspective,
		logger:           logger,
		enableDatagrams:  enableDatagrams,
		receivedSettings: make(chan struct{}),
	}
}

func (c *connection) HandleUnidirectionalStreams() {
	for {
		str, err := c.Connection.AcceptUniStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting unidirectional stream failed: %s", err)
			return
		}
		go c.handleUnidirectionalStream(str)
	}
}

func (c *connection) handleUnidirectionalStream(str quic.ReceiveStream) {
	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		c.logger.Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypePushStream:
		switch c.perspective {
		case protocol.PerspectiveClient:
			// we never increased the Push ID, so we don't expect any push streams
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		case protocol.PerspectiveServer:
			// only the server can push
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	f, err := parseNextFrame(str)
	if err != nil {
		c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagram:        sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	if c.receivedSettings != nil {
		close(c.receivedSettings)
	}
	if !sf.Datagram {
		return
	}
	// If datagram support was enabled on our side as well as on the server side,
	// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
	// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
	if c.enableDatagrams && !c.Connection.ConnectionState().SupportsDatagrams {
		c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
func (c *connection) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *connection) Settings() *Settings { return c.settings }

type serverConn struct {
	*connection
	handleRequestStream func(quic.Stream)
}

var _ ServerConn = &serverConn{}

func (c *serverConn) HandleRequestStream(str quic.Stream) {
	c.handleRequestStream(str)
}

func (c *serverConn) HandleUnidirectionalStream(str quic.ReceiveStream) {
	c.handleUnidirectionalStream(str)
}
