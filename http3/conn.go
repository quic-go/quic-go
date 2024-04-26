package http3

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// Connection is an HTTP/3 connection.
// It has all methods from the quic.Connection expect for AcceptStream, AcceptUniStream,
// SendDatagram and ReceiveDatagram.
type Connection interface {
	OpenStream() (quic.Stream, error)
	OpenStreamSync(context.Context) (quic.Stream, error)
	OpenUniStream() (quic.SendStream, error)
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(quic.ApplicationErrorCode, string) error
	Context() context.Context
	ConnectionState() quic.ConnectionState

	// ReceivedSettings returns a channel that is closed once the client's SETTINGS frame was received.
	ReceivedSettings() <-chan struct{}
	// Settings returns the settings received on this connection.
	Settings() *Settings
}

type connection struct {
	quic.Connection

	perspective protocol.Perspective
	logger      *slog.Logger

	enableDatagrams   bool
	uniStreamHijacker func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)

	settings         *Settings
	receivedSettings chan struct{}
}

func newConnection(
	quicConn quic.Connection,
	enableDatagrams bool,
	uniStreamHijacker func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool),
	perspective protocol.Perspective,
	logger *slog.Logger,
) *connection {
	return &connection{
		Connection:        quicConn,
		perspective:       perspective,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		uniStreamHijacker: uniStreamHijacker,
		receivedSettings:  make(chan struct{}),
	}
}

func (c *connection) HandleUnidirectionalStreams() {
	var (
		rcvdControlStr      atomic.Bool
		rcvdQPACKEncoderStr atomic.Bool
		rcvdQPACKDecoderStr atomic.Bool
	)

	for {
		str, err := c.Connection.AcceptUniStream(context.Background())
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("accepting unidirectional stream failed", "error", err)
			}
			return
		}

		go func(str quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				id := c.Connection.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				if c.uniStreamHijacker != nil && c.uniStreamHijacker(StreamType(streamType), id, str, err) {
					return
				}
				if c.logger != nil {
					c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
				}
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream:
				if isFirst := rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
					c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
				}
				// Our QPACK implementation doesn't use the dynamic table yet.
				return
			case streamTypeQPACKDecoderStream:
				if isFirst := rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
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
				if c.uniStreamHijacker != nil {
					if c.uniStreamHijacker(
						StreamType(streamType),
						c.Connection.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID),
						str,
						nil,
					) {
						return
					}
				}
				str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
				return
			}
			// Only a single control stream is allowed.
			if isFirstControlStr := rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
				c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
				return
			}
			f, err := parseNextFrame(str, nil)
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
		}(str)
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
func (c *connection) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *connection) Settings() *Settings { return c.settings }
