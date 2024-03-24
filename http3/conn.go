package http3

import (
	"context"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"
)

type connection struct {
	quicConn    quic.Connection
	perspective protocol.Perspective
	logger      utils.Logger

	enableDatagrams   bool
	uniStreamHijacker func(StreamType, quic.Connection, quic.ReceiveStream, error) (hijacked bool)

	settings         *Settings
	receivedSettings chan struct{}
}

func newConnection(
	quicConn quic.Connection,
	enableDatagrams bool,
	uniStreamHijacker func(StreamType, quic.Connection, quic.ReceiveStream, error) (hijacked bool),
	perspective protocol.Perspective,
	logger utils.Logger,
) *connection {
	return &connection{
		quicConn:          quicConn,
		perspective:       perspective,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		uniStreamHijacker: uniStreamHijacker,
		receivedSettings:  make(chan struct{}),
	}
}

func (c *connection) HandleUnidirectionalStreams() {
	var rcvdControlStream atomic.Bool

	for {
		str, err := c.quicConn.AcceptUniStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting unidirectional stream failed: %s", err)
			return
		}

		go func(str quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				if c.uniStreamHijacker != nil && c.uniStreamHijacker(StreamType(streamType), c.quicConn, str, err) {
					return
				}
				c.logger.Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream:
				// Our QPACK implementation doesn't use the dynamic table yet.
				// TODO: check that only one stream of each type is opened.
				return
			case streamTypePushStream:
				switch c.perspective {
				case protocol.PerspectiveClient:
					// we never increased the Push ID, so we don't expect any push streams
					c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
				case protocol.PerspectiveServer:
					// only the server can push
					c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
				}
				return
			default:
				if c.uniStreamHijacker != nil && c.uniStreamHijacker(StreamType(streamType), c.quicConn, str, nil) {
					return
				}
				str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
				return
			}
			// Only a single control stream is allowed.
			if isFirstControlStr := rcvdControlStream.CompareAndSwap(false, true); !isFirstControlStr {
				c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
				return
			}
			f, err := parseNextFrame(str, nil)
			if err != nil {
				c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
				return
			}
			sf, ok := f.(*settingsFrame)
			if !ok {
				c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
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
			if c.enableDatagrams && !c.quicConn.ConnectionState().SupportsDatagrams {
				c.quicConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			}
		}(str)
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
func (c *connection) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *connection) Settings() *Settings { return c.settings }
