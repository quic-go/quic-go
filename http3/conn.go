package http3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

type Conn interface {
	AcceptStream(context.Context) (Stream, error)
	AcceptUniStream(context.Context) (ReadableStream, error)
	OpenStream() (Stream, error)
	OpenUniStream(StreamType) (WritableStream, error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// ReadDatagram() ([]byte, error)
	// WriteDatagram([]byte) error

	// DecodeHeaders(io.Reader) (http.Header, error)

	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// This will block until the peer’s settings have been received.
	PeerSettings() (Settings, error)

	CloseWithError(quic.ApplicationErrorCode, string) error
}

type connection struct {
	quic.EarlySession

	settings Settings

	peerSettingsRead chan struct{} // Closed when peer settings are read
	peerSettings     Settings
	peerSettingsErr  error

	incomingUniStreams chan ReadableStream

	peerStreamsMutex sync.Mutex
	peerStreams      [4]ReadableStream

	isServer bool
}

// Open establishes a new HTTP/3 connection on an existing QUIC session.
// If settings is nil, it will use a set of reasonable defaults.
func Open(s quic.EarlySession, settings Settings) (Conn, error) {
	if settings == nil {
		settings = Settings{}
		// TODO: this blocks, so is this too clever?
		if s.ConnectionState().SupportsDatagrams {
			settings.EnableDatagrams()
		}
	}

	conn := &connection{
		EarlySession:       s,
		settings:           settings,
		peerSettingsRead:   make(chan struct{}),
		incomingUniStreams: make(chan ReadableStream, 1),
	}

	str, err := conn.OpenUniStream(StreamTypeControl)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	settings.writeFrame(w)

	conn.isServer = (str.StreamID() & 1) == 1

	go conn.handleIncomingUniStreams()

	return conn, nil
}

func (conn *connection) handleIncomingUniStreams() {
	for {
		str, err := conn.EarlySession.AcceptUniStream(context.Background())
		if err != nil {
			// TODO: close the connection
			return
		}
		go conn.handleIncomingUniStream(str)
	}
}

func (conn *connection) handleIncomingUniStream(qstr quic.ReceiveStream) {
	r := quicvarint.NewReader(qstr)
	t, err := quicvarint.Read(r)
	if err != nil {
		// TODO: close the stream
		qstr.CancelRead(quic.StreamErrorCode(errorGeneralProtocolError))
		return
	}
	str := &readableStream{
		ReceiveStream: qstr,
		conn:          conn,
		streamType:    StreamType(t),
	}
	if str.streamType < 4 {
		conn.peerStreamsMutex.Lock()
		if conn.peerStreams[str.streamType] != nil {
			conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("more than one %s opened", str.streamType))
			return
		}
		conn.peerStreams[str.streamType] = str
		conn.peerStreamsMutex.Unlock()
	}
	switch str.streamType {
	case StreamTypeControl:
		conn.handleControlStream(str)
	case StreamTypePush:
		if conn.isServer {
			conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("spurious %s from client", str.streamType))
			return
		}
		// TODO: handle push streams
	case StreamTypeQPACKEncoder, StreamTypeQPACKDecoder:
		// TODO: handle QPACK dynamic tables
	default:
		conn.incomingUniStreams <- str
	}
}

func (conn *connection) handleControlStream(str ReadableStream) {
	for {
		f, err := parseNextFrame(str)
		if err != nil {
			conn.peerSettingsErr = err
			conn.CloseWithError(quic.ApplicationErrorCode(errorFrameError), "")
			return
		}
		settings, ok := f.(Settings)
		if !ok {
			err := &quic.ApplicationError{
				ErrorCode: quic.ApplicationErrorCode(errorMissingSettings),
			}
			conn.CloseWithError(err.ErrorCode, err.ErrorMessage)
			conn.peerSettingsErr = err
			return
		}
		// If datagram support was enabled on this side and the peer side, we can expect it to have been
		// negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if settings.DatagramsEnabled() && !conn.ConnectionState().SupportsDatagrams {
			err := &quic.ApplicationError{
				ErrorCode:    quic.ApplicationErrorCode(errorSettingsError),
				ErrorMessage: "missing QUIC datagram support",
			}
			conn.CloseWithError(err.ErrorCode, err.ErrorMessage)
			conn.peerSettingsErr = err
			return
		}
		conn.peerSettings = settings
		close(conn.peerSettingsRead)
	}
}

func (conn *connection) AcceptStream(ctx context.Context) (Stream, error) {
	str, err := conn.EarlySession.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{
		Stream: str,
		conn:   conn,
	}, nil
}

func (conn *connection) AcceptUniStream(ctx context.Context) (ReadableStream, error) {
	select {
	case str := <-conn.incomingUniStreams:
		return str, nil
	case <-conn.Context().Done():
		return nil, errors.New("QUIC session closed")
	}
}

func (conn *connection) OpenStream() (Stream, error) {
	str, err := conn.EarlySession.OpenStream()
	if err != nil {
		return nil, err
	}
	return &stream{
		Stream: str,
		conn:   conn,
	}, nil
}

func (conn *connection) OpenUniStream(t StreamType) (WritableStream, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("invalid stream type: %s", t)
	}
	str, err := conn.EarlySession.OpenUniStream()
	if err != nil {
		return nil, err
	}
	// TODO: store a quicvarint.Writer in writableStream?
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(t))
	return &writableStream{
		SendStream: str,
		conn:       conn,
		streamType: t,
	}, nil
}

func (conn *connection) Settings() Settings {
	return conn.settings
}

func (conn *connection) PeerSettings() (Settings, error) {
	select {
	case <-conn.peerSettingsRead:
		return conn.peerSettings, conn.peerSettingsErr
	case <-conn.Context().Done():
		return nil, conn.Context().Err()
	}
}
