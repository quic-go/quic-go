package http3

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
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
	AcceptRequestStream(context.Context) (Stream, error)
}

// ClientConn is a client connection. It opens and processes HTTP/3 request sessions.
type ClientConn interface {
	Conn
	OpenRequestStream(context.Context) (Stream, error)
}
type connection struct {
	session quic.EarlySession

	settings Settings

	peerSettingsDone chan struct{} // Closed when peer settings are read
	peerSettings     Settings
	peerSettingsErr  error

	peerStreamsMutex sync.Mutex
	peerStreams      [4]ReadableStream
}

var (
	_ Conn       = &connection{}
	_ ClientConn = &connection{}
	_ ServerConn = &connection{}
)

// Accept establishes a new HTTP/3 server connection from an existing QUIC session.
// If settings is nil, it will use a set of reasonable defaults.
func Accept(s quic.EarlySession, settings Settings) (ServerConn, error) {
	if s.Perspective() != quic.PerspectiveServer {
		return nil, errors.New("Accept called on client session")
	}
	return newConn(s, settings)
}

// Open establishes a new HTTP/3 client connection from an existing QUIC session.
// If settings is nil, it will use a set of reasonable defaults.
func Open(s quic.EarlySession, settings Settings) (ClientConn, error) {
	if s.Perspective() != quic.PerspectiveClient {
		return nil, errors.New("Open called on server session")
	}
	return newConn(s, settings)
}

func newConn(s quic.EarlySession, settings Settings) (*connection, error) {
	if settings == nil {
		settings = Settings{}
		// TODO: this blocks, so is this too clever?
		if s.ConnectionState().SupportsDatagrams {
			settings.EnableDatagrams()
		}
	}

	conn := &connection{
		session:          s,
		settings:         settings,
		peerSettingsDone: make(chan struct{}),
	}

	str, err := conn.OpenUniStream(StreamTypeControl)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	conn.settings.writeFrame(w)

	go conn.handleIncomingUniStreams()

	return conn, nil
}

func (conn *connection) handleIncomingUniStreams() {
	for {
		str, err := conn.session.AcceptUniStream(context.Background())
		if err != nil {
			// TODO: log the error
			return
		}
		go conn.handleIncomingUniStream(str)
	}
}

func (conn *connection) handleIncomingUniStream(qstr quic.ReceiveStream) {
	r := quicvarint.NewReader(qstr)
	t, err := quicvarint.Read(r)
	if err != nil {
		qstr.CancelRead(quic.StreamErrorCode(errorGeneralProtocolError))
		return
	}
	str := &readableStream{
		ReceiveStream: qstr,
		conn:          conn,
		streamType:    StreamType(t),
	}

	// Store control, QPACK, and push streams on conn
	if str.streamType < 4 {
		conn.peerStreamsMutex.Lock()
		if conn.peerStreams[str.streamType] != nil {
			conn.session.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("more than one %s opened", str.streamType))
			return
		}
		conn.peerStreams[str.streamType] = str
		conn.peerStreamsMutex.Unlock()
	}

	switch str.streamType {
	case StreamTypeControl:
		conn.handleControlStream(str)
	case StreamTypePush:
		if conn.session.Perspective() == quic.PerspectiveServer {
			conn.session.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("spurious %s from client", str.streamType))
			return
		}
		// TODO: handle push streams
		// We never increased the Push ID, so we don't expect any push streams.
		conn.session.CloseWithError(quic.ApplicationErrorCode(errorIDError), "MAX_PUSH_ID = 0")
		return
	case StreamTypeQPACKEncoder, StreamTypeQPACKDecoder:
		// TODO: handle QPACK dynamic tables
	default:
		// TODO: demultiplex incoming uni streams
		str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
		// conn.incomingUniStreams <- str
	}
}

func (conn *connection) handleControlStream(str ReadableStream) {
	f, err := parseNextFrame(str)
	if err != nil {
		conn.session.CloseWithError(quic.ApplicationErrorCode(errorFrameError), "")
		return
	}
	settings, ok := f.(Settings)
	if !ok {
		err := &quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(errorMissingSettings),
		}
		conn.session.CloseWithError(err.ErrorCode, err.ErrorMessage)
		conn.peerSettingsErr = err
		return
	}
	// If datagram support was enabled on this side and the peer side, we can expect it to have been
	// negotiated both on the transport and on the HTTP/3 layer.
	// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
	if settings.DatagramsEnabled() && !conn.session.ConnectionState().SupportsDatagrams {
		err := &quic.ApplicationError{
			ErrorCode:    quic.ApplicationErrorCode(errorSettingsError),
			ErrorMessage: "missing QUIC Datagram support",
		}
		conn.session.CloseWithError(err.ErrorCode, err.ErrorMessage)
		conn.peerSettingsErr = err
		return
	}
	conn.peerSettings = settings
	close(conn.peerSettingsDone)

	// TODO: loop reading the reset of the frames from the control stream
}

// TODO: demultiplex incoming bidi streams
func (conn *connection) AcceptRequestStream(ctx context.Context) (Stream, error) {
	if conn.session.Perspective() != quic.PerspectiveServer {
		return nil, errors.New("server method called on client connection")
	}
	str, err := conn.session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &bidiStream{
		Stream: str,
		conn:   conn,
	}, nil
}

// TODO: multiplex outgoing bidi streams?
func (conn *connection) OpenRequestStream(ctx context.Context) (Stream, error) {
	if conn.session.Perspective() != quic.PerspectiveClient {
		return nil, errors.New("client method called on server connection")
	}
	str, err := conn.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &bidiStream{
		Stream: str,
		conn:   conn,
	}, nil
}

func (conn *connection) OpenUniStream(t StreamType) (WritableStream, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("invalid stream type: %s", t)
	}
	str, err := conn.session.OpenUniStream()
	if err != nil {
		return nil, err
	}
	return conn.openWritableStream(str, t)

}

func (conn *connection) OpenUniStreamSync(ctx context.Context, t StreamType) (WritableStream, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("invalid stream type: %s", t)
	}
	str, err := conn.session.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return conn.openWritableStream(str, t)
}

func (conn *connection) openWritableStream(str quic.SendStream, t StreamType) (WritableStream, error) {
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
	case <-conn.peerSettingsDone:
		return conn.peerSettings, conn.peerSettingsErr
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}
