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

// Conn is an HTTP/3 connection.
// The interface is modeled after quic.Session.
type Conn interface {
	AcceptStream(context.Context) (Stream, error)
	AcceptUniStream(context.Context) (ReadableStream, error)
	OpenStream() (Stream, error)
	OpenStreamSync(context.Context) (Stream, error)
	OpenUniStream(StreamType) (WritableStream, error)
	OpenUniStreamSync(context.Context, StreamType) (WritableStream, error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	Perspective() quic.Perspective

	// ReadDatagram() ([]byte, error)
	// WriteDatagram([]byte) error

	// DecodeHeaders(io.Reader) (http.Header, error)

	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// This will block until the peer’s settings have been received.
	PeerSettings() (Settings, error)

	// Blocks until the handshake completes (or fails).
	// Data sent before completion of the handshake is encrypted with 1-RTT keys.
	// Note that the client's identity hasn't been verified yet.
	HandshakeComplete() context.Context

	// ConnectionState returns basic details about the QUIC connection.
	// It blocks until the handshake completes.
	// Warning: This API should not be considered stable and might change soon.
	ConnectionState() quic.ConnectionState

	CloseWithError(quic.ApplicationErrorCode, string) error
}

type connection struct {
	session quic.EarlySession

	settings Settings

	peerSettingsDone chan struct{} // Closed when peer settings are read
	peerSettings     Settings
	peerSettingsErr  error

	incomingUniStreams chan ReadableStream

	peerStreamsMutex sync.Mutex
	peerStreams      [4]ReadableStream
}

var _ Conn = &connection{}

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
		session:            s,
		settings:           settings,
		peerSettingsDone:   make(chan struct{}),
		incomingUniStreams: make(chan ReadableStream, 1),
	}

	str, err := conn.OpenUniStream(StreamTypeControl)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	settings.writeFrame(w)

	go conn.handleIncomingUniStreams()

	return conn, nil
}

func (conn *connection) HandshakeComplete() context.Context {
	return conn.session.HandshakeComplete()
}

func (conn *connection) ConnectionState() quic.ConnectionState {
	return conn.session.ConnectionState()
}

func (conn *connection) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return conn.session.CloseWithError(code, msg)
}

func (conn *connection) handleIncomingUniStreams() {
	for {
		str, err := conn.session.AcceptUniStream(context.Background())
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

	// Store control, QPACK, and push streams on conn
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
		if conn.Perspective() == quic.PerspectiveServer {
			conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("spurious %s from client", str.streamType))
			return
		}
		// TODO: handle push streams
		// We never increased the Push ID, so we don't expect any push streams.
		conn.CloseWithError(quic.ApplicationErrorCode(errorIDError), "MAX_PUSH_ID = 0")
		return
	case StreamTypeQPACKEncoder, StreamTypeQPACKDecoder:
		// TODO: handle QPACK dynamic tables
	default:
		conn.incomingUniStreams <- str
	}
}

func (conn *connection) handleControlStream(str ReadableStream) {
	f, err := parseNextFrame(str)
	if err != nil {
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
	if settings.DatagramsEnabled() && !conn.session.ConnectionState().SupportsDatagrams {
		err := &quic.ApplicationError{
			ErrorCode:    quic.ApplicationErrorCode(errorSettingsError),
			ErrorMessage: "missing QUIC Datagram support",
		}
		conn.CloseWithError(err.ErrorCode, err.ErrorMessage)
		conn.peerSettingsErr = err
		return
	}
	conn.peerSettings = settings
	close(conn.peerSettingsDone)

	// TODO: loop reading the reset of the frames from the control stream
}

func (conn *connection) AcceptStream(ctx context.Context) (Stream, error) {
	str, err := conn.session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return conn.openBidiStream(str)
}

func (conn *connection) AcceptUniStream(ctx context.Context) (ReadableStream, error) {
	select {
	case str := <-conn.incomingUniStreams:
		if str == nil {
			return nil, errors.New("BUG: closed incomingUniStreams channel")
		}
		return str, nil
	case <-conn.session.Context().Done():
		return nil, errors.New("QUIC session closed")
	}
}

// OpenStream opens a new bidirectional stream.
func (conn *connection) OpenStream() (Stream, error) {
	str, err := conn.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return conn.openBidiStream(str)
}

// OpenStreamSync opens a new bidirectional stream.
// It blocks until a stream can be opened.
func (conn *connection) OpenStreamSync(ctx context.Context) (Stream, error) {
	str, err := conn.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return conn.openBidiStream(str)
}

func (conn *connection) openBidiStream(str quic.Stream) (Stream, error) {
	// TODO: store a quicvarint.Writer in bidiStream?
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

func (conn *connection) LocalAddr() net.Addr {
	return conn.session.LocalAddr()
}

func (conn *connection) RemoteAddr() net.Addr {
	return conn.session.RemoteAddr()
}

func (conn *connection) Perspective() quic.Perspective {
	return conn.session.Perspective()
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
