package http3

import (
	"context"
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

	isServer bool

	peerSettingsMutex sync.RWMutex
	peerSettings      Settings
	peerSettingsErr   error

	peerStreamsMutex sync.Mutex
	peerStreams      [4]ReadableStream
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
		EarlySession: s,
		settings:     settings,
	}

	str, err := conn.OpenUniStream(StreamTypeControl)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	settings.writeFrame(w)

	conn.isServer = (str.StreamID() & 1) == 1

	return conn, nil
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
	conn.peerStreamsMutex.Lock()
	defer conn.peerStreamsMutex.Unlock()
	for {
		qstr, err := conn.EarlySession.AcceptUniStream(ctx)
		if err != nil {
			return nil, err
		}
		r := quicvarint.NewReader(qstr)
		t, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		str := &readableStream{
			ReceiveStream: qstr,
			conn:          conn,
			streamType:    StreamType(t),
		}
		switch str.streamType {
		case StreamTypePush:
			if conn.isServer {
				err := &quic.ApplicationError{
					ErrorCode:    quic.ApplicationErrorCode(errorStreamCreationError),
					ErrorMessage: fmt.Sprintf("spurious %s from client", str.streamType),
				}
				conn.CloseWithError(err.ErrorCode, err.ErrorMessage)
				return nil, err
			}
			fallthrough
		case StreamTypeControl, StreamTypeQPACKEncoder, StreamTypeQPACKDecoder:
			if conn.peerStreams[str.streamType] != nil {
				// TODO: close with errorStreamCreationError
				return nil, fmt.Errorf("second %s opened", str.streamType)
			}
			conn.peerStreams[str.streamType] = str
			// TODO: start stream goroutine
		default:
			return str, nil
		}
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
	conn.peerSettingsMutex.RLock()
	defer conn.peerSettingsMutex.RUnlock()
	return conn.peerSettings, conn.peerSettingsErr
}
