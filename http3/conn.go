package http3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

const maxBufferedStreams = 8

// Conn is a base HTTP/3 connection.
// Callers should use either ServerConn or ClientConn.
type Conn interface {
	// Settings returns the HTTP/3 settings for this side of the connection.
	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// This will block until the peer’s settings have been received.
	PeerSettings() (Settings, error)

	// WebTransport returns a WebTransport session for a request stream.
	// The stream must be a request stream.
	WebTransport(quic.Stream) (WebTransport, error)
}

// ServerConn is a server connection. It accepts and processes HTTP/3 request streams.
type ServerConn interface {
	Conn
	AcceptRequestStream(context.Context) (RequestStream, error)
}

// ClientConn is a client connection. It opens and processes HTTP/3 request streams.
type ClientConn interface {
	Conn
	OpenRequestStream(context.Context) (RequestStream, error)
}

type connection struct {
	session quic.EarlySession

	settings Settings

	peerSettingsDone chan struct{} // Closed when peer settings are read
	peerSettings     Settings
	peerSettingsErr  error

	peerStreams [4]quic.ReceiveStream

	incomingStreamsOnce    sync.Once
	incomingStreamsErr     error
	incomingRequestStreams chan *requestStream

	// TODO: clean up buffers for closed streams
	incomingStreamsMutex sync.Mutex
	incomingStreams      map[quic.StreamID]chan quic.Stream // Lazily constructed

	// TODO: clean up buffers for closed streams
	incomingUniStreamsMutex sync.Mutex
	incomingUniStreams      map[quic.StreamID]chan quic.ReceiveStream // Lazily constructed

	// TODO: buffer incoming datagrams

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
		session:                s,
		settings:               settings,
		peerSettingsDone:       make(chan struct{}),
		incomingRequestStreams: make(chan *requestStream, maxBufferedStreams),
	}

	str, err := conn.session.OpenUniStream()
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(StreamTypeControl))
	conn.settings.writeFrame(w)

	go conn.handleIncomingUniStreams()

	return conn, nil
}

func (conn *connection) AcceptRequestStream(ctx context.Context) (RequestStream, error) {
	if conn.session.Perspective() != quic.PerspectiveServer {
		return nil, errors.New("server method called on client connection")
	}
	conn.incomingStreamsOnce.Do(func() {
		go conn.handleIncomingStreams()
	})
	select {
	case str := <-conn.incomingRequestStreams:
		if str == nil {
			// incomingRequestStreams was closed
			return nil, conn.incomingStreamsErr
		}
		return str, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}

func (conn *connection) OpenRequestStream(ctx context.Context) (RequestStream, error) {
	if conn.session.Perspective() != quic.PerspectiveClient {
		return nil, errors.New("client method called on server connection")
	}
	str, err := conn.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	conn.incomingStreamsOnce.Do(func() {
		go conn.handleIncomingStreams()
	})
	return newRequestStream(conn, str, str), nil
}

func (conn *connection) handleIncomingStreams() {
	for {
		str, err := conn.session.AcceptStream(context.Background())
		if err != nil {
			conn.incomingStreamsErr = err
			close(conn.incomingRequestStreams)
			// TODO: log the error
			return
		}
		conn.handleIncomingStream(str)
	}
}

func (conn *connection) handleIncomingStream(str quic.Stream) {
	r := bufio.NewReader(str)
	b, _ := r.Peek(16)
	br := bytes.NewReader(b)

	t, err := quicvarint.Read(br)
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(errorRequestIncomplete))
		return
	}

	switch FrameType(t) {
	case FrameTypeHeaders:
		conn.incomingRequestStreams <- newRequestStream(conn, str, r)
	case FrameTypeWebTransportStream:
		id, err := quicvarint.Read(br)
		if err != nil {
			str.CancelWrite(quic.StreamErrorCode(errorFrameError))
			return
		}
		select {
		case conn.incomingStreamChan(quic.StreamID(id)) <- str:
		default:
			str.CancelWrite(quic.StreamErrorCode(errorWebTransportBufferedStreamRejected))
			return
		}
	default:
		conn.session.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "expected first frame to be a HEADERS frame")
		return
	}
}

func (conn *connection) handleIncomingUniStreams() {
	for {
		str, err := conn.session.AcceptUniStream(context.Background())
		if err != nil {
			// TODO: log the error
			return
		}
		conn.handleIncomingUniStream(str)
	}
}

func (conn *connection) handleIncomingUniStream(str quic.ReceiveStream) {
	r := quicvarint.NewReader(str)
	t, err := quicvarint.Read(r)
	if err != nil {
		str.CancelRead(quic.StreamErrorCode(errorGeneralProtocolError))
		return
	}
	streamType := StreamType(t)

	// Store control, QPACK, and push streams on conn
	if streamType < 4 {
		if conn.peerStreams[streamType] != nil {
			conn.session.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("more than one %s opened", streamType))
			return
		}
		conn.peerStreams[streamType] = str
	}

	switch streamType {
	case StreamTypeControl:
		go conn.handleControlStream(str)
	case StreamTypePush:
		if conn.session.Perspective() == quic.PerspectiveServer {
			conn.session.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("spurious %s from client", streamType))
			return
		}
		// TODO: handle push streams
		// We never increased the Push ID, so we don't expect any push streams.
		conn.session.CloseWithError(quic.ApplicationErrorCode(errorIDError), "MAX_PUSH_ID = 0")
		return
	case StreamTypeQPACKEncoder, StreamTypeQPACKDecoder:
		// TODO: handle QPACK dynamic tables
	case StreamTypeWebTransportStream:
		id, err := quicvarint.Read(r)
		if err != nil {
			// TODO: log this error
			str.CancelRead(quic.StreamErrorCode(errorGeneralProtocolError))
			return
		}
		select {
		case conn.incomingUniStreamChan(quic.StreamID(id)) <- str:
		default:
			str.CancelRead(quic.StreamErrorCode(errorWebTransportBufferedStreamRejected))
			return
		}
	default:
		str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
	}
}

func (conn *connection) handleControlStream(str quic.ReceiveStream) {
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

func (conn *connection) incomingStreamChan(id quic.StreamID) chan quic.Stream {
	conn.incomingStreamsMutex.Lock()
	defer conn.incomingStreamsMutex.Unlock()
	if conn.incomingStreams[id] == nil {
		if conn.incomingStreams == nil {
			conn.incomingStreams = make(map[quic.StreamID]chan quic.Stream)
		}
		conn.incomingStreams[id] = make(chan quic.Stream, maxBufferedStreams)
	}
	return conn.incomingStreams[id]
}

func (conn *connection) incomingUniStreamChan(id quic.StreamID) chan quic.ReceiveStream {
	conn.incomingUniStreamsMutex.Lock()
	defer conn.incomingUniStreamsMutex.Unlock()
	if conn.incomingUniStreams[id] == nil {
		if conn.incomingUniStreams == nil {
			conn.incomingUniStreams = make(map[quic.StreamID]chan quic.ReceiveStream)
		}
		conn.incomingUniStreams[id] = make(chan quic.ReceiveStream, maxBufferedStreams)
	}
	return conn.incomingUniStreams[id]
}

func (conn *connection) cleanup(id quic.StreamID) {
	conn.incomingStreamsMutex.Lock()
	delete(conn.incomingStreams, id)
	conn.incomingStreamsMutex.Unlock()

	conn.incomingUniStreamsMutex.Lock()
	delete(conn.incomingUniStreams, id)
	conn.incomingUniStreamsMutex.Unlock()

	// TODO: clean up buffered datagrams
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

func (conn *connection) WebTransport(str quic.Stream) (WebTransport, error) {
	if str.StreamID().Type() != protocol.StreamTypeBidi {
		return nil, errors.New("bidirectional stream required")
	}
	return newWebTransportSession(conn, str), nil
}
