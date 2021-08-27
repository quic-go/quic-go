package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

const (
	maxBufferedStreams   = 10
	maxBufferedDatagrams = 10
)

// Conn is a base HTTP/3 connection.
// Callers should use either ServerConn or ClientConn.
type Conn interface {
	// Settings returns the HTTP/3 settings for this side of the connection.
	Settings() Settings

	// PeerSettings returns the peer’s HTTP/3 settings.
	// Returns nil if the peer’s settings have not been received.
	PeerSettings() (Settings, error)

	// PeerSettingsSync returns the peer’s HTTP/3 settings,
	// blocking until the peer’s settings have been received,
	// the underlying QUIC session is closed, or the context is canceled.
	PeerSettingsSync(context.Context) (Settings, error)
}

// ServerConn is a server connection. It accepts and processes HTTP/3 request streams.
type ServerConn interface {
	Conn
	AcceptMessageStream(context.Context) (MessageStream, error)
}

// ClientConn is a client connection. It opens and processes HTTP/3 request streams.
type ClientConn interface {
	Conn
	OpenMessageStream(context.Context) (MessageStream, error)
}

// webTransportConn is an internal interface for implementing WebTransport.
type webTransportConn interface {
	acceptStream(context.Context, SessionID) (quic.Stream, error)
	acceptUniStream(context.Context, SessionID) (quic.ReceiveStream, error)
	openStream(SessionID) (quic.Stream, error)
	openStreamSync(context.Context, SessionID) (quic.Stream, error)
	openUniStream(SessionID) (quic.SendStream, error)
	openUniStreamSync(context.Context, SessionID) (quic.SendStream, error)
	readDatagram(context.Context, SessionID) ([]byte, error)
	writeDatagram(SessionID, []byte) error
}

type connection struct {
	session quic.EarlySession

	settings Settings

	peerSettingsDone chan struct{} // Closed when peer settings are read
	peerSettings     Settings
	peerSettingsErr  error

	peerStreamsMutex sync.Mutex
	peerStreams      [4]quic.ReceiveStream

	incomingStreamsOnce    sync.Once
	incomingStreamsErr     error
	incomingMessageStreams chan quic.Stream

	incomingStreamsMutex sync.Mutex
	incomingStreams      map[SessionID]chan quic.Stream // Lazily constructed

	incomingUniStreamsMutex sync.Mutex
	incomingUniStreams      map[SessionID]chan quic.ReceiveStream // Lazily constructed

	// TODO: buffer incoming datagrams
	incomingDatagramsOnce  sync.Once
	incomingDatagramsMutex sync.Mutex
	incomingDatagrams      map[SessionID]chan []byte // Lazily constructed
}

var (
	_ Conn             = &connection{}
	_ ClientConn       = &connection{}
	_ ServerConn       = &connection{}
	_ webTransportConn = &connection{}
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
		incomingMessageStreams: make(chan quic.Stream, maxBufferedStreams),
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

func (conn *connection) Settings() Settings {
	return conn.settings
}

func (conn *connection) PeerSettings() (Settings, error) {
	select {
	case <-conn.peerSettingsDone:
		return conn.peerSettings, conn.peerSettingsErr
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	default:
		return nil, nil
	}
}

func (conn *connection) PeerSettingsSync(ctx context.Context) (Settings, error) {
	select {
	case <-conn.peerSettingsDone:
		return conn.peerSettings, conn.peerSettingsErr
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (conn *connection) negotiatedWebTransport() bool {
	if !conn.Settings().WebTransportEnabled() {
		return false
	}
	peerSettings, err := conn.PeerSettingsSync(context.Background())
	if err != nil {
		// TODO: log error
		return false
	}
	return peerSettings.WebTransportEnabled()
}

func (conn *connection) maxHeaderBytes() uint64 {
	max := conn.Settings()[SettingMaxFieldSectionSize]
	if max > 0 {
		return max
	}
	return http.DefaultMaxHeaderBytes
}

func (conn *connection) peerMaxHeaderBytes() uint64 {
	peerSettings, _ := conn.PeerSettings()
	if max, ok := peerSettings[SettingMaxFieldSectionSize]; ok && max > 0 {
		return max
	}
	return http.DefaultMaxHeaderBytes
}

func (conn *connection) AcceptMessageStream(ctx context.Context) (MessageStream, error) {
	if conn.session.Perspective() != quic.PerspectiveServer {
		return nil, errors.New("server method called on client connection")
	}
	conn.incomingStreamsOnce.Do(func() {
		go conn.handleIncomingStreams()
	})
	select {
	case str := <-conn.incomingMessageStreams:
		if str == nil {
			// incomingMessageStreams was closed
			return nil, conn.incomingStreamsErr
		}
		t := FrameTypeHeaders
		return newMessageStream(conn, str, &t), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}

func (conn *connection) OpenMessageStream(ctx context.Context) (MessageStream, error) {
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
	return newMessageStream(conn, str, nil), nil
}

func (conn *connection) handleIncomingStreams() {
	var wg sync.WaitGroup
	for {
		str, err := conn.session.AcceptStream(context.Background())
		if err != nil {
			conn.incomingStreamsErr = err
			// TODO: log the error
			break
		}
		wg.Add(1)
		go func(str quic.Stream) {
			conn.handleIncomingStream(str)
			wg.Done()
		}(str)
	}
	wg.Wait()
	close(conn.incomingMessageStreams)
}

func (conn *connection) handleIncomingStream(str quic.Stream) {
	r := quicvarint.NewReader(str)

	i, err := quicvarint.Read(r)
	if err != nil {
		str.CancelWrite(quic.StreamErrorCode(errorRequestIncomplete))
		return
	}

	t := FrameType(i)

	switch FrameType(t) { //nolint:exhaustive
	case FrameTypeHeaders:
		conn.incomingMessageStreams <- str
	case FrameTypeWebTransportStream:
		if !conn.negotiatedWebTransport() {
			// TODO: log error
			// TODO: should this close the connection or the stream?
			// https://github.com/ietf-wg-webtrans/draft-ietf-webtrans-http3/pull/56
			str.CancelWrite(quic.StreamErrorCode(errorSettingsError))
			return
		}
		id, err := quicvarint.Read(r)
		if err != nil {
			str.CancelWrite(quic.StreamErrorCode(errorFrameError))
			return
		}
		select {
		case conn.incomingStreamsChan(SessionID(id)) <- str:
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
		// FIXME: This could lead to resource exhaustion.
		// Chrome sends 2 unidirectional streams before opening the first WebTransport uni stream.
		// The streams are open, but zero data is sent on them, which blocks reads below.
		go conn.handleIncomingUniStream(str)
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
		conn.peerStreamsMutex.Lock()
		prevPeerStream := conn.peerStreams[streamType]
		conn.peerStreams[streamType] = str
		conn.peerStreamsMutex.Unlock()
		if prevPeerStream != nil {
			conn.session.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), fmt.Sprintf("more than one %s opened", streamType))
			return
		}
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
		case conn.incomingUniStreamsChan(SessionID(id)) <- str:
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

func (conn *connection) acceptStream(ctx context.Context, id SessionID) (quic.Stream, error) {
	select {
	case str := <-conn.incomingStreamsChan(id):
		return str, nil
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}

func (conn *connection) acceptUniStream(ctx context.Context, id SessionID) (quic.ReceiveStream, error) {
	select {
	case str := <-conn.incomingUniStreamsChan(id):
		return str, nil
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}

func (conn *connection) openStream(id SessionID) (quic.Stream, error) {
	str, err := conn.session.OpenStream()
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(FrameTypeWebTransportStream))
	quicvarint.Write(w, uint64(id))
	return str, nil
}

func (conn *connection) openStreamSync(ctx context.Context, id SessionID) (quic.Stream, error) {
	str, err := conn.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(FrameTypeWebTransportStream))
	quicvarint.Write(w, uint64(id))
	return str, nil
}

func (conn *connection) openUniStream(id SessionID) (quic.SendStream, error) {
	str, err := conn.session.OpenUniStream()
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(StreamTypeWebTransportStream))
	quicvarint.Write(w, uint64(id))
	return str, nil
}

func (conn *connection) openUniStreamSync(ctx context.Context, id SessionID) (quic.SendStream, error) {
	str, err := conn.session.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(StreamTypeWebTransportStream))
	quicvarint.Write(w, uint64(id))
	return str, nil
}

func (conn *connection) readDatagram(ctx context.Context, id SessionID) ([]byte, error) {
	conn.incomingDatagramsOnce.Do(func() {
		go conn.handleIncomingDatagrams()
	})
	select {
	case msg := <-conn.incomingDatagramsChan(id):
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-conn.session.Context().Done():
		return nil, conn.session.Context().Err()
	}
}

func (conn *connection) handleIncomingDatagrams() {
	for {
		msg, err := conn.session.ReceiveMessage()
		if err != nil {
			// TODO: log error
			return
		}

		r := bytes.NewReader(msg)
		id, err := quicvarint.Read(r)
		if err != nil {
			// TODO: log error
			continue
		}

		// TODO: handle differences between datagram draft (quarter stream ID)
		// and WebTransport draft (session ID = stream ID).
		msg = msg[quicvarint.Len(id):]

		select {
		case conn.incomingDatagramsChan(SessionID(id)) <- msg:
		case <-conn.session.Context().Done():
			return
		}
	}
}

func (conn *connection) writeDatagram(id SessionID, msg []byte) error {
	b := make([]byte, 0, len(msg)+int(quicvarint.Len(uint64(id))))
	buf := bytes.NewBuffer(b)
	quicvarint.Write(buf, uint64(id))
	n, err := buf.Write(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return errors.New("BUG: datagram buffer too small")
	}
	return conn.session.SendMessage(buf.Bytes())
}

func (conn *connection) incomingStreamsChan(id SessionID) chan quic.Stream {
	conn.incomingStreamsMutex.Lock()
	defer conn.incomingStreamsMutex.Unlock()
	if conn.incomingStreams[id] == nil {
		if conn.incomingStreams == nil {
			conn.incomingStreams = make(map[SessionID]chan quic.Stream)
		}
		conn.incomingStreams[id] = make(chan quic.Stream, maxBufferedStreams)
	}
	return conn.incomingStreams[id]
}

func (conn *connection) incomingUniStreamsChan(id SessionID) chan quic.ReceiveStream {
	conn.incomingUniStreamsMutex.Lock()
	defer conn.incomingUniStreamsMutex.Unlock()
	if conn.incomingUniStreams[id] == nil {
		if conn.incomingUniStreams == nil {
			conn.incomingUniStreams = make(map[SessionID]chan quic.ReceiveStream)
		}
		conn.incomingUniStreams[id] = make(chan quic.ReceiveStream, maxBufferedStreams)
	}
	return conn.incomingUniStreams[id]
}

func (conn *connection) incomingDatagramsChan(id SessionID) chan []byte {
	conn.incomingDatagramsMutex.Lock()
	defer conn.incomingDatagramsMutex.Unlock()
	if conn.incomingDatagrams[id] == nil {
		if conn.incomingDatagrams == nil {
			conn.incomingDatagrams = make(map[SessionID]chan []byte)
		}
		conn.incomingDatagrams[id] = make(chan []byte, maxBufferedDatagrams)
	}
	return conn.incomingDatagrams[id]
}

func (conn *connection) cleanup(id SessionID) {
	conn.incomingStreamsMutex.Lock()
	delete(conn.incomingStreams, id)
	conn.incomingStreamsMutex.Unlock()

	conn.incomingUniStreamsMutex.Lock()
	delete(conn.incomingUniStreams, id)
	conn.incomingUniStreamsMutex.Unlock()

	conn.incomingDatagramsMutex.Lock()
	delete(conn.incomingDatagrams, id)
	conn.incomingDatagramsMutex.Unlock()
}
