package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen     = quic.ListenEarly
	quicListenAddr = quic.ListenAddrEarly
)

const (
	nextProtoH3Draft29 = "h3-29"
	nextProtoH3        = "h3"
)

// StreamType is the stream type of a unidirectional stream.
type StreamType uint64

const (
	streamTypeControlStream      = 0
	streamTypePushStream         = 1
	streamTypeQPACKEncoderStream = 2
	streamTypeQPACKDecoderStream = 3
)

func versionToALPN(v protocol.VersionNumber) string {
	if v == protocol.Version1 {
		return nextProtoH3
	}
	if v == protocol.VersionTLS || v == protocol.VersionDraft29 {
		return nextProtoH3Draft29
	}
	return ""
}

// ConfigureTLSConfig creates a new tls.Config which can be used
// to create a quic.Listener meant for serving http3. The created
// tls.Config adds the functionality of detecting the used QUIC version
// in order to set the correct ALPN value for the http3 connection.
func ConfigureTLSConfig(tlsConf *tls.Config) *tls.Config {
	// The tls.Config used to setup the quic.Listener needs to have the GetConfigForClient callback set.
	// That way, we can get the QUIC version and set the correct ALPN value.
	return &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			// determine the ALPN from the QUIC version used
			proto := nextProtoH3Draft29
			if qconn, ok := ch.Conn.(handshake.ConnWithVersion); ok {
				if qconn.GetQUICVersion() == protocol.Version1 {
					proto = nextProtoH3
				}
			}
			config := tlsConf
			if tlsConf.GetConfigForClient != nil {
				getConfigForClient := tlsConf.GetConfigForClient
				var err error
				conf, err := getConfigForClient(ch)
				if err != nil {
					return nil, err
				}
				if conf != nil {
					config = conf
				}
			}
			if config == nil {
				return nil, nil
			}
			config = config.Clone()
			config.NextProtos = []string{proto}
			return config, nil
		},
	}
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "quic-go/http3 context value " + k.name }

// ServerContextKey is a context key. It can be used in HTTP
// handlers with Context.Value to access the server that
// started the handler. The associated value will be of
// type *http3.Server.
var ServerContextKey = &contextKey{"http3-server"}

type requestError struct {
	err       error
	streamErr errorCode
	connErr   errorCode
}

func newStreamError(code errorCode, err error) requestError {
	return requestError{err: err, streamErr: code}
}

func newConnError(code errorCode, err error) requestError {
	return requestError{err: err, connErr: code}
}

// Server is a HTTP/3 server.
type Server struct {
	*http.Server

	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	// Enable support for HTTP/3 datagrams.
	// If set to true, QuicConfig.EnableDatagram will be set.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-07.
	EnableDatagrams bool

	// The port to use in Alt-Svc response headers.
	// If needed Port can be manually set when the Server is created.
	// This is useful when a Layer 4 firewall is redirecting UDP traffic and clients must use
	// a port different from the port the Server is listening on.
	Port int

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by the HTTP/3 draft and the datagram draft.
	AdditionalSettings map[uint64]uint64

	// When set, this callback is called for the first unknown frame parsed on a bidirectional stream.
	// It is called right after parsing the frame type.
	// Callers can either process the frame and return control of the stream back to HTTP/3
	// (by returning hijacked false).
	// Alternatively, callers can take over the QUIC stream (by returning hijacked true).
	StreamHijacker func(FrameType, quic.Connection, quic.Stream) (hijacked bool, err error)

	// When set, this callback is called for unknown unidirectional stream of unknown stream type.
	UniStreamHijacker func(StreamType, quic.Connection, quic.ReceiveStream) (hijacked bool)

	mutex     sync.RWMutex
	listeners map[*serverListener]context.CancelFunc // mutable
	conns     map[*serverConn]context.CancelFunc     // mutable
	closed    uint32                                 // mutable, atomic

	altSvcHeader string // mutable

	loggerOnce sync.Once
	logger     utils.Logger
}

// getLogger initializes and returns the underlying server logger.
func (s *Server) getLogger() utils.Logger {
	s.loggerOnce.Do(func() {
		if s.logger != nil {
			return
		}
		s.logger = utils.DefaultLogger.WithPrefix("server")
	})
	return s.logger
}

// getClosed returns a boolean value indicating whether the server is closed.
func (s *Server) getClosed() bool {
	return atomic.LoadUint32(&s.closed) == 1
}

// setClosed sets the server state to be closed.
func (s *Server) setClosed() {
	atomic.StoreUint32(&s.closed, 1)
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *Server) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	return s.serveConn(s.TLSConfig, nil)
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}
	return s.serveConn(config, nil)
}

// Serve an existing UDP connection.
// It is possible to reuse the same connection for outgoing connections.
// Closing the server does not close the packet conn.
func (s *Server) Serve(conn net.PacketConn) error {
	return s.serveConn(s.TLSConfig, conn)
}

// ServeListener serves an existing QUIC listener.
// Make sure you use http3.ConfigureTLSConfig to configure a tls.Config
// and use it to construct a http3-friendly QUIC listener.
// Closing the server does close the listener.
func (s *Server) ServeListener(ln quic.EarlyListener) error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}

	if s.getClosed() {
		return http.ErrServerClosed
	}

	sl := s.newListener(ln)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.addListener(sl, cancel); err != nil {
		_ = ln.Close()
		return err
	}

	err := s.serveListener(ctx, sl)

	if s.removeListener(sl) {
		_ = ln.Close()
	}

	return err
}

func (s *Server) serveConn(tlsConf *tls.Config, conn net.PacketConn) error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}

	baseConf := ConfigureTLSConfig(tlsConf)
	quicConf := s.QuicConfig
	if quicConf == nil {
		quicConf = &quic.Config{}
	} else {
		quicConf = s.QuicConfig.Clone()
	}
	if s.EnableDatagrams {
		quicConf.EnableDatagrams = true
	}

	var ln quic.EarlyListener
	var err error
	if conn == nil {
		ln, err = quicListenAddr(s.Addr, baseConf, quicConf)
	} else {
		ln, err = quicListen(conn, baseConf, quicConf)
	}
	if err != nil {
		return err
	}
	return s.ServeListener(ln)
}

func (s *Server) serveListener(ctx context.Context, sl *serverListener) error {
	for {
		conn, err := sl.ln.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				return err
			}
			s.getLogger().Infof("accepting connection after or during server shutdown: %s", err)
			return http.ErrServerClosed
		}
		s.handleConn(ctx, conn, true)
	}
}

// handleConn handles requests on the given connection until it is no longer
// readable.
func (s *Server) handleConn(ctx context.Context, conn quic.EarlyConnection, background bool) {
	sc := s.newConn(conn)

	ctx, cancel := context.WithCancel(ctx)

	s.mutex.Lock()
	if s.conns == nil {
		s.conns = make(map[*serverConn]context.CancelFunc)
	}
	s.conns[sc] = cancel
	s.mutex.Unlock()

	if background {
		go s.handleConnServe(ctx, sc)
	} else {
		s.handleConnServe(ctx, sc)
	}
}

// handleConnServe serves the requests on the given serverConn and removes it
// from active connections map when serve method returns.
func (s *Server) handleConnServe(ctx context.Context, c *serverConn) {
	c.serve(ctx)

	s.mutex.Lock()
	cancel, ok := s.conns[c]
	delete(s.conns, c)
	if len(s.conns) == 0 {
		s.conns = nil
	}
	s.mutex.Unlock()
	close(c.done)
	if ok {
		cancel()
	}
}

func extractPort(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}

	portInt, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, err
	}
	return portInt, nil
}

func (s *Server) generateAltSvcHeader() {
	if len(s.listeners) == 0 {
		// Don't announce any ports since no one is listening for connections
		s.altSvcHeader = ""
		return
	}

	// This code assumes that we will use protocol.SupportedVersions if no quic.Config is passed.
	supportedVersions := protocol.SupportedVersions
	if s.QuicConfig != nil && len(s.QuicConfig.Versions) > 0 {
		supportedVersions = s.QuicConfig.Versions
	}
	var versionStrings []string
	for _, version := range supportedVersions {
		if v := versionToALPN(version); len(v) > 0 {
			versionStrings = append(versionStrings, v)
		}
	}

	var altSvc []string
	addPort := func(port int) {
		for _, v := range versionStrings {
			altSvc = append(altSvc, fmt.Sprintf(`%s=":%d"; ma=2592000`, v, port))
		}
	}

	if s.Port == 0 {
		// If we have some listeners assigned, try to find ports which
		// we can announce, otherwise nothing should be announced.
		portsMap := make(map[int]struct{})
		for l := range s.listeners {
			if l.port == 0 {
				continue
			}
			portsMap[l.port] = struct{}{}
		}

		ports := make([]int, 0, len(portsMap))
		for port := range portsMap {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		for _, port := range ports {
			addPort(port)
		}

		if len(ports) == 0 {
			if port, err := extractPort(s.Addr); err == nil {
				addPort(port)
			}
		}
	} else {
		// If Port is specified, we must use it instead of the listener
		// addresses since there's a reason it's specified.
		addPort(s.Port)
	}

	s.altSvcHeader = strings.Join(altSvc, ",")
}

// serverListener is a single QUIC listener owned by the HTTP/3 server.
type serverListener struct {
	// ln is the underlying listener that is being served.
	ln quic.EarlyListener

	// done is the channel that is closed when accept loop returns for this
	// listener.
	done chan struct{}

	// port is the cached port parsed from the listener’s address. If zero,
	// no information about port is available.
	port int
}

// newListener returns a new serverListener instance.
func (s *Server) newListener(l quic.EarlyListener) *serverListener {
	sl := &serverListener{
		ln:   l,
		done: make(chan struct{}),
	}
	if port, err := extractPort(l.Addr().String()); err != nil {
		s.getLogger().Errorf(
			"Unable to extract port from listener %+v, will not be announced using SetQuicHeaders: %s", l, err)
	} else {
		sl.port = port
	}
	return sl
}

// addListener adds the given listener to the active listeners map. If the
// server was closed, it returns http.ErrServerClosed. Cancel function is used
// on shutdown to trigger sending GOAWAY frames on accepted connections.
func (s *Server) addListener(sl *serverListener, cancel context.CancelFunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.getClosed() {
		return http.ErrServerClosed
	}
	if s.listeners == nil {
		s.listeners = make(map[*serverListener]context.CancelFunc)
	}
	s.listeners[sl] = cancel
	s.generateAltSvcHeader()
	return nil
}

// removeListener removes the given listener from the active listeners map. It
// returns false if the listener ownership was transfered to the Shutdown method
// and Close must not be called on the listener.
func (s *Server) removeListener(l *serverListener) bool {
	s.mutex.Lock()
	cancel, ok := s.listeners[l]
	delete(s.listeners, l)
	if len(s.listeners) == 0 {
		s.listeners = nil
	}
	s.generateAltSvcHeader()
	s.mutex.Unlock()
	close(l.done)
	if ok {
		cancel()
	}
	return ok
}

// serverConn is a server side of a single QUIC connection.
type serverConn struct {
	// Server is the server on which connection has arrived.
	*Server

	// conn is the underlying connection that is being served.
	conn quic.EarlyConnection

	// decoder is a shared decoder instance. It is safe for concurrent use.
	decoder *qpack.Decoder

	// ctrl is an atomic boolean that is set to true when the first control
	// stream is accepted.
	ctrl uint32 // mutable, atomic

	// goaway is a channel that is closed when a client sends GOAWAY frame.
	goaway chan struct{}

	// lastStreamID is the ID of the last accepted client-initiated
	// bidirectional stream for GOAWAY frame.
	//
	// It is updated in (*serverConn).acceptStreams loop.
	lastStreamID quic.StreamID // mutable

	// streamWG and uniStreamWG are the wait groups for stream handlers.
	streamWG, uniStreamWG sync.WaitGroup

	// done is the channel that is closed when server method returns for
	// this connection.
	done chan struct{}
}

// newConn returns a new server connection from c.
func (s *Server) newConn(c quic.EarlyConnection) *serverConn {
	return &serverConn{
		Server:  s,
		conn:    c,
		goaway:  make(chan struct{}),
		decoder: qpack.NewDecoder(nil),
		done:    make(chan struct{}),
	}
}

// serve starts serving requests on the underlying connection.
func (s *serverConn) serve(ctx context.Context) {
	ctrl, err := s.openControlStream()
	if err != nil {
		s.getLogger().Debugf("Opening the control stream failed: %s", err)
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorClosedCriticalStream), "")
		return
	}

	// Send SETTINGS frame on the control stream.
	buf := bytes.NewBuffer(nil)
	(&settingsFrame{Datagram: s.EnableDatagrams, Other: s.AdditionalSettings}).Write(buf)
	ctrl.Write(buf.Bytes())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		s.acceptUniStreams(ctx)

		// Stop accepting bidirectional streams.
		cancel()
	}()
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-s.goaway:
			cancel()
		}
	}()

	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	s.acceptStreams(ctx)

	// Stop accepting unidirectional streams.
	cancel()
	wg.Wait()

	// Send GOAWAY frame after acceptStreams loop returns.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#connection-shutdown
	buf.Reset()
	(&goawayFrame{StreamID: s.lastStreamID}).Write(buf)
	ctrl.Write(buf.Bytes())

	// Wait for active handlers to complete and close the connection.
	s.streamWG.Wait()
	s.conn.CloseWithError(quic.ApplicationErrorCode(errorNoError), "")

	// Wait for unidirectional streams and client-initiated control stream
	// handlers to return.
	s.uniStreamWG.Wait()
}

// openControlStream opens a server-initiated connection control stream.
func (s *serverConn) openControlStream() (quic.SendStream, error) {
	str, err := s.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	quicvarint.Write(quicvarint.NewWriter(str), streamTypeControlStream)
	return str, nil
}

// acceptStreams accepts client-initiated bidirectional streams. For each stream
// it spawns a handler goroutine.
func (s *serverConn) acceptStreams(ctx context.Context) {
	for {
		str, err := s.conn.AcceptStream(ctx)
		if err != nil {
			s.getLogger().Debugf("Accepting stream failed: %s", err)
			return
		}

		s.lastStreamID = str.StreamID()

		s.streamWG.Add(1)
		go func() {
			defer s.streamWG.Done()
			s.handleStream(str)
		}()
	}
}

// handleStream handles client-initiated bidirectional stream.
func (s *serverConn) handleStream(str quic.Stream) {
	rerr := s.handleRequest(s.conn, str, s.decoder, func() {
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
	})
	if rerr.err == errHijacked {
		return
	}
	if rerr.err != nil || rerr.streamErr != 0 || rerr.connErr != 0 {
		s.getLogger().Debugf("Handling request failed: %s", rerr.err)
		if rerr.streamErr != 0 {
			str.CancelWrite(quic.StreamErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 {
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			s.conn.CloseWithError(quic.ApplicationErrorCode(rerr.connErr), reason)
		}
		return
	}
	str.Close()
}

// acceptUniStreams accepts client-initiated unidirectional streams in a loop.
// For each stream it spawns a handler goroutine.
func (s *serverConn) acceptUniStreams(ctx context.Context) {
	for {
		str, err := s.conn.AcceptUniStream(ctx)
		if err != nil {
			s.getLogger().Debugf("accepting unidirectional stream failed: %s", err)
			return
		}

		s.uniStreamWG.Add(1)
		go func() {
			defer s.uniStreamWG.Done()
			s.handleUniStream(str)
		}()
	}
}

// handleUniStream handles client-initiated unidirectional stream.
func (s *serverConn) handleUniStream(str quic.ReceiveStream) {
	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		s.getLogger().Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
		return
	}
	switch streamType {
	case streamTypeControlStream:
		s.handleControlStream(str)
	case streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream:
		// Our QPACK implementation doesn't use the dynamic table yet.
		// TODO: check that only one stream of each type is opened.
	case streamTypePushStream: // only the server can push
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), "")
	default:
		if s.UniStreamHijacker != nil && s.UniStreamHijacker(StreamType(streamType), s.conn, str) {
			return
		}
		str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
	}
}

// handleControlStream handles client’s control stream. It closes the underlying
// connection if called more than once.
func (s *serverConn) handleControlStream(str quic.ReceiveStream) {
	// Only one control stream per peer is permitted.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-control-streams
	if !atomic.CompareAndSwapUint32(&s.ctrl, 0, 1) {
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), "")
		return
	}

	f, err := parseNextFrame(str, nil)
	if err != nil {
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorFrameError), "")
		return
	}

	// The SETTINGS frame must be the first frame in control stream.
	// Subsequent SETTINGS frames will result in connection error.
	//
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-settings
	sf, ok := f.(*settingsFrame)
	if !ok {
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorMissingSettings), "")
		return
	}

	if !sf.Datagram {
		return
	}

	// If datagram support was enabled on our side as well as on the client side,
	// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
	// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
	if s.EnableDatagrams && !s.conn.ConnectionState().SupportsDatagrams {
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorSettingsError), "missing QUIC Datagram support")
		return
	}

	var goawayClosed bool
	for {
		f, err := parseNextFrame(str, nil)
		if err != nil {
			// Abort connection with H3_CLOSED_CRITICAL_STREAM if the control stream is closed.
			//
			// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-control-streams
			var ec errorCode
			if errors.As(err, new(*quic.StreamError)) {
				ec = errorClosedCriticalStream
			} else {
				ec = errorFrameError
			}
			s.getLogger().Debugf("parsing next frame in the control stream: %s", err)
			s.conn.CloseWithError(quic.ApplicationErrorCode(ec), "")
			return
		}
		// The following frames are allowed in control streams:
		//
		//  • CANCEL_PUSH
		//  • SETTINGS (must be the first frame)
		//  • GOAWAY
		//  • MAX_PUSH_ID
		//  • Reserved
		//
		// parseNextFrame skips reserved frames, so we only have to
		// reject known frame types.
		switch f.(type) {
		case *cancelPushFrame, *maxPushIDFrame:
			// TODO: currently not implemented.
		case *goawayFrame:
			// Trigger graceful connection shutdown.
			if goawayClosed {
				continue
			}
			goawayClosed = true
			close(s.goaway)
		case *dataFrame, *headersFrame, *settingsFrame, *pushPromiseFrame:
			s.conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
			return
		}
	}
}

func (s *Server) maxHeaderBytes() uint64 {
	if s.Server.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.Server.MaxHeaderBytes)
}

func (s *Server) handleRequest(conn quic.Connection, str quic.Stream, decoder *qpack.Decoder, onFrameError func()) requestError {
	var ufh unknownFrameHandlerFunc
	if s.StreamHijacker != nil {
		ufh = func(ft FrameType) (processed bool, err error) {
			return s.StreamHijacker(ft, conn, str)
		}
	}
	frame, err := parseNextFrame(str, ufh)
	if err != nil {
		if err == errHijacked {
			return requestError{err: errHijacked}
		}
		return newStreamError(errorRequestIncomplete, err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}
	if hf.Length > s.maxHeaderBytes() {
		return newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return newStreamError(errorRequestIncomplete, err)
	}
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return newConnError(errorGeneralProtocolError, err)
	}
	req, err := requestFromHeaders(hfs)
	if err != nil {
		// TODO: use the right error code
		return newStreamError(errorGeneralProtocolError, err)
	}

	req.RemoteAddr = conn.RemoteAddr().String()
	req.Body = newRequestBody(str, onFrameError)

	if l := s.getLogger(); l.Debug() {
		l.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		l.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	ctx := str.Context()
	ctx = context.WithValue(ctx, ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
	req = req.WithContext(ctx)
	r := newResponseWriter(str, conn, s.getLogger())
	defer func() {
		if !r.usedDataStream() {
			r.Flush()
		}
	}()
	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	var panicked bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				s.getLogger().Errorf("http: panic serving: %v\n%s", p, buf)
				panicked = true
			}
		}()
		handler.ServeHTTP(r, req)
	}()

	if !r.usedDataStream() {
		if panicked {
			r.WriteHeader(500)
		} else {
			r.WriteHeader(200)
		}
		// If the EOF was read by the handler, CancelRead() is a no-op.
		str.CancelRead(quic.StreamErrorCode(errorNoError))
	}
	return requestError{}
}

// Close immediately closes all active listeners and connections. The server
// sends CONNECTION_CLOSE frames to connected clients and returns before all
// request handlers complete.
//
// Once Close has been called on a server, it may not be reused; future calls
// to methods such as Serve will return http.ErrServerClosed.
func (s *Server) Close() error {
	if s.getClosed() {
		return nil
	}

	s.mutex.Lock()
	activeListeners := s.listeners
	s.listeners = nil
	s.setClosed()
	s.mutex.Unlock()

	var err error
	for sl, cancel := range activeListeners {
		if cerr := sl.ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
		cancel()
	}
	return err
}

// Shutdown shuts down the server gracefully. The server sends a GOAWAY frame
// and waits for either the context to expire or active requests to complete.
// If the context expires, the server sends CONNECTION_CLOSE frame to connected
// clients.
//
// Once Shutdown has been called on a server, it may not be reused; future calls
// to methods such as Serve will return http.ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.getClosed() {
		return nil
	}

	// Get active listeners and connections and set them to nil to indicate
	// that we’ve moved the ownership. Also set server state to closed.
	s.mutex.Lock()
	activeListeners := s.listeners
	s.listeners = nil
	s.setClosed()
	s.mutex.Unlock()

	// Trigger graceful shutdown for active listeners and connections.
	for _, cancel := range activeListeners {
		cancel()
	}

	var once sync.Once
	forceShutdown := func() {
		for sl := range activeListeners {
			_ = sl.ln.Close()
		}
		for sl := range activeListeners {
			<-sl.done
		}
		activeListeners = nil
	}

	// Wait for listener loops to return. Close listeners (and therefore
	// connections) if context expires but do not return yet since we want
	// to guarantee that no connections are running after Shutdown returns.
	for sl := range activeListeners {
		select {
		case <-sl.done:
			continue
		case <-ctx.Done():
		}
		once.Do(forceShutdown)
		break
	}

	// At this point we know that no new connections will be created.
	s.mutex.Lock()
	activeConns := s.conns
	s.conns = nil
	s.mutex.Unlock()

	for _, cancel := range activeConns {
		cancel()
	}

	// Wait for graceful connections shutdown. If context expires, close
	// all listeners (and therefore connections) and wait until all conns
	// are done.
	for sc := range activeConns {
		select {
		case <-sc.done:
			delete(activeConns, sc)
			continue
		case <-ctx.Done():
		}
		once.Do(forceShutdown)
		for sc := range activeConns {
			<-sc.done
		}
		break
	}

	// Finally, close listeners after all connections have returned.
	once.Do(forceShutdown)

	return nil
}

// ErrNoAltSvcPort is the error returned by SetQuicHeaders when no port was found
// for Alt-Svc to announce. This can happen if listening on a PacketConn without a port
// (UNIX socket, for example) and no port is specified in Server.Port or Server.Addr.
var ErrNoAltSvcPort = errors.New("no port can be announced, specify it explicitly using Server.Port or Server.Addr")

// SetQuicHeaders can be used to set the proper headers that announce that this server supports HTTP/3.
// The values set by default advertise all of the ports the server is listening on, but can be
// changed to a specific port by setting Server.Port before launching the serverr.
// If no listener's Addr().String() returns an address with a valid port, Server.Addr will be used
// to extract the port, if specified.
// For example, a server launched using ListenAndServe on an address with port 443 would set:
// 	Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
func (s *Server) SetQuicHeaders(hdr http.Header) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.altSvcHeader == "" {
		return ErrNoAltSvcPort
	}
	// use the map directly to avoid constant canonicalization
	// since the key is already canonicalized
	hdr["Alt-Svc"] = append(hdr["Alt-Svc"], s.altSvcHeader)
	return nil
}

// ListenAndServeQUIC listens on the UDP network address addr and calls the
// handler for HTTP/3 requests on incoming connections. http.DefaultServeMux is
// used when handler is nil.
func ListenAndServeQUIC(addr, certFile, keyFile string, handler http.Handler) error {
	server := &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServe listens on the given network address for both, TLS and QUIC
// connections in parallel. It returns if one of the two returns an error.
// http.DefaultServeMux is used when handler is nil.
// The correct Alt-Svc headers for QUIC are set.
func ListenAndServe(addr, certFile, keyFile string, handler http.Handler) error {
	// Load certs
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, config)
	defer tlsConn.Close()

	// Start the servers
	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: config,
	}

	quicServer := &Server{
		Server: httpServer,
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}
	httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		handler.ServeHTTP(w, r)
	})

	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}
