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
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// listenerInfo contains info about specific listener added with addListener
type listenerInfo struct {
	port int // 0 means that no info about port is available
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
	listeners map[*quic.EarlyListener]listenerInfo

	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc

	closed bool

	altSvcHeader string

	logger utils.Logger
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

	if err := s.addListener(&ln); err != nil {
		return err
	}
	err := s.serveListener(ln)
	s.removeListener(&ln)
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
	if err := s.addListener(&ln); err != nil {
		return err
	}
	err = s.serveListener(ln)
	s.removeListener(&ln)
	return err
}

func (s *Server) serveListener(ln quic.EarlyListener) error {
	s.initContext()
	for {
		conn, err := ln.Accept(s.ctx)
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

// handleConn handles requests on the given connection until it is no longer
// readable.
func (s *Server) handleConn(conn quic.EarlyConnection) {
	s.newConn(conn).serve()
}

// ServeConn serves HTTP/3 requests on the provided QUIC connection and blocks
// until connection is no longer readable.
//
// It is guaranteed that the given connection and the server’s http.Handler will
// not be used once ServeConn returns.
func (s *Server) ServeConn(conn quic.EarlyConnection) {
	s.handleConn(conn)
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

	if s.Port != 0 {
		// if Port is specified, we must use it instead of the
		// listener addresses since there's a reason it's specified.
		addPort(s.Port)
	} else {
		// if we have some listeners assigned, try to find ports
		// which we can announce, otherwise nothing should be announced
		validPortsFound := false
		for _, info := range s.listeners {
			if info.port != 0 {
				addPort(info.port)
				validPortsFound = true
			}
		}
		if !validPortsFound {
			if port, err := extractPort(s.Addr); err == nil {
				addPort(port)
			}
		}
	}

	s.altSvcHeader = strings.Join(altSvc, ",")
}

// We store a pointer to interface in the map set. This is safe because we only
// call trackListener via Serve and can track+defer untrack the same pointer to
// local variable there. We never need to compare a Listener from another caller.
func (s *Server) addListener(l *quic.EarlyListener) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closed {
		return http.ErrServerClosed
	}
	if s.logger == nil {
		s.logger = utils.DefaultLogger.WithPrefix("server")
	}
	if s.listeners == nil {
		s.listeners = make(map[*quic.EarlyListener]listenerInfo)
	}

	if port, err := extractPort((*l).Addr().String()); err == nil {
		s.listeners[l] = listenerInfo{port}
	} else {
		s.logger.Errorf(
			"Unable to extract port from listener %+v, will not be announced using SetQuicHeaders: %s", err)
		s.listeners[l] = listenerInfo{}
	}
	s.generateAltSvcHeader()
	return nil
}

func (s *Server) removeListener(l *quic.EarlyListener) {
	s.mutex.Lock()
	delete(s.listeners, l)
	s.generateAltSvcHeader()
	s.mutex.Unlock()
}

// serverConn is a server side of a single QUIC connection.
type serverConn struct {
	// Server is the server on which connection arrived (or passed to
	// ServeConn method).
	*Server

	// conn is the underlying connection that is being served.
	conn quic.EarlyConnection

	// ctx is the context used for accepting streams on the connection.
	ctx context.Context
	// cancel is a function that cancels ctx context.
	cancel context.CancelFunc

	// decoder is a shared decoder instance. It is safe for concurrent use.
	decoder *qpack.Decoder

	// ctrl is an atomic boolean that is set to true when the first control
	// stream is accepted.
	ctrl uint32 // mutable

	// lastStreamID is the ID of the last accepted client-initiated
	// bidirectional stream for GOAWAY frame.
	//
	// It is updated in (*serverConn).acceptStreams loop.
	lastStreamID quic.StreamID // mutable

	// streamWG and uniStreamWG are the wait groups for stream handlers.
	streamWG, uniStreamWG sync.WaitGroup
}

// newConn returns a new server connection from c.
func (s *Server) newConn(c quic.EarlyConnection) *serverConn {
	ctx, cancel := s.newConnContext()
	return &serverConn{
		Server:  s,
		conn:    c,
		ctx:     ctx,
		cancel:  cancel,
		decoder: qpack.NewDecoder(nil),
	}
}

// newConnContext returns a child context of the internal server’s context for
// new connection. The context is used to propagates graceful server shutdown
// signal to connections.
func (s *Server) newConnContext() (context.Context, context.CancelFunc) {
	s.initContext()
	return context.WithCancel(s.ctx)
}

// initContext initialized the internal server context at most once.
func (s *Server) initContext() {
	s.once.Do(func() {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	})
}

// serve starts serving requests on the underlying connection.
func (s *serverConn) serve() {
	ctrl, err := s.openControlStream()
	if err != nil {
		s.cancel()
		s.logger.Debugf("Opening the control stream failed: %s", err)
		s.conn.CloseWithError(quic.ApplicationErrorCode(errorClosedCriticalStream), "")
		return
	}

	// Send SETTINGS frame on the control stream.
	buf := bytes.NewBuffer(nil)
	(&settingsFrame{Datagram: s.EnableDatagrams, Other: s.AdditionalSettings}).Write(buf)
	ctrl.Write(buf.Bytes())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.cancel()
		s.acceptUniStreams()
	}()

	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	s.acceptStreams()

	// Stop accepting unidirectional streams.
	s.cancel()
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
	// handlers to complete.
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
func (s *serverConn) acceptStreams() {
	for {
		str, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			s.logger.Debugf("Accepting stream failed: %s", err)
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
		s.logger.Debugf("Handling request failed: %s", rerr.err)
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
func (s *serverConn) acceptUniStreams() {
	for {
		str, err := s.conn.AcceptUniStream(s.ctx)
		if err != nil {
			s.logger.Debugf("accepting unidirectional stream failed: %s", err)
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
		s.logger.Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
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
			s.logger.Debugf("parsing next frame in the control stream: %s", err)
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
			s.cancel()
			return
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

	if s.logger.Debug() {
		s.logger.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		s.logger.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	ctx := str.Context()
	ctx = context.WithValue(ctx, ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
	req = req.WithContext(ctx)
	r := newResponseWriter(str, conn, s.logger)
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
				s.logger.Errorf("http: panic serving: %v\n%s", p, buf)
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

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.closed = true

	var err error
	for ln := range s.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// CloseGracefully shuts down the server gracefully. The server sends a GOAWAY frame first, then waits for either timeout to trigger, or for all running requests to complete.
// CloseGracefully in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) CloseGracefully(timeout time.Duration) error {
	// TODO: implement
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
