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

	mutex     sync.RWMutex
	listeners map[*quic.EarlyListener]listenerInfo
	closed    utils.AtomicBool

	altSvcHeader string

	loggerOnce sync.Once
	logger     utils.Logger
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

// Serve an existing QUIC listener.
// Make sure you use http3.ConfigureTLSConfig to configure a tls.Config
// and use it to construct a http3-friendly QUIC listener.
// Closing the server does close the listener.
func (s *Server) ServeListener(listener quic.EarlyListener) error {
	return s.serveImpl(func() (quic.EarlyListener, error) { return listener, nil })
}

func (s *Server) serveConn(tlsConf *tls.Config, conn net.PacketConn) error {
	return s.serveImpl(func() (quic.EarlyListener, error) {
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
			return nil, err
		}
		return ln, nil
	})
}

func (s *Server) serveImpl(startListener func() (quic.EarlyListener, error)) error {
	if s.closed.Get() {
		return http.ErrServerClosed
	}
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	s.loggerOnce.Do(func() {
		s.logger = utils.DefaultLogger.WithPrefix("server")
	})

	ln, err := startListener()
	if err != nil {
		return err
	}
	s.addListener(&ln)
	defer s.removeListener(&ln)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(conn)
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
func (s *Server) addListener(l *quic.EarlyListener) {
	s.mutex.Lock()
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

	s.mutex.Unlock()
}

func (s *Server) removeListener(l *quic.EarlyListener) {
	s.mutex.Lock()
	delete(s.listeners, l)
	s.generateAltSvcHeader()
	s.mutex.Unlock()
}

func (s *Server) handleConn(conn quic.EarlyConnection) {
	decoder := qpack.NewDecoder(nil)

	// send a SETTINGS frame
	str, err := conn.OpenUniStream()
	if err != nil {
		s.logger.Debugf("Opening the control stream failed.")
		return
	}
	buf := &bytes.Buffer{}
	quicvarint.Write(buf, streamTypeControlStream) // stream type
	(&settingsFrame{Datagram: s.EnableDatagrams}).Write(buf)
	str.Write(buf.Bytes())

	go s.handleUnidirectionalStreams(conn)

	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			s.logger.Debugf("Accepting stream failed: %s", err)
			return
		}
		go func() {
			rerr := s.handleRequest(conn, str, decoder, func() {
				conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
			})
			if rerr.err != nil || rerr.streamErr != 0 || rerr.connErr != 0 {
				s.logger.Debugf("Handling request failed: %s", err)
				if rerr.streamErr != 0 {
					str.CancelWrite(quic.StreamErrorCode(rerr.streamErr))
				}
				if rerr.connErr != 0 {
					var reason string
					if rerr.err != nil {
						reason = rerr.err.Error()
					}
					conn.CloseWithError(quic.ApplicationErrorCode(rerr.connErr), reason)
				}
				return
			}
			str.Close()
		}()
	}
}

func (s *Server) handleUnidirectionalStreams(conn quic.EarlyConnection) {
	for {
		str, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			s.logger.Debugf("accepting unidirectional stream failed: %s", err)
			return
		}

		go func(str quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				s.logger.Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream:
				// Our QPACK implementation doesn't use the dynamic table yet.
				// TODO: check that only one stream of each type is opened.
				return
			case streamTypePushStream: // only the server can push
				conn.CloseWithError(quic.ApplicationErrorCode(errorStreamCreationError), "")
				return
			default:
				str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
				return
			}
			f, err := parseNextFrame(str)
			if err != nil {
				conn.CloseWithError(quic.ApplicationErrorCode(errorFrameError), "")
				return
			}
			sf, ok := f.(*settingsFrame)
			if !ok {
				conn.CloseWithError(quic.ApplicationErrorCode(errorMissingSettings), "")
				return
			}
			if !sf.Datagram {
				return
			}
			// If datagram support was enabled on our side as well as on the client side,
			// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
			// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
			if s.EnableDatagrams && !conn.ConnectionState().SupportsDatagrams {
				conn.CloseWithError(quic.ApplicationErrorCode(errorSettingsError), "missing QUIC Datagram support")
			}
		}(str)
	}
}

func (s *Server) maxHeaderBytes() uint64 {
	if s.Server.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.Server.MaxHeaderBytes)
}

func (s *Server) handleRequest(conn quic.Connection, str quic.Stream, decoder *qpack.Decoder, onFrameError func()) requestError {
	frame, err := parseNextFrame(str)
	if err != nil {
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
	r := newResponseWriter(str, s.logger)
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
	s.closed.Set(true)

	s.mutex.Lock()
	defer s.mutex.Unlock()

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
