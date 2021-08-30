package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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

func versionToALPN(v protocol.VersionNumber) string {
	if v == protocol.Version1 {
		return nextProtoH3
	}
	if v == protocol.VersionTLS || v == protocol.VersionDraft29 {
		return nextProtoH3Draft29
	}
	return ""
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

	// If set, the supplied HTTP/3 settings will be transmitted to the client.
	// If nil, reasonable default values will be used.
	// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-http-2-settings-parameters.
	Settings Settings

	// Enable support for HTTP/3 datagrams.
	// If set to true, QuicConfig.EnableDatagram will be set.
	// See https://www.ietf.org/archive/id/draft-schinazi-masque-h3-datagram-02.html.
	EnableDatagrams bool

	// Enable support for WebTransport.
	// If set to true, QuicConfig.EnableDatagram will be set.
	// See https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-01.html.
	EnableWebTransport bool

	port uint32 // used atomically

	mutex     sync.Mutex
	listeners map[*quic.EarlyListener]struct{}
	closed    utils.AtomicBool

	loggerOnce sync.Once
	logger     utils.Logger
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *Server) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	return s.serveImpl(s.TLSConfig, nil)
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
	return s.serveImpl(config, nil)
}

// Serve an existing UDP connection.
// It is possible to reuse the same connection for outgoing connections.
// Closing the server does not close the packet conn.
func (s *Server) Serve(conn net.PacketConn) error {
	return s.serveImpl(s.TLSConfig, conn)
}

func (s *Server) serveImpl(tlsConf *tls.Config, conn net.PacketConn) error {
	if s.closed.Get() {
		return http.ErrServerClosed
	}
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	s.loggerOnce.Do(func() {
		s.logger = utils.DefaultLogger.WithPrefix("server")
	})

	// The tls.Config we pass to Listen needs to have the GetConfigForClient callback set.
	// That way, we can get the QUIC version and set the correct ALPN value.
	baseConf := &tls.Config{
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

	var ln quic.EarlyListener
	var err error
	quicConf := s.QuicConfig
	if quicConf == nil {
		quicConf = &quic.Config{}
	} else {
		quicConf = s.QuicConfig.Clone()
	}
	if s.EnableDatagrams || s.EnableWebTransport {
		quicConf.EnableDatagrams = true
	}
	if conn == nil {
		ln, err = quicListenAddr(s.Addr, baseConf, quicConf)
	} else {
		ln, err = quicListen(conn, baseConf, quicConf)
	}
	if err != nil {
		return err
	}
	s.addListener(&ln)
	defer s.removeListener(&ln)

	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(sess)
	}
}

// We store a pointer to interface in the map set. This is safe because we only
// call trackListener via Serve and can track+defer untrack the same pointer to
// local variable there. We never need to compare a Listener from another caller.
func (s *Server) addListener(l *quic.EarlyListener) {
	s.mutex.Lock()
	if s.listeners == nil {
		s.listeners = make(map[*quic.EarlyListener]struct{})
	}
	s.listeners[l] = struct{}{}
	s.mutex.Unlock()
}

func (s *Server) removeListener(l *quic.EarlyListener) {
	s.mutex.Lock()
	delete(s.listeners, l)
	s.mutex.Unlock()
}

func (s *Server) settings() Settings {
	if s.Settings != nil {
		return s.Settings
	}
	settings := Settings{
		SettingMaxFieldSectionSize: uint64(s.maxHeaderBytes()),
	}
	if s.EnableDatagrams {
		settings.EnableDatagrams()
	}
	if s.EnableWebTransport {
		settings.EnableWebTransport()
	}
	return settings
}

func (s *Server) handleConn(sess quic.EarlySession) {
	conn, err := Accept(sess, s.settings())
	if err != nil {
		s.logger.Errorf("unable to open HTTP/3 connection")
		sess.CloseWithError(quic.ApplicationErrorCode(errorGeneralProtocolError), "")
		return
	}

	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	for {
		str, err := conn.AcceptRequestStream(context.Background())
		if err != nil {
			s.logger.Debugf("Accepting stream failed: %s", err)
			return
		}
		go func() {
			err := s.handleRequestStream(sess, str)
			if err != nil {
				s.logger.Debugf("Handling request failed: %s", err)
				switch err := err.(type) {
				case *FrameTypeError:
					// HTTP requests MUST start with a HEADERS frame.
					sess.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), err.Error())
				case *connError:
					sess.CloseWithError(quic.ApplicationErrorCode(err.Code), err.Unwrap().Error())
				case *streamError:
					str.CancelWrite(quic.StreamErrorCode(err.Code))
				default:
					str.CancelWrite(quic.StreamErrorCode(errorGeneralProtocolError))
				}
				return
			}
			// TODO: should this close CONNECT (WebTransport) requests?
			str.Close()
		}()
	}
}

func (s *Server) maxHeaderBytes() uint64 {
	if s.Server.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.Server.MaxHeaderBytes)
}

func (s *Server) handleRequestStream(sess quic.EarlySession, str RequestStream) error {
	rw := newResponseWriter(str, s.logger)
	defer func() {
		if !rw.usedDataStream() {
			rw.Flush()
		}
	}()

	headers, err := str.ReadHeaders()
	if err != nil {
		return err
	}

	ctx := str.Context()
	ctx = context.WithValue(ctx, ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, sess.LocalAddr())

	req, err := requestFromHeaders(ctx, headers)
	if err != nil {
		return nil
	}

	req.RemoteAddr = sess.RemoteAddr().String()
	// TODO(ydnar): wrap str to set req.Trailer after last read on body fails hitting EOF or a trailing HEADERS frame
	req.Body = str.DataReader()
	// TODO: set trailers

	if s.logger.Debug() {
		s.logger.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		s.logger.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

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
		handler.ServeHTTP(rw, req)
	}()

	if !rw.usedDataStream() {
		if panicked {
			rw.WriteHeader(http.StatusInternalServerError)
		} else {
			rw.WriteHeader(http.StatusOK)
		}
		// If the EOF was read by the handler, CancelRead() is a no-op.
		// TODO(ydnar): should this stream persist for CONNECT (WebTransport) requests?
		str.CancelRead(quic.StreamErrorCode(errorNoError))
	}
	return nil
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

// SetQuicHeaders can be used to set the proper headers that announce that this server supports QUIC.
// The values that are set depend on the port information from s.Server.Addr, and currently look like this (if Addr has port 443):
//  Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30"
func (s *Server) SetQuicHeaders(hdr http.Header) error {
	port := atomic.LoadUint32(&s.port)

	if port == 0 {
		// Extract port from s.Server.Addr
		_, portStr, err := net.SplitHostPort(s.Server.Addr)
		if err != nil {
			return err
		}
		portInt, err := net.LookupPort("tcp", portStr)
		if err != nil {
			return err
		}
		port = uint32(portInt)
		atomic.StoreUint32(&s.port, port)
	}

	// This code assumes that we will use protocol.SupportedVersions if no quic.Config is passed.
	supportedVersions := protocol.SupportedVersions
	if s.QuicConfig != nil && len(s.QuicConfig.Versions) > 0 {
		supportedVersions = s.QuicConfig.Versions
	}
	altSvc := make([]string, 0, len(supportedVersions))
	for _, version := range supportedVersions {
		v := versionToALPN(version)
		if len(v) > 0 {
			altSvc = append(altSvc, fmt.Sprintf(`%s=":%d"; ma=2592000`, v, port))
		}
	}
	hdr.Add("Alt-Svc", strings.Join(altSvc, ","))
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
// connetions in parallel. It returns if one of the two returns an error.
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
