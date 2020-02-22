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
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
	"github.com/onsi/ginkgo"
)

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen     = quic.ListenEarly
	quicListenAddr = quic.ListenAddrEarly
)

const nextProtoH3 = "h3-24"

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "quic-go/http3 context value " + k.name }

var (
	// ServerContextKey is a context key. It can be used in HTTP
	// handlers with Context.Value to access the server that
	// started the handler. The associated value will be of
	// type *http3.Server.
	ServerContextKey = &contextKey{"http3-server"}
)

type requestError struct {
	err       error
	streamErr errorCode
	connErr   errorCode
}

func (r *requestError) HasError() bool {
	return r.err != nil || r.streamErr != 0 || r.connErr != 0
}

func (r *requestError) String() string {
	ret := make([]string, 0)
	if r.err != nil {
		ret = append(ret, r.err.Error())
	}
	if r.streamErr != 0 {
		ret = append(ret, r.streamErr.String())
	}
	if r.connErr != 0 {
		ret = append(ret, r.connErr.String())
	}
	return strings.Join(ret, ", ")
}

type ctrlStream struct {
	out         quic.SendStream
	in          quic.ReceiveStream
	maxStreamID protocol.StreamID
}

func newStreamError(code errorCode, err error) requestError {
	return requestError{err: err, streamErr: code}
}

func newConnError(code errorCode, err error) requestError {
	if code == 0 {
		panic("errorCode == 0 means no error occurred, errorCode must not equal 0 to be a connection error")
	}
	return requestError{err: err, connErr: code}
}

// Server is a HTTP2 server listening for QUIC connections.
type Server struct {
	*http.Server

	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	port uint32 // used atomically

	mutex     sync.Mutex
	listeners map[*quic.EarlyListener]struct{}
	closed    utils.AtomicBool

	logger utils.Logger

	sessCtx      context.Context
	sessCancel   context.CancelFunc
	clients      sync.WaitGroup
	serverClosed chan struct{}
}

func (cs *ctrlStream) incrementStreamID() {
	atomic.AddInt64((*int64)(&cs.maxStreamID), 4)
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
	s.logger = utils.DefaultLogger.WithPrefix("server")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{nextProtoH3}
	if tlsConf.GetConfigForClient != nil {
		getConfigForClient := tlsConf.GetConfigForClient
		tlsConf.GetConfigForClient = func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			conf, err := getConfigForClient(ch)
			if err != nil || conf == nil {
				return conf, err
			}
			conf = conf.Clone()
			conf.NextProtos = []string{nextProtoH3}
			return conf, nil
		}
	}

	var ln quic.EarlyListener
	var err error
	if conn == nil {
		ln, err = quicListenAddr(s.Addr, tlsConf, s.QuicConfig)
	} else {
		ln, err = quicListen(conn, tlsConf, s.QuicConfig)
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

func (s *Server) handleConn(sess quic.EarlySession) {
	// TODO: accept control streams
	decoder := qpack.NewDecoder(nil)

	cs, rerr := s.handleControlStreams(sess)
	if rerr.HasError() {
		s.logger.Debugf("Error encountered while opening control streams: %s", rerr)
		if rerr.connErr != 0 {
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			sess.CloseWithError(quic.ErrorCode(rerr.connErr), reason)
		}
		// control streams only have connection errors
	}

	if s.sessCtx == nil {
		s.sessCtx, s.sessCancel = context.WithCancel(context.Background())
	}
	if s.serverClosed == nil {
		s.serverClosed = make(chan struct{})
	}

	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	for {
		if s.closed.Get() {
			return
		}
		str, err := sess.AcceptStream(s.sessCtx)
		if err != nil {
			if errors.Is(context.Canceled, s.sessCtx.Err()) {
				s.logger.Debugf("Server closed, ending session")
				return
			}
			s.logger.Debugf("Accepting stream failed: %s", err)
			return
		}
		cs.incrementStreamID()
		go func() {
			defer ginkgo.GinkgoRecover()
			rerr := s.handleRequest(sess, str, decoder, func() {
				sess.CloseWithError(quic.ErrorCode(errorFrameUnexpected), "")
			})
			if rerr.HasError() {
				s.logger.Debugf("Handling request failed: %s", rerr)
				if rerr.streamErr != 0 {
					str.CancelWrite(quic.ErrorCode(rerr.streamErr))
				}
				if rerr.connErr != 0 {
					var reason string
					if rerr.err != nil {
						reason = rerr.err.Error()
					}
					sess.CloseWithError(quic.ErrorCode(rerr.connErr), reason)
				}
				return
			}
			str.Close()
		}()
	}
}

func (s *Server) handleControlStreams(sess quic.Session) (*ctrlStream, requestError) {
	// send a SETTINGS frame
	controlStreamOut, err := sess.OpenUniStream()
	if err != nil {
		return nil, newConnError(errorMissingSettings, err)
	}
	buf := bytes.NewBuffer([]byte{0})
	(&settingsFrame{}).Write(buf)
	controlStreamOut.Write(buf.Bytes())

	controlStreamIn, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		s.logger.Debugf("Accepting the incoming control stream failed.")
		return nil, newConnError(errorMissingSettings, err)
	}

	pair := &ctrlStream{in: controlStreamIn, out: controlStreamOut}

	br, ok := controlStreamIn.(byteReader)
	if !ok {
		br = &byteReaderImpl{controlStreamIn}
	}
	t, err := utils.ReadVarInt(br)
	if t != 0x0 {
		s.logger.Debugf("First stream must be a control stream")
		return nil, newConnError(errorMissingSettings, err)
	}

	frame, err := parseNextFrame(controlStreamIn)
	if err != nil {
		s.logger.Debugf("Error encountered while parsing incoming frame")
		return nil, newConnError(errorMissingSettings, err)
	}
	sf, ok := frame.(*settingsFrame)
	if !ok {
		s.logger.Debugf("First incoming frame parsed was not a settings frame")
		return nil, newConnError(errorMissingSettings, nil)
	}
	// TODO: do something with the settings frame
	s.logger.Debugf("Got settings frame: %+v", sf)

	s.clients.Add(1)
	connDone := make(chan struct{})
	go func() {
		defer ginkgo.GinkgoRecover()
		defer close(connDone)
		defer s.clients.Done()
		for {
			frame, err := parseNextFrame(controlStreamIn)
			if err != nil {
				s.logger.Debugf("Error encountered while parsing incoming frame: %s", err)
				return
			}
			// TODO: do something with incoming frames on the control stream
			s.logger.Debugf("Got frame on control stream: %+v", frame)
		}
	}()

	go func() {
		select {
		case <-s.serverClosed:
			goaway := goawayFrame{
				StreamID: pair.maxStreamID + 4,
			}
			buf := &bytes.Buffer{}
			goaway.Write(buf)
			_, err := pair.out.Write(buf.Bytes())
			if err != nil {
				s.logger.Debugf("Error encountered while writing goaway frame: %s", err)
			}
			s.logger.Debugf("Sent goaway frame with StreamID %d to %d", pair.maxStreamID, pair.out.StreamID())

		case <-connDone:
		}
	}()

	return pair, requestError{}
}

func (s *Server) maxHeaderBytes() uint64 {
	if s.Server.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.Server.MaxHeaderBytes)
}

func (s *Server) handleRequest(sess quic.Session, str quic.Stream, decoder *qpack.Decoder, onFrameError func()) requestError {
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

	req.RemoteAddr = sess.RemoteAddr().String()
	req.Body = newRequestBody(str, onFrameError)

	if s.logger.Debug() {
		s.logger.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		s.logger.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	ctx := str.Context()
	ctx = context.WithValue(ctx, ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, sess.LocalAddr())
	req = req.WithContext(ctx)
	responseWriter := newResponseWriter(str, s.logger)
	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	var panicked, readEOF bool
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
		handler.ServeHTTP(responseWriter, req)
		// read the eof
		if _, err = str.Read([]byte{0}); err == io.EOF {
			readEOF = true
		}
	}()

	if panicked {
		responseWriter.WriteHeader(500)
	} else {
		responseWriter.WriteHeader(200)
	}

	if !readEOF {
		str.CancelRead(quic.ErrorCode(errorEarlyResponse))
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
	s.closed.Set(true)

	if s.serverClosed == nil {
		s.logger.Debugf("Nothing is open, closing")
		return s.Close()
	}

	s.sessCancel()
	close(s.serverClosed)

	// give time for those connections to either complete or self terminate
	done := make(chan struct{})
	go func() {
		s.clients.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
	}

	// close them
	return s.Close()
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

	hdr.Add("Alt-Svc", fmt.Sprintf(`%s=":%d"; ma=2592000`, nextProtoH3, port))

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
