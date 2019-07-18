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
)

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen     = quic.Listen
	quicListenAddr = quic.ListenAddr
)

const nextProtoH3 = "h3-22"

// Server is a HTTP2 server listening for QUIC connections.
type Server struct {
	*http.Server

	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	port uint32 // used atomically

	listenerMutex sync.Mutex
	listener      quic.Listener
	closed        bool

	supportedVersionsAsString string

	logger utils.Logger
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
func (s *Server) Serve(conn net.PacketConn) error {
	return s.serveImpl(s.TLSConfig, conn)
}

func (s *Server) serveImpl(tlsConfig *tls.Config, conn net.PacketConn) error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	s.logger = utils.DefaultLogger.WithPrefix("server")
	s.listenerMutex.Lock()
	if s.closed {
		s.listenerMutex.Unlock()
		return errors.New("Server is already closed")
	}
	if s.listener != nil {
		s.listenerMutex.Unlock()
		return errors.New("ListenAndServe may only be called once")
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	if !strSliceContains(tlsConfig.NextProtos, nextProtoH3) {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, nextProtoH3)
	}

	var ln quic.Listener
	var err error
	if conn == nil {
		ln, err = quicListenAddr(s.Addr, tlsConfig, s.QuicConfig)
	} else {
		ln, err = quicListen(conn, tlsConfig, s.QuicConfig)
	}
	if err != nil {
		s.listenerMutex.Unlock()
		return err
	}
	s.listener = ln
	s.listenerMutex.Unlock()

	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(sess)
	}
}

func (s *Server) handleConn(sess quic.Session) {
	// TODO: accept control streams
	decoder := qpack.NewDecoder(nil)

	// send a SETTINGS frame
	str, err := sess.OpenUniStream()
	if err != nil {
		s.logger.Debugf("Opening the control stream failed.")
		return
	}
	buf := bytes.NewBuffer([]byte{0})
	(&settingsFrame{}).Write(buf)
	str.Write(buf.Bytes())

	for {
		str, err := sess.AcceptStream(context.Background())
		if err != nil {
			s.logger.Debugf("Accepting stream failed: %s", err)
			return
		}
		// TODO: handle error
		go func() {
			if err := s.handleRequest(str, decoder); err != nil {
				s.logger.Debugf("Handling request failed: %s", err)
				str.CancelWrite(quic.ErrorCode(errorGeneralProtocolError))
				return
			}
			str.Close()
		}()
	}
}

// TODO: improve error handling.
// Most (but not all) of the errors occurring here are connection-level erros.
func (s *Server) handleRequest(str quic.Stream, decoder *qpack.Decoder) error {
	frame, err := parseNextFrame(str)
	if err != nil {
		str.CancelWrite(quic.ErrorCode(errorRequestCanceled))
		return err
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		str.CancelWrite(quic.ErrorCode(errorUnexpectedFrame))
		return errors.New("expected first frame to be a headers frame")
	}
	// TODO: check length
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		str.CancelWrite(quic.ErrorCode(errorIncompleteRequest))
		return err
	}
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		str.CancelWrite(quic.ErrorCode(errorGeneralProtocolError))
		return err
	}
	req, err := requestFromHeaders(hfs)
	if err != nil {
		return err
	}
	req.Body = newRequestBody(str)

	if s.logger.Debug() {
		s.logger.Infof("%s %s%s, on stream %d", req.Method, req.Host, req.RequestURI, str.StreamID())
	} else {
		s.logger.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	req = req.WithContext(str.Context())
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
	return nil
}

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) Close() error {
	s.listenerMutex.Lock()
	defer s.listenerMutex.Unlock()
	s.closed = true
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
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

	if s.supportedVersionsAsString == "" {
		var versions []string
		for _, v := range protocol.SupportedVersions {
			versions = append(versions, v.ToAltSvc())
		}
		s.supportedVersionsAsString = strings.Join(versions, ",")
	}

	hdr.Add("Alt-Svc", fmt.Sprintf(`quic=":%d"; ma=2592000; v="%s"`, port, s.supportedVersionsAsString))

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

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
