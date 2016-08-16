package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type streamCreator interface {
	GetOrOpenStream(protocol.StreamID) (utils.Stream, error)
	Close(error) error
	RemoteAddr() *net.UDPAddr
}

// Server is a HTTP2 server listening for QUIC connections.
type Server struct {
	*http.Server

	// Private flag for demo, do not use
	CloseAfterFirstRequest bool

	port uint32 // used atomically

	server      *quic.Server
	serverMutex sync.Mutex
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/2 requests on incoming connections.
func (s *Server) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of h2quic.Server without http.Server")
	}
	return s.serveImpl(s.TLSConfig, nil)
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/2 requests on incoming connections.
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
func (s *Server) Serve(conn *net.UDPConn) error {
	return s.serveImpl(s.TLSConfig, conn)
}

func (s *Server) serveImpl(tlsConfig *tls.Config, conn *net.UDPConn) error {
	if s.Server == nil {
		return errors.New("use of h2quic.Server without http.Server")
	}
	s.serverMutex.Lock()
	if s.server != nil {
		s.serverMutex.Unlock()
		return errors.New("ListenAndServe may only be called once")
	}
	var err error
	server, err := quic.NewServer(s.Addr, s.TLSConfig, s.handleStreamCb)
	if err != nil {
		s.serverMutex.Unlock()
		return err
	}
	s.server = server
	s.serverMutex.Unlock()
	if conn == nil {
		return server.ListenAndServe()
	}
	return server.Serve(conn)
}

func (s *Server) handleStreamCb(session *quic.Session, stream utils.Stream) {
	s.handleStream(session, stream)
}

func (s *Server) handleStream(session streamCreator, stream utils.Stream) {
	if stream.StreamID() != 3 {
		return
	}

	hpackDecoder := hpack.NewDecoder(4096, nil)
	h2framer := http2.NewFramer(nil, stream)

	go func() {
		var headerStreamMutex sync.Mutex // Protects concurrent calls to Write()
		for {
			if err := s.handleRequest(session, stream, &headerStreamMutex, hpackDecoder, h2framer); err != nil {
				// QuicErrors must originate from stream.Read() returning an error.
				// In this case, the session has already logged the error, so we don't
				// need to log it again.
				if _, ok := err.(*qerr.QuicError); !ok {
					utils.Errorf("error handling h2 request: %s", err.Error())
				}
				return
			}
		}
	}()
}

func (s *Server) handleRequest(session streamCreator, headerStream utils.Stream, headerStreamMutex *sync.Mutex, hpackDecoder *hpack.Decoder, h2framer *http2.Framer) error {
	h2frame, err := h2framer.ReadFrame()
	if err != nil {
		return err
	}
	h2headersFrame := h2frame.(*http2.HeadersFrame)
	if !h2headersFrame.HeadersEnded() {
		return errors.New("http2 header continuation not implemented")
	}
	headers, err := hpackDecoder.DecodeFull(h2headersFrame.HeaderBlockFragment())
	if err != nil {
		utils.Errorf("invalid http2 headers encoding: %s", err.Error())
		return err
	}

	req, err := requestFromHeaders(headers)
	if err != nil {
		return err
	}

	req.RemoteAddr = session.RemoteAddr().String()

	if utils.Debug() {
		utils.Infof("%s %s%s, on data stream %d", req.Method, req.Host, req.RequestURI, h2headersFrame.StreamID)
	} else {
		utils.Infof("%s %s%s", req.Method, req.Host, req.RequestURI)
	}

	dataStream, err := session.GetOrOpenStream(protocol.StreamID(h2headersFrame.StreamID))
	if err != nil {
		return err
	}

	if h2headersFrame.StreamEnded() {
		dataStream.CloseRemote(0)
		_, _ = dataStream.Read([]byte{0}) // read the eof
	}

	// stream's Close() closes the write side, not the read side
	req.Body = ioutil.NopCloser(dataStream)

	responseWriter := newResponseWriter(headerStream, headerStreamMutex, dataStream, protocol.StreamID(h2headersFrame.StreamID))

	go func() {
		handler := s.Handler
		if handler == nil {
			handler = http.DefaultServeMux
		}
		handler.ServeHTTP(responseWriter, req)
		responseWriter.finish()
		if responseWriter.dataStream != nil {
			responseWriter.dataStream.Close()
		}
		if s.CloseAfterFirstRequest {
			time.Sleep(100 * time.Millisecond)
			session.Close(nil)
		}
	}()

	return nil
}

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) Close() error {
	s.serverMutex.Lock()
	defer s.serverMutex.Unlock()
	if s.server != nil {
		err := s.server.Close()
		s.server = nil
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
//  Alternate-Protocol: 443:quic
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

	hdr.Add("Alternate-Protocol", fmt.Sprintf("%d:quic", port))
	hdr.Add("Alt-Svc", fmt.Sprintf(`quic=":%d"; ma=2592000; v="%s"`, port, protocol.SupportedVersionsAsString))

	return nil
}

// ListenAndServeQUIC listens on the UDP network address addr and calls the
// handler for HTTP/2 requests on incoming connections. http.DefaultServeMux is
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
