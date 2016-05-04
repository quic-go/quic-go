package h2quic

import (
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Server is a HTTP2 server listening for QUIC connections
type Server struct {
	server  *quic.Server
	handler http.Handler
}

// NewServer creates a new server instance
func NewServer(tlsConfig *tls.Config) (*Server, error) {
	s := &Server{}

	var err error
	s.server, err = quic.NewServer(tlsConfig, s.handleStream)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// ListenAndServe listens on the network address and calls the handler.
func (s *Server) ListenAndServe(addr string, handler http.Handler) error {
	if handler != nil {
		s.handler = handler
	} else {
		s.handler = http.DefaultServeMux
	}
	return s.server.ListenAndServe(addr)
}

func (s *Server) handleStream(session *quic.Session, headerStream utils.Stream) {
	hpackDecoder := hpack.NewDecoder(4096, nil)
	h2framer := http2.NewFramer(nil, headerStream)

	go func() {
		for {
			if err := s.handleRequest(session, headerStream, hpackDecoder, h2framer); err != nil {
				utils.Errorf("error handling h2 request: %s", err.Error())
				return
			}
		}
	}()
}

func (s *Server) handleRequest(session *quic.Session, headerStream utils.Stream, hpackDecoder *hpack.Decoder, h2framer *http2.Framer) error {
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
	utils.Infof("Request: %#v", req)

	responseWriter := &responseWriter{
		header:       http.Header{},
		headerStream: headerStream,
		dataStreamID: protocol.StreamID(h2headersFrame.StreamID),
		session:      session,
	}

	go func() {
		s.handler.ServeHTTP(responseWriter, req)
		if responseWriter.dataStream != nil {
			responseWriter.dataStream.Close()
		}
	}()

	return nil
}
