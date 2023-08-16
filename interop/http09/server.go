package http09

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/quic-go/quic-go"
)

const h09alpn = "hq-interop"

// Close closes the server.
func (s *Server) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.listener.Close()
}

// ListenAndServe listens and serves HTTP/0.9 over QUIC.
func (s *Server) ListenAndServe() error {
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	tlsConf := s.TLSConfig.Clone()
	tlsConf.NextProtos = []string{h09alpn}
	ln, err := quic.ListenEarly(conn, tlsConf, s.QuicConfig)
	if err != nil {
		return err
	}
	s.mutex.Lock()
	s.listener = ln
	s.mutex.Unlock()

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn quic.Connection) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Error accepting stream: %s\n", err.Error())
			return
		}
		go func() {
			if err := s.handleStream(str); err != nil {
				log.Printf("Handling stream failed: %s\n", err.Error())
			}
		}()
	}
}
