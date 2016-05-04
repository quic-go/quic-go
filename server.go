package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// PacketHandler handles packets
type PacketHandler interface {
	HandlePacket(addr interface{}, publicHeader *PublicHeader, r *bytes.Reader)
	Run()
}

// A Server of QUIC
type Server struct {
	conn *net.UDPConn

	signer crypto.Signer
	scfg   *handshake.ServerConfig

	sessions      map[protocol.ConnectionID]PacketHandler
	sessionsMutex sync.RWMutex

	streamCallback StreamCallback

	newSession func(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback CloseCallback) PacketHandler
}

// NewServer makes a new server
func NewServer(tlsConfig *tls.Config, cb StreamCallback) (*Server, error) {
	signer, err := crypto.NewRSASigner(tlsConfig)
	if err != nil {
		return nil, err
	}

	scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)

	return &Server{
		signer:         signer,
		scfg:           scfg,
		streamCallback: cb,
		sessions:       map[protocol.ConnectionID]PacketHandler{},
		newSession:     NewSession,
	}, nil
}

// ListenAndServe listens and serves a connection
func (s *Server) ListenAndServe(address string) error {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	for {
		data := make([]byte, protocol.MaxPacketSize)
		n, remoteAddr, err := s.conn.ReadFromUDP(data)
		if err != nil {
			return err
		}
		data = data[:n]
		if err := s.handlePacket(s.conn, remoteAddr, data); err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
		}
	}
}

// Close the server
func (s *Server) Close() error {
	return s.conn.Close()
}

func (s *Server) handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, packet []byte) error {
	r := bytes.NewReader(packet)
	// ToDo: check packet size and send errorcodes.QUIC_PACKET_TOO_LARGE if packet is too large

	publicHeader, err := ParsePublicHeader(r)
	if err != nil {
		// ToDo: send errorcodes.QUIC_INVALID_PACKET_HEADER
		return errors.New("Could not parse public header")
	}
	publicHeader.Raw = packet[:len(packet)-r.Len()]

	// Send Version Negotiation Packet if the client is speaking a different protocol version
	if publicHeader.VersionFlag && !protocol.IsSupportedVersion(publicHeader.VersionNumber) {
		utils.Infof("Client offered version %d, sending VersionNegotiationPacket", publicHeader.VersionNumber)
		_, err = conn.WriteToUDP(composeVersionNegotiation(publicHeader.ConnectionID), remoteAddr)
		if err != nil {
			return err
		}
		return nil
	}

	s.sessionsMutex.RLock()
	session, ok := s.sessions[publicHeader.ConnectionID]
	s.sessionsMutex.RUnlock()

	if !ok {
		utils.Infof("Serving new connection: %d from %v", publicHeader.ConnectionID, remoteAddr)
		session = s.newSession(
			&udpConn{conn: conn, currentAddr: remoteAddr},
			publicHeader.VersionNumber,
			publicHeader.ConnectionID,
			s.scfg,
			s.streamCallback,
			s.closeCallback,
		)
		go session.Run()
		s.sessionsMutex.Lock()
		s.sessions[publicHeader.ConnectionID] = session
		s.sessionsMutex.Unlock()
	}
	if session == nil {
		// Late packet for closed session
		return nil
	}
	session.HandlePacket(remoteAddr, publicHeader, r)
	return nil
}

func (s *Server) closeCallback(session *Session) {
	s.sessionsMutex.Lock()
	s.sessions[session.connectionID] = nil
	s.sessionsMutex.Unlock()
}

func composeVersionNegotiation(connectionID protocol.ConnectionID) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	err := responsePublicHeader.WritePublicHeader(fullReply)
	if err != nil {
		panic(err) // Should not happen ;)
	}
	fullReply.Write(protocol.SupportedVersionsAsTags)
	return fullReply.Bytes()
}
