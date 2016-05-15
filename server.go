package quic

import (
	"bytes"
	"crypto/tls"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// packetHandler handles packets
type packetHandler interface {
	HandlePacket(addr interface{}, hdr *publicHeader, data []byte)
	Run()
}

// A Server of QUIC
type Server struct {
	conns      []*net.UDPConn
	connsMutex sync.Mutex

	signer crypto.Signer
	scfg   *handshake.ServerConfig

	sessions      map[protocol.ConnectionID]packetHandler
	sessionsMutex sync.RWMutex

	streamCallback StreamCallback

	newSession func(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback CloseCallback) packetHandler
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
		sessions:       map[protocol.ConnectionID]packetHandler{},
		newSession:     newSession,
	}, nil
}

// ListenAndServe listens and serves a connection
func (s *Server) ListenAndServe(address string) error {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.connsMutex.Lock()
	s.conns = append(s.conns, conn)
	s.connsMutex.Unlock()

	for {
		data := make([]byte, protocol.MaxPacketSize)
		n, remoteAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			return err
		}
		data = data[:n]
		if err := s.handlePacket(conn, remoteAddr, data); err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
		}
	}
}

// Close the server
func (s *Server) Close() error {
	s.connsMutex.Lock()
	defer s.connsMutex.Unlock()
	for _, c := range s.conns {
		err := c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, packet []byte) error {
	r := bytes.NewReader(packet)
	// ToDo: check packet size and send errorcodes.QUIC_PACKET_TOO_LARGE if packet is too large

	hdr, err := parsePublicHeader(r)
	if err != nil {
		// ToDo: send errorcodes.QUIC_INVALID_PACKET_HEADER
		return err
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	// Send Version Negotiation Packet if the client is speaking a different protocol version
	if hdr.VersionFlag && !protocol.IsSupportedVersion(hdr.VersionNumber) {
		utils.Infof("Client offered version %d, sending VersionNegotiationPacket", hdr.VersionNumber)
		_, err = conn.WriteToUDP(composeVersionNegotiation(hdr.ConnectionID), remoteAddr)
		if err != nil {
			return err
		}
		return nil
	}

	s.sessionsMutex.RLock()
	session, ok := s.sessions[hdr.ConnectionID]
	s.sessionsMutex.RUnlock()

	if !ok {
		utils.Infof("Serving new connection: %x, version %d from %v", hdr.ConnectionID, hdr.VersionNumber, remoteAddr)
		session = s.newSession(
			&udpConn{conn: conn, currentAddr: remoteAddr},
			hdr.VersionNumber,
			hdr.ConnectionID,
			s.scfg,
			s.streamCallback,
			s.closeCallback,
		)
		go session.Run()
		s.sessionsMutex.Lock()
		s.sessions[hdr.ConnectionID] = session
		s.sessionsMutex.Unlock()
	}
	if session == nil {
		// Late packet for closed session
		return nil
	}
	session.HandlePacket(remoteAddr, hdr, packet[len(packet)-r.Len():])
	return nil
}

func (s *Server) closeCallback(id protocol.ConnectionID) {
	s.sessionsMutex.Lock()
	s.sessions[id] = nil
	s.sessionsMutex.Unlock()
}

func composeVersionNegotiation(connectionID protocol.ConnectionID) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := publicHeader{
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
