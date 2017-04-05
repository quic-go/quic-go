package quic

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// packetHandler handles packets
type packetHandler interface {
	Session
	handlePacket(*receivedPacket)
	run()
}

// A Listener of QUIC
type server struct {
	config *Config

	conn net.PacketConn

	certChain crypto.CertChain
	scfg      *handshake.ServerConfig

	sessions                  map[protocol.ConnectionID]packetHandler
	sessionsMutex             sync.RWMutex
	deleteClosedSessionsAfter time.Duration

	newSession func(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, closeCallback closeCallback, cryptoChangeCallback cryptoChangeCallback) (packetHandler, error)
}

var _ Listener = &server{}

// ListenAddr creates a QUIC server listening on a given address.
// The listener is not active until Serve() is called.
func ListenAddr(addr string, config *Config) (Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return Listen(conn, config)
}

// Listen listens for QUIC connections on a given net.PacketConn.
// The listener is not active until Serve() is called.
func Listen(conn net.PacketConn, config *Config) (Listener, error) {
	certChain := crypto.NewCertChain(config.TLSConfig)
	kex, err := crypto.NewCurve25519KEX()
	if err != nil {
		return nil, err
	}
	scfg, err := handshake.NewServerConfig(kex, certChain)
	if err != nil {
		return nil, err
	}

	return &server{
		conn:                      conn,
		config:                    config,
		certChain:                 certChain,
		scfg:                      scfg,
		sessions:                  map[protocol.ConnectionID]packetHandler{},
		newSession:                newSession,
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
	}, nil
}

// Listen listens on an existing PacketConn
func (s *server) Serve() error {
	for {
		data := getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, remoteAddr, err := s.conn.ReadFrom(data)
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
func (s *server) Close() error {
	s.sessionsMutex.Lock()
	for _, session := range s.sessions {
		if session != nil {
			s.sessionsMutex.Unlock()
			_ = session.Close(nil)
			s.sessionsMutex.Lock()
		}
	}
	s.sessionsMutex.Unlock()

	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Addr returns the server's network address
func (s *server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *server) handlePacket(pconn net.PacketConn, remoteAddr net.Addr, packet []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := ParsePublicHeader(r, protocol.PerspectiveClient)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	s.sessionsMutex.RLock()
	session, ok := s.sessions[hdr.ConnectionID]
	s.sessionsMutex.RUnlock()

	// ignore all Public Reset packets
	if hdr.ResetFlag {
		if ok {
			var pr *publicReset
			pr, err = parsePublicReset(r)
			if err != nil {
				utils.Infof("Received a Public Reset for connection %x. An error occurred parsing the packet.")
			} else {
				utils.Infof("Received a Public Reset for connection %x, rejected packet number: 0x%x.", hdr.ConnectionID, pr.rejectedPacketNumber)
			}
		} else {
			utils.Infof("Received Public Reset for unknown connection %x.", hdr.ConnectionID)
		}
		return nil
	}

	// a session is only created once the client sent a supported version
	// if we receive a packet for a connection that already has session, it's probably an old packet that was sent by the client before the version was negotiated
	// it is safe to drop it
	if ok && hdr.VersionFlag && !protocol.IsSupportedVersion(hdr.VersionNumber) {
		return nil
	}

	// Send Version Negotiation Packet if the client is speaking a different protocol version
	if hdr.VersionFlag && !protocol.IsSupportedVersion(hdr.VersionNumber) {
		// drop packets that are too small to be valid first packets
		if len(packet) < protocol.ClientHelloMinimumSize+len(hdr.Raw) {
			return errors.New("dropping small packet with unknown version")
		}
		utils.Infof("Client offered version %d, sending VersionNegotiationPacket", hdr.VersionNumber)
		_, err = pconn.WriteTo(composeVersionNegotiation(hdr.ConnectionID), remoteAddr)
		return err
	}

	if !ok {
		if !hdr.VersionFlag {
			_, err = pconn.WriteTo(writePublicReset(hdr.ConnectionID, hdr.PacketNumber, 0), remoteAddr)
			return err
		}
		version := hdr.VersionNumber
		if !protocol.IsSupportedVersion(version) {
			return errors.New("Server BUG: negotiated version not supported")
		}

		utils.Infof("Serving new connection: %x, version %d from %v", hdr.ConnectionID, version, remoteAddr)
		session, err = s.newSession(
			&conn{pconn: pconn, currentAddr: remoteAddr},
			version,
			hdr.ConnectionID,
			s.scfg,
			s.closeCallback,
			s.cryptoChangeCallback,
		)
		if err != nil {
			return err
		}
		go session.run()
		s.sessionsMutex.Lock()
		s.sessions[hdr.ConnectionID] = session
		s.sessionsMutex.Unlock()
		if s.config.ConnState != nil {
			go s.config.ConnState(session, ConnStateVersionNegotiated)
		}
	}
	if session == nil {
		// Late packet for closed session
		return nil
	}
	session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (s *server) cryptoChangeCallback(session Session, isForwardSecure bool) {
	var state ConnState
	if isForwardSecure {
		state = ConnStateForwardSecure
	} else {
		state = ConnStateSecure
	}
	if s.config.ConnState != nil {
		go s.config.ConnState(session, state)
	}
}

func (s *server) closeCallback(id protocol.ConnectionID) {
	s.sessionsMutex.Lock()
	s.sessions[id] = nil
	s.sessionsMutex.Unlock()

	time.AfterFunc(s.deleteClosedSessionsAfter, func() {
		s.sessionsMutex.Lock()
		delete(s.sessions, id)
		s.sessionsMutex.Unlock()
	})
}

func composeVersionNegotiation(connectionID protocol.ConnectionID) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	err := responsePublicHeader.Write(fullReply, protocol.Version35, protocol.PerspectiveServer)
	if err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
	}
	fullReply.Write(protocol.SupportedVersionsAsTags)
	return fullReply.Bytes()
}
