package quic

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var supportedVersions = map[protocol.VersionNumber]bool{
	30: true,
	32: true,
}

// A Server of QUIC
type Server struct {
	keyData *crypto.KeyData
	scfg    *handshake.ServerConfig

	sessions map[protocol.ConnectionID]*Session

	streamCallback StreamCallback
}

// NewServer makes a new server
func NewServer(certPath, keyPath string, cb StreamCallback) (*Server, error) {
	path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
	keyData, err := crypto.LoadKeyData(path+"cert.der", path+"key.der")
	if err != nil {
		return nil, err
	}

	scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), keyData)

	return &Server{
		keyData:        keyData,
		scfg:           scfg,
		streamCallback: cb,
		sessions:       map[protocol.ConnectionID]*Session{},
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

	for {
		data := make([]byte, 1400)
		n, remoteAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			return err
		}
		data = data[:n]
		r := bytes.NewReader(data)

		fmt.Printf("Received %d bytes from %v\n", n, remoteAddr)

		publicHeader, err := ParsePublicHeader(r)
		if err != nil {
			fmt.Printf("Could not parse public header")
			continue
		}

		fmt.Printf("Got packet # %d\n", publicHeader.PacketNumber)

		// Send Version Negotiation Packet if the client is speaking a different protocol version
		if publicHeader.VersionFlag && !supportedVersions[publicHeader.VersionNumber] {
			if err := sendVersionNegotiation(conn, remoteAddr, publicHeader); err != nil {
				fmt.Printf("Error sending version negotiation: %s", err.Error())
			}
			continue
		}

		session, ok := s.sessions[publicHeader.ConnectionID]
		if !ok {
			session = NewSession(conn, publicHeader.VersionNumber, publicHeader.ConnectionID, s.scfg, s.streamCallback)
			s.sessions[publicHeader.ConnectionID] = session
		}
		err = session.HandlePacket(remoteAddr, data[0:n-r.Len()], publicHeader, r)
		if err != nil {
			fmt.Printf("Error handling packet: %s\n", err.Error())
		}
	}
}

func sendVersionNegotiation(conn *net.UDPConn, remoteAddr *net.UDPAddr, publicHeader *PublicHeader) error {
	fmt.Println("Sending VersionNegotiationPacket")
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{ConnectionID: publicHeader.ConnectionID, PacketNumber: 1, VersionFlag: true}
	err := responsePublicHeader.WritePublicHeader(fullReply)
	if err != nil {
		return err
	}
	for v := range supportedVersions {
		utils.WriteUint32(fullReply, protocol.VersionNumberToTag(v))
	}
	_, err = conn.WriteToUDP(fullReply.Bytes(), remoteAddr)
	if err != nil {
		return err
	}
	return nil
}
