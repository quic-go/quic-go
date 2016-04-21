package quic

import (
	"bytes"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	connectionID protocol.ConnectionID
	packetCount  int
}

func (s *mockSession) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	s.packetCount++
	return nil
}

func newMockSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) PacketHandler {
	return &mockSession{
		connectionID: connectionID,
	}
}

var _ = Describe("Server", func() {
	Describe("with mock session", func() {
		var (
			server *Server
		)

		BeforeEach(func() {
			server = &Server{
				sessions:   map[protocol.ConnectionID]PacketHandler{},
				newSession: newMockSession,
			}
		})

		It("composes version negotiation packets", func() {
			expected := append(
				[]byte{0x3d, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0},
				protocol.SupportedVersionsAsTags...,
			)
			Expect(composeVersionNegotiation(1)).To(Equal(expected))
		})

		It("creates new sessions", func() {
			err := server.handlePacket(nil, nil, []byte{0x04, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4c].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4c)))
			Expect(server.sessions[0x4c].(*mockSession).packetCount).To(Equal(1))
		})

		It("assigns packets to existing sessions", func() {
			err := server.handlePacket(nil, nil, []byte{0x04, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			err = server.handlePacket(nil, nil, []byte{0x04, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4c].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4c)))
			Expect(server.sessions[0x4c].(*mockSession).packetCount).To(Equal(2))
		})
	})

	It("setups and responds with version negotiation", func() {
		path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
		server, err := NewServer(path+"cert.der", path+"key.der", nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			time.Sleep(10 * time.Millisecond)
			addr, err2 := net.ResolveUDPAddr("udp", "localhost:13370")
			Expect(err2).ToNot(HaveOccurred())
			conn, err2 := net.DialUDP("udp", nil, addr)
			Expect(err2).ToNot(HaveOccurred())
			_, err2 = conn.Write([]byte{0x05, 0x01, 'Q', '0', '0', '0', 0x01})
			Expect(err2).ToNot(HaveOccurred())
			data := make([]byte, 1000)
			n, _, err2 := conn.ReadFromUDP(data)
			Expect(err2).ToNot(HaveOccurred())
			data = data[:n]
			expected := append(
				[]byte{0x3d, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0},
				protocol.SupportedVersionsAsTags...,
			)
			Expect(data).To(Equal(expected))
			err2 = server.Close()
			Expect(err2).ToNot(HaveOccurred())
		}()
		err = server.ListenAndServe("localhost:13370")
		Expect(err).To(HaveOccurred())
	})

	It("setups and responds with error on invalid frame", func() {
		path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
		server, err := NewServer(path+"cert.der", path+"key.der", nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			time.Sleep(10 * time.Millisecond)
			addr, err2 := net.ResolveUDPAddr("udp", "localhost:13370")
			Expect(err2).ToNot(HaveOccurred())
			conn, err2 := net.DialUDP("udp", nil, addr)
			Expect(err2).ToNot(HaveOccurred())
			_, err2 = conn.Write([]byte{0x05, 0x01, 'Q', '0', '3', '0', 0x01, 0x00})
			Expect(err2).ToNot(HaveOccurred())
			data := make([]byte, 1000)
			n, _, err2 := conn.ReadFromUDP(data)
			Expect(err2).ToNot(HaveOccurred())
			Expect(n).ToNot(BeZero())
			err2 = server.Close()
			Expect(err2).ToNot(HaveOccurred())
		}()
		err = server.ListenAndServe("localhost:13370")
		Expect(err).To(HaveOccurred())
	})
})
