package quic

import (
	"bytes"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	connectionID protocol.ConnectionID
	packetCount  int
}

func (s *mockSession) HandlePacket(addr interface{}, publicHeader *PublicHeader, r *bytes.Reader) {
	s.packetCount++
}

func (s *mockSession) Run() {
}

func newMockSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback CloseCallback) PacketHandler {
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
			err := server.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
		})

		It("assigns packets to existing sessions", func() {
			err := server.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			err = server.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(2))
		})
	})

	PIt("setups and responds with version negotiation", func() {
		server, err := NewServer(testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := server.ListenAndServe("127.0.0.1:13370")
			Expect(err).To(HaveOccurred())
		}()

		time.Sleep(50 * time.Millisecond)
		addr, err2 := net.ResolveUDPAddr("udp", "127.0.0.1:13370")
		Expect(err2).ToNot(HaveOccurred())
		conn, err2 := net.DialUDP("udp", nil, addr)
		Expect(err2).ToNot(HaveOccurred())
		_, err2 = conn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01})
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
	})

	PIt("setups and responds with error on invalid frame", func() {
		server, err := NewServer(testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := server.ListenAndServe("127.0.0.1:13370")
			Expect(err).To(HaveOccurred())
		}()

		time.Sleep(50 * time.Millisecond)
		addr, err2 := net.ResolveUDPAddr("udp", "127.0.0.1:13370")
		Expect(err2).ToNot(HaveOccurred())
		conn, err2 := net.DialUDP("udp", nil, addr)
		Expect(err2).ToNot(HaveOccurred())
		_, err2 = conn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01, 0x00})
		Expect(err2).ToNot(HaveOccurred())
		data := make([]byte, 1000)
		n, _, err2 := conn.ReadFromUDP(data)
		Expect(err2).ToNot(HaveOccurred())
		Expect(n).ToNot(BeZero())
		time.Sleep(20 * time.Millisecond)
		err2 = server.Close()
		Expect(err2).ToNot(HaveOccurred())
	})

	PIt("closes and deletes sessions", func() {
		server, err := NewServer(testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := server.ListenAndServe("127.0.0.1:13370")
			Expect(err).To(HaveOccurred())
		}()

		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:13370")
		Expect(err).ToNot(HaveOccurred())

		// Send an invalid packet
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())
		pheader := []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x32, 0x01}
		_, err = conn.Write(append(pheader, (&crypto.NullAEAD{}).Seal(0, pheader, nil)...))
		Expect(err).ToNot(HaveOccurred())

		time.Sleep(10 * time.Millisecond)

		// The server should now have closed the session, leaving a nil value in the sessions map
		Expect(server.sessions).To(HaveLen(1))
		// Expect(server.sessions[0x4cfa9f9b668619f6]).To(BeNil())
		Expect(server.sessions[0x4cfa9f9b668619f6]).To(BeNil())

		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	})
})
