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
				[]byte{0x3d, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
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

		It("closes and deletes sessions", func() {
			pheader := []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x32, 0x01}
			err := server.handlePacket(nil, nil, append(pheader, (&crypto.NullAEAD{}).Seal(0, pheader, nil)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			server.closeCallback(0x4cfa9f9b668619f6)
			// The server should now have closed the session, leaving a nil value in the sessions map
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6]).To(BeNil())
		})

	})

	It("setups and responds with version negotiation", func(done Done) {
		server, err := NewServer(testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := server.ListenAndServe("127.0.0.1:13370")
			Expect(err).To(HaveOccurred())
			close(done)
		}()

		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:13370")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err = conn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01})
			if err != nil {
				return err
			}
			data := make([]byte, 1000)
			n, _, err := conn.ReadFromUDP(data)
			if err != nil {
				return err
			}
			data = data[:n]
			expected := append(
				[]byte{0x3d, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				protocol.SupportedVersionsAsTags...,
			)
			Expect(data).To(Equal(expected))
			return nil
		}).ShouldNot(HaveOccurred())

		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	}, 1)

	It("setups and responds with error on invalid frame", func(done Done) {
		server, err := NewServer(testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := server.ListenAndServe("127.0.0.1:13370")
			Expect(err).To(HaveOccurred())
			close(done)
		}()

		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:13370")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error {
			_, err = conn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01, 0x00})
			if err != nil {
				return err
			}
			data := make([]byte, 1000)
			n, _, err := conn.ReadFromUDP(data)
			if err != nil {
				return err
			}
			Expect(n).ToNot(BeZero())
			return nil
		}).ShouldNot(HaveOccurred())

		time.Sleep(20 * time.Millisecond)
		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	}, 1)
})
