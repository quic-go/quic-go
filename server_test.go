package quic

import (
	"bytes"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	connectionID protocol.ConnectionID
	packetCount  int
	closed       bool
}

func (s *mockSession) handlePacket(*receivedPacket) {
	s.packetCount++
}

func (s *mockSession) run()              {}
func (s *mockSession) Close(error) error { s.closed = true; return nil }

func newMockSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback closeCallback) (packetHandler, error) {
	return &mockSession{
		connectionID: connectionID,
	}, nil
}

var _ = Describe("Server", func() {
	Describe("with mock session", func() {
		var (
			server      *Server
			firstPacket []byte // a valid first packet for a new connection with connectionID 0x4cfa9f9b668619f6
		)

		BeforeEach(func() {
			server = &Server{
				sessions:   map[protocol.ConnectionID]packetHandler{},
				newSession: newMockSession,
			}
			b := &bytes.Buffer{}
			utils.WriteUint32(b, protocol.VersionNumberToTag(protocol.SupportedVersions[0]))
			firstPacket = []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}
			firstPacket = append(append(firstPacket, b.Bytes()...), 0x01)
		})

		It("composes version negotiation packets", func() {
			expected := append(
				[]byte{0x01 | 0x08, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				protocol.SupportedVersionsAsTags...,
			)
			Expect(composeVersionNegotiation(1)).To(Equal(expected))
		})

		It("creates new sessions", func() {
			err := server.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
		})

		It("assigns packets to existing sessions", func() {
			err := server.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			err = server.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).connectionID).To(Equal(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(2))
		})

		It("closes and deletes sessions", func() {
			err := server.handlePacket(nil, nil, append(firstPacket, (&crypto.NullAEAD{}).Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6]).ToNot(BeNil())
			server.closeCallback(0x4cfa9f9b668619f6)
			// The server should now have closed the session, leaving a nil value in the sessions map
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6]).To(BeNil())
		})

		It("deletes nil session entries after a wait time", func() {
			server.deleteClosedSessionsAfter = 25 * time.Millisecond
			err := server.handlePacket(nil, nil, append(firstPacket, (&crypto.NullAEAD{}).Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			server.closeCallback(0x4cfa9f9b668619f6)
			Expect(server.sessions).To(HaveKey(protocol.ConnectionID(0x4cfa9f9b668619f6)))
			Eventually(func() map[protocol.ConnectionID]packetHandler { return server.sessions }).ShouldNot(HaveKey(protocol.ConnectionID(0x4cfa9f9b668619f6)))
		})

		It("closes sessions when Close is called", func() {
			session := &mockSession{}
			server.sessions[1] = session
			err := server.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(session.closed).To(BeTrue())
		})

		It("ignores packets for closed sessions", func() {
			server.sessions[0x4cfa9f9b668619f6] = nil
			err := server.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6]).To(BeNil())
		})

		It("ignores delayed packets with mismatching versions", func() {
			err := server.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
			b := &bytes.Buffer{}
			// add an unsupported version
			utils.WriteUint32(b, protocol.VersionNumberToTag(protocol.SupportedVersions[0]-2))
			data := []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}
			data = append(append(data, b.Bytes()...), 0x01)
			err = server.handlePacket(nil, nil, data)
			Expect(err).ToNot(HaveOccurred())
			// if we didn't ignore the packet, the server would try to send a version negotation packet, which would make the test panic because it doesn't have a udpConn
			// TODO: test that really doesn't send anything on the udpConn
			// make sure the packet was *not* passed to session.handlePacket()
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
		})

		It("errors on invalid public header", func() {
			err := server.handlePacket(nil, nil, nil)
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
		})

		It("errors on large packets", func() {
			err := server.handlePacket(nil, nil, bytes.Repeat([]byte{'a'}, int(protocol.MaxPacketSize)+1))
			Expect(err).To(MatchError(qerr.PacketTooLarge))
		})

		It("ignores public resets for unknown connections", func() {
			err := server.handlePacket(nil, nil, writePublicReset(999, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(BeEmpty())
		})

		It("ignores public resets for known connections", func() {
			err := server.handlePacket(nil, nil, firstPacket)
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
			err = server.handlePacket(nil, nil, writePublicReset(0x4cfa9f9b668619f6, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
		})

		It("ignores invalid public resets for known connections", func() {
			err := server.handlePacket(nil, nil, firstPacket)
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
			data := writePublicReset(0x4cfa9f9b668619f6, 1, 1337)
			err = server.handlePacket(nil, nil, data[:len(data)-2])
			Expect(err).ToNot(HaveOccurred())
			Expect(server.sessions).To(HaveLen(1))
			Expect(server.sessions[0x4cfa9f9b668619f6].(*mockSession).packetCount).To(Equal(1))
		})
	})

	It("setups with the right values", func() {
		server, err := NewServer("", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(server.deleteClosedSessionsAfter).To(Equal(protocol.ClosedSessionDeleteTimeout))
		Expect(server.sessions).ToNot(BeNil())
		Expect(server.scfg).ToNot(BeNil())
	})

	It("setups and responds with version negotiation", func(done Done) {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		server, err := NewServer("", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())

		serverConn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())

		addr = serverConn.LocalAddr().(*net.UDPAddr)

		go func() {
			defer GinkgoRecover()
			err2 := server.Serve(serverConn)
			Expect(err2).ToNot(HaveOccurred())
			close(done)
		}()

		clientConn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())

		_, err = clientConn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01})
		Expect(err).NotTo(HaveOccurred())
		data := make([]byte, 1000)
		var n int
		n, _, err = clientConn.ReadFromUDP(data)
		Expect(err).NotTo(HaveOccurred())
		data = data[:n]
		expected := append(
			[]byte{0x9, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			protocol.SupportedVersionsAsTags...,
		)
		Expect(data).To(Equal(expected))

		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	})

	It("sends a public reset for new connections that don't have the VersionFlag set", func(done Done) {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		server, err := NewServer("", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())

		serverConn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())

		addr = serverConn.LocalAddr().(*net.UDPAddr)

		go func() {
			defer GinkgoRecover()
			err2 := server.Serve(serverConn)
			Expect(err2).ToNot(HaveOccurred())
			close(done)
		}()

		clientConn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())

		_, err = clientConn.Write([]byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
		Expect(err).ToNot(HaveOccurred())
		data := make([]byte, 1000)
		var n int
		n, _, err = clientConn.ReadFromUDP(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).ToNot(BeZero())
		Expect(data[0] & 0x02).ToNot(BeZero()) // check that the ResetFlag is set
		Expect(server.sessions).To(BeEmpty())

		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	})

	It("setups and responds with error on invalid frame", func(done Done) {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		server, err := NewServer("", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())

		serverConn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())

		addr = serverConn.LocalAddr().(*net.UDPAddr)

		go func() {
			defer GinkgoRecover()
			err2 := server.Serve(serverConn)
			Expect(err2).ToNot(HaveOccurred())
			close(done)
		}()

		clientConn, err := net.DialUDP("udp", nil, addr)
		Expect(err).ToNot(HaveOccurred())

		_, err = clientConn.Write([]byte{0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 'Q', '0', '0', '0', 0x01, 0x00})
		Expect(err).NotTo(HaveOccurred())
		data := make([]byte, 1000)
		var n int
		n, _, err = clientConn.ReadFromUDP(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).ToNot(BeZero())

		err = server.Close()
		Expect(err).ToNot(HaveOccurred())
	})
})
