package quic

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	connectionID protocol.ConnectionID
	packetCount  int
	closed       bool
	closeReason  error
}

func (s *mockSession) handlePacket(*receivedPacket) {
	s.packetCount++
}

func (s *mockSession) run() {}
func (s *mockSession) Close(e error) error {
	s.closeReason = e
	s.closed = true
	return nil
}
func (s *mockSession) AcceptStream() (Stream, error) {
	panic("not implemented")
}
func (s *mockSession) OpenStream() (Stream, error) {
	return &stream{streamID: 1337}, nil
}
func (s *mockSession) OpenStreamSync() (Stream, error) {
	panic("not implemented")
}
func (s *mockSession) LocalAddr() net.Addr {
	panic("not implemented")
}
func (s *mockSession) RemoteAddr() net.Addr {
	panic("not implemented")
}

var _ Session = &mockSession{}

func newMockSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, closeCallback closeCallback, cryptoChangeCallback cryptoChangeCallback) (packetHandler, error) {
	return &mockSession{
		connectionID: connectionID,
	}, nil
}

var _ = Describe("Server", func() {
	var (
		conn    *mockPacketConn
		config  *Config
		udpAddr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	)

	BeforeEach(func() {
		conn = &mockPacketConn{}
		config = &Config{}
	})

	Context("with mock session", func() {
		var (
			serv        *server
			firstPacket []byte // a valid first packet for a new connection with connectionID 0x4cfa9f9b668619f6 (= connID)
			connID      = protocol.ConnectionID(0x4cfa9f9b668619f6)
		)

		BeforeEach(func() {
			serv = &server{
				sessions:   make(map[protocol.ConnectionID]packetHandler),
				newSession: newMockSession,
				conn:       conn,
				config:     config,
			}
			b := &bytes.Buffer{}
			utils.WriteUint32(b, protocol.VersionNumberToTag(protocol.SupportedVersions[0]))
			firstPacket = []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}
			firstPacket = append(append(firstPacket, b.Bytes()...), 0x01)
		})

		It("returns the address", func() {
			conn.addr = &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1234,
			}
			Expect(serv.Addr().String()).To(Equal("192.168.13.37:1234"))
		})

		It("composes version negotiation packets", func() {
			expected := append(
				[]byte{0x01 | 0x08, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				protocol.SupportedVersionsAsTags...,
			)
			Expect(composeVersionNegotiation(1)).To(Equal(expected))
		})

		It("creates new sessions", func() {
			var connStateCalled bool
			var connStateStatus ConnState
			var connStateSession Session
			config.ConnState = func(s Session, state ConnState) {
				connStateStatus = state
				connStateSession = s
				connStateCalled = true
			}
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			sess := serv.sessions[connID].(*mockSession)
			Expect(sess.connectionID).To(Equal(connID))
			Expect(sess.packetCount).To(Equal(1))
			Eventually(func() bool { return connStateCalled }).Should(BeTrue())
			Expect(connStateSession).To(Equal(sess))
			Expect(connStateStatus).To(Equal(ConnStateVersionNegotiated))
		})

		It("calls the ConnState callback when the connection is secure", func() {
			var connStateCalled bool
			var connStateStatus ConnState
			var connStateSession Session
			config.ConnState = func(s Session, state ConnState) {
				connStateStatus = state
				connStateSession = s
				connStateCalled = true
			}
			sess := &mockSession{}
			serv.cryptoChangeCallback(sess, false)
			Eventually(func() bool { return connStateCalled }).Should(BeTrue())
			Expect(connStateSession).To(Equal(sess))
			Expect(connStateStatus).To(Equal(ConnStateSecure))
		})

		It("calls the ConnState callback when the connection is forward-secure", func() {
			var connStateCalled bool
			var connStateStatus ConnState
			var connStateSession Session
			config.ConnState = func(s Session, state ConnState) {
				connStateStatus = state
				connStateSession = s
				connStateCalled = true
			}
			sess := &mockSession{}
			serv.cryptoChangeCallback(sess, true)
			Eventually(func() bool { return connStateCalled }).Should(BeTrue())
			Expect(connStateStatus).To(Equal(ConnStateForwardSecure))
			Expect(connStateSession).To(Equal(sess))
		})

		It("assigns packets to existing sessions", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			err = serv.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).connectionID).To(Equal(connID))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(2))
		})

		It("closes and deletes sessions", func() {
			serv.deleteClosedSessionsAfter = time.Second // make sure that the nil value for the closed session doesn't get deleted in this test
			nullAEAD := crypto.NewNullAEAD(protocol.PerspectiveServer, protocol.VersionWhatever)
			err := serv.handlePacket(nil, nil, append(firstPacket, nullAEAD.Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID]).ToNot(BeNil())
			serv.closeCallback(connID)
			// The server should now have closed the session, leaving a nil value in the sessions map
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID]).To(BeNil())
		})

		It("deletes nil session entries after a wait time", func() {
			serv.deleteClosedSessionsAfter = 25 * time.Millisecond
			nullAEAD := crypto.NewNullAEAD(protocol.PerspectiveServer, protocol.VersionWhatever)
			err := serv.handlePacket(nil, nil, append(firstPacket, nullAEAD.Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			serv.closeCallback(connID)
			Expect(serv.sessions).To(HaveKey(connID))
			Eventually(func() bool {
				serv.sessionsMutex.Lock()
				_, ok := serv.sessions[connID]
				serv.sessionsMutex.Unlock()
				return ok
			}).Should(BeFalse())
		})

		It("closes sessions and the connection when Close is called", func() {
			session := &mockSession{}
			serv.sessions[1] = session
			err := serv.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(session.closed).To(BeTrue())
			Expect(conn.closed).To(BeTrue())
		})

		It("ignores packets for closed sessions", func() {
			serv.sessions[connID] = nil
			err := serv.handlePacket(nil, nil, []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID]).To(BeNil())
		})

		It("closes properly", func() {
			ln, err := ListenAddr("127.0.0.1:0", config)
			Expect(err).ToNot(HaveOccurred())

			var returned bool
			go func() {
				defer GinkgoRecover()
				err := ln.Serve()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("use of closed network connection"))
				returned = true
			}()
			ln.Close()
			Eventually(func() bool { return returned }).Should(BeTrue())
		})

		It("errors when encountering a connection error", func() {
			testErr := errors.New("connection error")
			conn.readErr = testErr
			err := serv.Serve()
			Expect(err).To(MatchError(testErr))
		})

		It("ignores delayed packets with mismatching versions", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			b := &bytes.Buffer{}
			// add an unsupported version
			utils.WriteUint32(b, protocol.VersionNumberToTag(protocol.SupportedVersions[0]-2))
			data := []byte{0x09, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c}
			data = append(append(data, b.Bytes()...), 0x01)
			err = serv.handlePacket(nil, nil, data)
			Expect(err).ToNot(HaveOccurred())
			// if we didn't ignore the packet, the server would try to send a version negotation packet, which would make the test panic because it doesn't have a udpConn
			Expect(conn.dataWritten.Bytes()).To(BeEmpty())
			// make sure the packet was *not* passed to session.handlePacket()
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
		})

		It("errors on invalid public header", func() {
			err := serv.handlePacket(nil, nil, nil)
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
		})

		It("ignores public resets for unknown connections", func() {
			err := serv.handlePacket(nil, nil, writePublicReset(999, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(BeEmpty())
		})

		It("ignores public resets for known connections", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			err = serv.handlePacket(nil, nil, writePublicReset(connID, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
		})

		It("ignores invalid public resets for known connections", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			data := writePublicReset(connID, 1, 1337)
			err = serv.handlePacket(nil, nil, data[:len(data)-2])
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
		})

		It("doesn't respond with a version negotiation packet if the first packet is too small", func() {
			b := &bytes.Buffer{}
			hdr := PublicHeader{
				VersionFlag:     true,
				ConnectionID:    0x1337,
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			hdr.Write(b, 13 /* not a valid QUIC version */, protocol.PerspectiveClient)
			b.Write(bytes.Repeat([]byte{0}, protocol.ClientHelloMinimumSize-1)) // this packet is 1 byte too small
			err := serv.handlePacket(conn, udpAddr, b.Bytes())
			Expect(err).To(MatchError("dropping small packet with unknown version"))
			Expect(conn.dataWritten.Len()).Should(BeZero())
		})
	})

	It("setups with the right values", func() {
		config := Config{
			ConnState: func(_ Session, _ ConnState) {},
		}
		ln, err := Listen(conn, &config)
		server := ln.(*server)
		Expect(err).ToNot(HaveOccurred())
		Expect(server.deleteClosedSessionsAfter).To(Equal(protocol.ClosedSessionDeleteTimeout))
		Expect(server.sessions).ToNot(BeNil())
		Expect(server.scfg).ToNot(BeNil())
		Expect(server.config).To(Equal(&config))
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, config)
		Expect(err).ToNot(HaveOccurred())
		serv := ln.(*server)
		Expect(serv.Addr().String()).To(Equal(addr))
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, config)
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, config)
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})

	It("setups and responds with version negotiation", func() {
		b := &bytes.Buffer{}
		hdr := PublicHeader{
			VersionFlag:     true,
			ConnectionID:    0x1337,
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr.Write(b, 13 /* not a valid QUIC version */, protocol.PerspectiveClient)
		b.Write(bytes.Repeat([]byte{0}, protocol.ClientHelloMinimumSize)) // add a fake CHLO
		conn.dataToRead = b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, config)
		Expect(err).ToNot(HaveOccurred())

		var returned bool
		go func() {
			ln.Serve()
			returned = true
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		expected := append(
			[]byte{0x9, 0x37, 0x13, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			protocol.SupportedVersionsAsTags...,
		)
		Expect(conn.dataWritten.Bytes()).To(Equal(expected))
		Expect(returned).To(BeFalse())
	})

	It("sends a PublicReset for new connections that don't have the VersionFlag set", func() {
		conn.dataReadFrom = udpAddr
		conn.dataToRead = []byte{0x08, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x01}
		ln, err := Listen(conn, config)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			err := ln.Serve()
			Expect(err).ToNot(HaveOccurred())
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		Expect(conn.dataWritten.Bytes()[0] & 0x02).ToNot(BeZero()) // check that the ResetFlag is set
		Expect(ln.(*server).sessions).To(BeEmpty())
	})
})
