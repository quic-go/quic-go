package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	connectionID  protocol.ConnectionID
	packetCount   int
	closed        bool
	closeReason   error
	closedRemote  bool
	stopRunLoop   chan struct{} // run returns as soon as this channel receives a value
	handshakeChan chan error
}

func (s *mockSession) handlePacket(*receivedPacket) {
	s.packetCount++
}

func (s *mockSession) run() error {
	<-s.stopRunLoop
	return s.closeReason
}
func (s *mockSession) Close(e error) error {
	if s.closed {
		return nil
	}
	s.closeReason = e
	s.closed = true
	close(s.stopRunLoop)
	return nil
}
func (s *mockSession) closeRemote(e error) {
	s.closeReason = e
	s.closed = true
	s.closedRemote = true
	close(s.stopRunLoop)
}
func (s *mockSession) OpenStream() (Stream, error) {
	return &stream{}, nil
}
func (s *mockSession) AcceptStream() (Stream, error)    { panic("not implemented") }
func (s *mockSession) OpenStreamSync() (Stream, error)  { panic("not implemented") }
func (s *mockSession) LocalAddr() net.Addr              { panic("not implemented") }
func (s *mockSession) RemoteAddr() net.Addr             { panic("not implemented") }
func (*mockSession) Context() context.Context           { panic("not implemented") }
func (*mockSession) ConnectionState() ConnectionState   { panic("not implemented") }
func (*mockSession) GetVersion() protocol.VersionNumber { return protocol.VersionWhatever }
func (s *mockSession) handshakeStatus() <-chan error    { return s.handshakeChan }
func (*mockSession) getCryptoStream() cryptoStreamI     { panic("not implemented") }

var _ Session = &mockSession{}

func newMockSession(
	_ connection,
	_ protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	_ *handshake.ServerConfig,
	_ *tls.Config,
	_ *Config,
) (packetHandler, error) {
	s := mockSession{
		connectionID:  connectionID,
		handshakeChan: make(chan error),
		stopRunLoop:   make(chan struct{}),
	}
	return &s, nil
}

var _ = Describe("Server", func() {
	var (
		conn    *mockPacketConn
		config  *Config
		udpAddr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	)

	BeforeEach(func() {
		conn = newMockPacketConn()
		conn.addr = &net.UDPAddr{}
		config = &Config{Versions: protocol.SupportedVersions}
	})

	Context("with mock session", func() {
		var (
			serv        *server
			firstPacket []byte // a valid first packet for a new connection with connectionID 0x4cfa9f9b668619f6 (= connID)
			connID      = protocol.ConnectionID(0x4cfa9f9b668619f6)
		)

		BeforeEach(func() {
			serv = &server{
				sessions:     make(map[protocol.ConnectionID]packetHandler),
				newSession:   newMockSession,
				conn:         conn,
				config:       config,
				sessionQueue: make(chan Session, 5),
				errorChan:    make(chan struct{}),
			}
			b := &bytes.Buffer{}
			utils.BigEndian.WriteUint32(b, uint32(protocol.SupportedVersions[0]))
			firstPacket = []byte{0x09, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			firstPacket = append(append(firstPacket, b.Bytes()...), 0x01)
			firstPacket = append(firstPacket, bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)...) // add padding
		})

		It("returns the address", func() {
			conn.addr = &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1234,
			}
			Expect(serv.Addr().String()).To(Equal("192.168.13.37:1234"))
		})

		It("creates new sessions", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			sess := serv.sessions[connID].(*mockSession)
			Expect(sess.connectionID).To(Equal(connID))
			Expect(sess.packetCount).To(Equal(1))
		})

		It("accepts a session once the connection it is forward secure", func(done Done) {
			var acceptedSess Session
			go func() {
				defer GinkgoRecover()
				var err error
				acceptedSess, err = serv.Accept()
				Expect(err).ToNot(HaveOccurred())
			}()
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			sess := serv.sessions[connID].(*mockSession)
			Consistently(func() Session { return acceptedSess }).Should(BeNil())
			close(sess.handshakeChan)
			Eventually(func() Session { return acceptedSess }).Should(Equal(sess))
			close(done)
		}, 0.5)

		It("doesn't accept session that error during the handshake", func(done Done) {
			var accepted bool
			go func() {
				defer GinkgoRecover()
				serv.Accept()
				accepted = true
			}()
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			sess := serv.sessions[connID].(*mockSession)
			sess.handshakeChan <- errors.New("handshake failed")
			Consistently(func() bool { return accepted }).Should(BeFalse())
			close(done)
		})

		It("assigns packets to existing sessions", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			err = serv.handlePacket(nil, nil, []byte{0x08, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).connectionID).To(Equal(connID))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(2))
		})

		It("closes and deletes sessions", func() {
			serv.deleteClosedSessionsAfter = time.Second // make sure that the nil value for the closed session doesn't get deleted in this test
			nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			err = serv.handlePacket(nil, nil, append(firstPacket, nullAEAD.Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID]).ToNot(BeNil())
			// make session.run() return
			serv.sessions[connID].(*mockSession).stopRunLoop <- struct{}{}
			// The server should now have closed the session, leaving a nil value in the sessions map
			Consistently(func() map[protocol.ConnectionID]packetHandler { return serv.sessions }).Should(HaveLen(1))
			Expect(serv.sessions[connID]).To(BeNil())
		})

		It("deletes nil session entries after a wait time", func() {
			serv.deleteClosedSessionsAfter = 25 * time.Millisecond
			nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			err = serv.handlePacket(nil, nil, append(firstPacket, nullAEAD.Seal(nil, nil, 0, firstPacket)...))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions).To(HaveKey(connID))
			// make session.run() return
			serv.sessions[connID].(*mockSession).stopRunLoop <- struct{}{}
			Eventually(func() bool {
				serv.sessionsMutex.Lock()
				_, ok := serv.sessions[connID]
				serv.sessionsMutex.Unlock()
				return ok
			}).Should(BeFalse())
		})

		It("closes sessions and the connection when Close is called", func() {
			go serv.serve()
			session, _ := newMockSession(nil, 0, 0, nil, nil, nil)
			serv.sessions[1] = session
			err := serv.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(session.(*mockSession).closed).To(BeTrue())
			Expect(conn.closed).To(BeTrue())
		})

		It("ignores packets for closed sessions", func() {
			serv.sessions[connID] = nil
			err := serv.handlePacket(nil, nil, []byte{0x08, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6, 0x01})
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID]).To(BeNil())
		})

		It("works if no quic.Config is given", func(done Done) {
			ln, err := ListenAddr("127.0.0.1:0", testdata.GetTLSConfig(), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ln.Close()).To(Succeed())
			close(done)
		}, 1)

		It("closes properly", func() {
			ln, err := ListenAddr("127.0.0.1:0", testdata.GetTLSConfig(), config)
			Expect(err).ToNot(HaveOccurred())

			var returned bool
			go func() {
				defer GinkgoRecover()
				_, err := ln.Accept()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("use of closed network connection"))
				returned = true
			}()
			ln.Close()
			Eventually(func() bool { return returned }).Should(BeTrue())
		})

		It("errors when encountering a connection error", func(done Done) {
			testErr := errors.New("connection error")
			conn.readErr = testErr
			go serv.serve()
			_, err := serv.Accept()
			Expect(err).To(MatchError(testErr))
			Expect(serv.Close()).To(Succeed())
			close(done)
		}, 0.5)

		It("closes all sessions when encountering a connection error", func() {
			session, _ := newMockSession(nil, 0, 0, nil, nil, nil)
			serv.sessions[0x12345] = session
			Expect(serv.sessions[0x12345].(*mockSession).closed).To(BeFalse())
			testErr := errors.New("connection error")
			conn.readErr = testErr
			go serv.serve()
			Eventually(func() Session { return serv.sessions[connID] }).Should(BeNil())
			Eventually(func() bool { return session.(*mockSession).closed }).Should(BeTrue())
			Expect(serv.Close()).To(Succeed())
		})

		It("ignores delayed packets with mismatching versions", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			b := &bytes.Buffer{}
			// add an unsupported version
			data := []byte{0x09, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			utils.BigEndian.WriteUint32(b, uint32(protocol.SupportedVersions[0]+1))
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
			err := serv.handlePacket(nil, nil, wire.WritePublicReset(999, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(BeEmpty())
		})

		It("ignores public resets for known connections", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			err = serv.handlePacket(nil, nil, wire.WritePublicReset(connID, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
		})

		It("ignores invalid public resets for known connections", func() {
			err := serv.handlePacket(nil, nil, firstPacket)
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
			data := wire.WritePublicReset(connID, 1, 1337)
			err = serv.handlePacket(nil, nil, data[:len(data)-2])
			Expect(err).ToNot(HaveOccurred())
			Expect(serv.sessions).To(HaveLen(1))
			Expect(serv.sessions[connID].(*mockSession).packetCount).To(Equal(1))
		})

		It("doesn't try to process a packet after sending a gQUIC Version Negotiation Packet", func() {
			config.Versions = []protocol.VersionNumber{99}
			b := &bytes.Buffer{}
			hdr := wire.Header{
				VersionFlag:     true,
				ConnectionID:    0x1337,
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)
			b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)) // add a fake CHLO
			err := serv.handlePacket(conn, nil, b.Bytes())
			Expect(conn.dataWritten.Bytes()).ToNot(BeEmpty())
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't respond with a version negotiation packet if the first packet is too small", func() {
			b := &bytes.Buffer{}
			hdr := wire.Header{
				VersionFlag:     true,
				ConnectionID:    0x1337,
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)
			b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize-1)) // this packet is 1 byte too small
			err := serv.handlePacket(conn, udpAddr, b.Bytes())
			Expect(err).To(MatchError("dropping small packet with unknown version"))
			Expect(conn.dataWritten.Len()).Should(BeZero())
		})
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{1, 3, 5}
		acceptCookie := func(_ net.Addr, _ *Cookie) bool { return true }
		config := Config{
			Versions:         supportedVersions,
			AcceptCookie:     acceptCookie,
			HandshakeTimeout: 1337 * time.Hour,
			IdleTimeout:      42 * time.Minute,
			KeepAlive:        true,
		}
		ln, err := Listen(conn, &tls.Config{}, &config)
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.deleteClosedSessionsAfter).To(Equal(protocol.ClosedSessionDeleteTimeout))
		Expect(server.sessions).ToNot(BeNil())
		Expect(server.scfg).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.IdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(acceptCookie)))
		Expect(server.config.KeepAlive).To(BeTrue())
	})

	It("fills in default values if options are not set in the Config", func() {
		ln, err := Listen(conn, &tls.Config{}, &Config{})
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.config.Versions).To(Equal(protocol.SupportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
		Expect(server.config.IdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(defaultAcceptCookie)))
		Expect(server.config.KeepAlive).To(BeFalse())
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, nil, config)
		Expect(err).ToNot(HaveOccurred())
		serv := ln.(*server)
		Expect(serv.Addr().String()).To(Equal(addr))
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, nil, config)
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, nil, config)
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})

	It("sends a gQUIC Version Negotaion Packet, if the client sent a gQUIC Public Header", func() {
		config.Versions = []protocol.VersionNumber{99}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			VersionFlag:     true,
			ConnectionID:    0x1337,
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)
		b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)) // add a fake CHLO
		conn.dataToRead <- b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, nil, config)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			ln.Accept()
			close(done)
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		r := bytes.NewReader(conn.dataWritten.Bytes())
		packet, err := wire.ParseHeaderSentByServer(r, protocol.VersionUnknown)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.VersionFlag).To(BeTrue())
		Expect(packet.ConnectionID).To(Equal(protocol.ConnectionID(0x1337)))
		Expect(r.Len()).To(BeZero())
		Consistently(done).ShouldNot(BeClosed())
		// make the go routine return
		ln.Close()
		Eventually(done).Should(BeClosed())
	})

	It("sends an IETF draft style Version Negotaion Packet, if the client sent a IETF draft style header", func() {
		config.Versions = []protocol.VersionNumber{99, protocol.VersionTLS}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			Type:         protocol.PacketTypeInitial,
			IsLongHeader: true,
			ConnectionID: 0x1337,
			PacketNumber: 0x55,
			Version:      0x1234,
		}
		err := hdr.Write(b, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		b.Write(bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize)) // add a fake CHLO
		conn.dataToRead <- b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, testdata.GetTLSConfig(), config)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			ln.Accept()
			close(done)
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		r := bytes.NewReader(conn.dataWritten.Bytes())
		packet, err := wire.ParseHeaderSentByServer(r, protocol.VersionUnknown)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.IsVersionNegotiation).To(BeTrue())
		Expect(packet.ConnectionID).To(Equal(protocol.ConnectionID(0x1337)))
		Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(0x55)))
		Expect(r.Len()).To(BeZero())
		Consistently(done).ShouldNot(BeClosed())
	})

	It("ignores IETF draft style Initial packets, if it doesn't support TLS", func() {
		version := protocol.VersionNumber(99)
		Expect(version.UsesTLS()).To(BeFalse())
		config.Versions = []protocol.VersionNumber{version}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			Type:         protocol.PacketTypeInitial,
			IsLongHeader: true,
			ConnectionID: 0x1337,
			PacketNumber: 0x55,
			Version:      protocol.VersionTLS,
		}
		err := hdr.Write(b, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)) // add a fake CHLO
		conn.dataToRead <- b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, testdata.GetTLSConfig(), config)
		defer ln.Close()
		Expect(err).ToNot(HaveOccurred())
		Consistently(func() int { return conn.dataWritten.Len() }).Should(BeZero())
	})

	It("sends a PublicReset for new connections that don't have the VersionFlag set", func() {
		conn.dataReadFrom = udpAddr
		conn.dataToRead <- []byte{0x08, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6, 0x01}
		ln, err := Listen(conn, nil, config)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			_, err := ln.Accept()
			Expect(err).ToNot(HaveOccurred())
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		Expect(conn.dataWritten.Bytes()[0] & 0x02).ToNot(BeZero()) // check that the ResetFlag is set
		Expect(ln.(*server).sessions).To(BeEmpty())
	})
})

var _ = Describe("default source address verification", func() {
	It("accepts a token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1",
			SentTime:   time.Now().Add(-protocol.CookieExpiryTime).Add(time.Second), // will expire in 1 second
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeTrue())
	})

	It("requests verification if no token is provided", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		Expect(defaultAcceptCookie(remoteAddr, nil)).To(BeFalse())
	})

	It("rejects a token if the address doesn't match", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "127.0.0.1",
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})

	It("accepts a token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1:1337",
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeTrue())
	})

	It("rejects an invalid token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1:7331", // mismatching port
			SentTime:   time.Now(),
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})

	It("rejects an expired token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		cookie := &Cookie{
			RemoteAddr: "192.168.0.1",
			SentTime:   time.Now().Add(-protocol.CookieExpiryTime).Add(-time.Second), // expired 1 second ago
		}
		Expect(defaultAcceptCookie(remoteAddr, cookie)).To(BeFalse())
	})
})
