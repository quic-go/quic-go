package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/golang/mock/gomock"
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
	*MockQuicSession

	connID protocol.ConnectionID
	runner sessionRunner
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

	Context("quic.Config", func() {
		It("setups with the right values", func() {
			config := &Config{
				HandshakeTimeout:            1337 * time.Minute,
				IdleTimeout:                 42 * time.Hour,
				RequestConnectionIDOmission: true,
				MaxIncomingStreams:          1234,
				MaxIncomingUniStreams:       4321,
				ConnectionIDLength:          12,
			}
			c := populateServerConfig(config)
			Expect(c.HandshakeTimeout).To(Equal(1337 * time.Minute))
			Expect(c.IdleTimeout).To(Equal(42 * time.Hour))
			Expect(c.RequestConnectionIDOmission).To(BeFalse())
			Expect(c.MaxIncomingStreams).To(Equal(1234))
			Expect(c.MaxIncomingUniStreams).To(Equal(4321))
			Expect(c.ConnectionIDLength).To(Equal(12))
		})

		It("disables bidirectional streams", func() {
			config := &Config{
				MaxIncomingStreams:    -1,
				MaxIncomingUniStreams: 4321,
			}
			c := populateServerConfig(config)
			Expect(c.MaxIncomingStreams).To(BeZero())
			Expect(c.MaxIncomingUniStreams).To(Equal(4321))
		})

		It("disables unidirectional streams", func() {
			config := &Config{
				MaxIncomingStreams:    1234,
				MaxIncomingUniStreams: -1,
			}
			c := populateServerConfig(config)
			Expect(c.MaxIncomingStreams).To(Equal(1234))
			Expect(c.MaxIncomingUniStreams).To(BeZero())
		})

		It("doesn't use 0-byte connection IDs", func() {
			config := &Config{}
			c := populateClientConfig(config, true)
			Expect(c.ConnectionIDLength).To(Equal(protocol.DefaultConnectionIDLength))
		})
	})

	Context("with mock session", func() {
		var (
			serv           *server
			firstPacket    []byte // a valid first packet for a new connection with connectionID 0x4cfa9f9b668619f6 (= connID)
			connID         = protocol.ConnectionID{0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			sessions       = make([]*MockQuicSession, 0)
			sessionHandler *MockPacketHandlerManager
		)

		BeforeEach(func() {
			sessionHandler = NewMockPacketHandlerManager(mockCtrl)
			newMockSession := func(
				_ connection,
				runner sessionRunner,
				_ protocol.VersionNumber,
				connID protocol.ConnectionID,
				_ *handshake.ServerConfig,
				_ *tls.Config,
				_ *Config,
				_ utils.Logger,
			) (quicSession, error) {
				ExpectWithOffset(0, sessions).ToNot(BeEmpty())
				s := &mockSession{MockQuicSession: sessions[0]}
				s.connID = connID
				s.runner = runner
				sessions = sessions[1:]
				return s, nil
			}
			serv = &server{
				sessionHandler: sessionHandler,
				newSession:     newMockSession,
				conn:           conn,
				config:         config,
				sessionQueue:   make(chan Session, 5),
				errorChan:      make(chan struct{}),
				logger:         utils.DefaultLogger,
			}
			serv.setup()
			b := &bytes.Buffer{}
			utils.BigEndian.WriteUint32(b, uint32(protocol.SupportedVersions[0]))
			firstPacket = []byte{0x09, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			firstPacket = append(append(firstPacket, b.Bytes()...), 0x01)
			firstPacket = append(firstPacket, bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)...) // add padding
		})

		AfterEach(func() {
			Expect(sessions).To(BeEmpty())
		})

		It("returns the address", func() {
			conn.addr = &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1234,
			}
			Expect(serv.Addr().String()).To(Equal("192.168.13.37:1234"))
		})

		It("creates new sessions", func() {
			s := NewMockQuicSession(mockCtrl)
			s.EXPECT().handlePacket(gomock.Any())
			run := make(chan struct{})
			s.EXPECT().run().Do(func() { close(run) })
			sessions = append(sessions, s)

			sessionHandler.EXPECT().Get(connID)
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(_ protocol.ConnectionID, sess packetHandler) {
				Expect(sess.(*mockSession).connID).To(Equal(connID))
			})
			err := serv.handlePacket(nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Eventually(run).Should(BeClosed())
		})

		It("accepts new TLS sessions", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			sess := NewMockQuicSession(mockCtrl)
			err := serv.setupTLS()
			Expect(err).ToNot(HaveOccurred())
			added := make(chan struct{})
			sessionHandler.EXPECT().Add(connID, sess).Do(func(protocol.ConnectionID, packetHandler) {
				close(added)
			})
			serv.serverTLS.sessionChan <- tlsSession{
				connID: connID,
				sess:   sess,
			}
			Eventually(added).Should(BeClosed())
		})

		It("accepts a session once the connection it is forward secure", func() {
			s := NewMockQuicSession(mockCtrl)
			s.EXPECT().handlePacket(gomock.Any())
			run := make(chan struct{})
			s.EXPECT().run().Do(func() { close(run) })
			sessions = append(sessions, s)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess, err := serv.Accept()
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.(*mockSession).connID).To(Equal(connID))
				close(done)
			}()
			sessionHandler.EXPECT().Get(connID)
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(_ protocol.ConnectionID, sess packetHandler) {
				Consistently(done).ShouldNot(BeClosed())
				sess.(*mockSession).runner.onHandshakeComplete(sess.(Session))
			})
			err := serv.handlePacket(nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Eventually(done).Should(BeClosed())
			Eventually(run).Should(BeClosed())
		})

		It("doesn't accept sessions that error during the handshake", func() {
			run := make(chan error, 1)
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().handlePacket(gomock.Any())
			sess.EXPECT().run().DoAndReturn(func() error { return <-run })
			sessions = append(sessions, sess)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.Accept()
				close(done)
			}()
			sessionHandler.EXPECT().Get(connID)
			sessionHandler.EXPECT().Add(connID, gomock.Any()).Do(func(_ protocol.ConnectionID, sess packetHandler) {
				run <- errors.New("handshake error")
			})
			err := serv.handlePacket(nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
			Consistently(done).ShouldNot(BeClosed())
			// make the go routine return
			sessionHandler.EXPECT().Close()
			close(serv.errorChan)
			serv.Close()
			Eventually(done).Should(BeClosed())
		})

		It("assigns packets to existing sessions", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().handlePacket(gomock.Any())
			sess.EXPECT().GetVersion()

			sessionHandler.EXPECT().Get(connID).Return(sess, true)
			err := serv.handlePacket(nil, []byte{0x08, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6, 0x01})
			Expect(err).ToNot(HaveOccurred())
		})

		It("closes the sessionHandler and the connection when Close is called", func() {
			go func() {
				defer GinkgoRecover()
				serv.serve()
			}()
			// close the server
			sessionHandler.EXPECT().Close().AnyTimes()
			Expect(serv.Close()).To(Succeed())
			Expect(conn.closed).To(BeTrue())
		})

		It("ignores packets for closed sessions", func() {
			sessionHandler.EXPECT().Get(connID).Return(nil, true)
			err := serv.handlePacket(nil, firstPacket)
			Expect(err).ToNot(HaveOccurred())
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

		It("errors when encountering a connection error", func() {
			testErr := errors.New("connection error")
			conn.readErr = testErr
			sessionHandler.EXPECT().Close()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.serve()
				close(done)
			}()
			_, err := serv.Accept()
			Expect(err).To(MatchError(testErr))
			Eventually(done).Should(BeClosed())
		})

		It("ignores delayed packets with mismatching versions", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().GetVersion()
			// don't EXPECT any handlePacket() calls to this session
			sessionHandler.EXPECT().Get(connID).Return(sess, true)

			b := &bytes.Buffer{}
			// add an unsupported version
			data := []byte{0x09, 0x4c, 0xfa, 0x9f, 0x9b, 0x66, 0x86, 0x19, 0xf6}
			utils.BigEndian.WriteUint32(b, uint32(protocol.SupportedVersions[0]+1))
			data = append(append(data, b.Bytes()...), 0x01)
			err := serv.handlePacket(nil, data)
			Expect(err).ToNot(HaveOccurred())
			// if we didn't ignore the packet, the server would try to send a version negotiation packet, which would make the test panic because it doesn't have a udpConn
			Expect(conn.dataWritten.Bytes()).To(BeEmpty())
		})

		It("errors on invalid public header", func() {
			err := serv.handlePacket(nil, nil)
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidPacketHeader))
		})

		It("errors on packets that are smaller than the Payload Length in the packet header", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().GetVersion().Return(protocol.VersionTLS)
			sessionHandler.EXPECT().Get(connID).Return(sess, true)

			serv.supportsTLS = true
			b := &bytes.Buffer{}
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PayloadLen:       1000,
				SrcConnectionID:  connID,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          versionIETFFrames,
			}
			Expect(hdr.Write(b, protocol.PerspectiveClient, versionIETFFrames)).To(Succeed())
			err := serv.handlePacket(nil, append(b.Bytes(), make([]byte, 456)...))
			Expect(err).To(MatchError("packet payload (456 bytes) is smaller than the expected payload length (1000 bytes)"))
		})

		It("cuts packets at the payload length", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().handlePacket(gomock.Any()).Do(func(packet *receivedPacket) {
				Expect(packet.data).To(HaveLen(123))
			})
			sess.EXPECT().GetVersion().Return(protocol.VersionTLS)
			sessionHandler.EXPECT().Get(connID).Return(sess, true)

			serv.supportsTLS = true
			b := &bytes.Buffer{}
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PayloadLen:       123,
				SrcConnectionID:  connID,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          versionIETFFrames,
			}
			Expect(hdr.Write(b, protocol.PerspectiveClient, versionIETFFrames)).To(Succeed())
			err := serv.handlePacket(nil, append(b.Bytes(), make([]byte, 456)...))
			Expect(err).ToNot(HaveOccurred())
		})

		It("drops packets with invalid packet types", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().GetVersion().Return(protocol.VersionTLS)
			sessionHandler.EXPECT().Get(connID).Return(sess, true)

			serv.supportsTLS = true
			b := &bytes.Buffer{}
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeRetry,
				PayloadLen:       123,
				SrcConnectionID:  connID,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          versionIETFFrames,
			}
			Expect(hdr.Write(b, protocol.PerspectiveClient, versionIETFFrames)).To(Succeed())
			err := serv.handlePacket(nil, append(b.Bytes(), make([]byte, 456)...))
			Expect(err).To(MatchError("Received unsupported packet type: Retry"))
		})

		It("ignores Public Resets", func() {
			sess := NewMockQuicSession(mockCtrl)
			sess.EXPECT().GetVersion().Return(protocol.VersionTLS)
			sessionHandler.EXPECT().Get(connID).Return(sess, true)

			err := serv.handlePacket(nil, wire.WritePublicReset(connID, 1, 1337))
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't try to process a packet after sending a gQUIC Version Negotiation Packet", func() {
			config.Versions = []protocol.VersionNumber{99}
			b := &bytes.Buffer{}
			hdr := wire.Header{
				VersionFlag:      true,
				DestConnectionID: connID,
				PacketNumber:     1,
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			Expect(hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)).To(Succeed())
			b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)) // add a fake CHLO
			serv.conn = conn
			sessionHandler.EXPECT().Get(connID)
			err := serv.handlePacket(nil, b.Bytes())
			Expect(conn.dataWritten.Bytes()).ToNot(BeEmpty())
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't respond with a version negotiation packet if the first packet is too small", func() {
			b := &bytes.Buffer{}
			hdr := wire.Header{
				VersionFlag:      true,
				DestConnectionID: connID,
				PacketNumber:     1,
				PacketNumberLen:  protocol.PacketNumberLen2,
			}
			Expect(hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)).To(Succeed())
			b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize-1)) // this packet is 1 byte too small
			serv.conn = conn
			sessionHandler.EXPECT().Get(connID)
			err := serv.handlePacket(udpAddr, b.Bytes())
			Expect(err).To(MatchError("dropping small packet with unknown version"))
			Expect(conn.dataWritten.Len()).Should(BeZero())
		})
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{protocol.VersionTLS, protocol.Version39}
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
		Expect(server.sessionHandler).ToNot(BeNil())
		Expect(server.scfg).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.IdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(acceptCookie)))
		Expect(server.config.KeepAlive).To(BeTrue())
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(conn, &tls.Config{}, &Config{Versions: []protocol.VersionNumber{version}})
		Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
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
		connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			VersionFlag:      true,
			DestConnectionID: connID,
			PacketNumber:     1,
			PacketNumberLen:  protocol.PacketNumberLen2,
		}
		Expect(hdr.Write(b, protocol.PerspectiveClient, 13 /* not a valid QUIC version */)).To(Succeed())
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
		iHdr, err := wire.ParseInvariantHeader(r, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(iHdr.IsLongHeader).To(BeFalse())
		replyHdr, err := iHdr.Parse(r, protocol.PerspectiveServer, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(replyHdr.IsVersionNegotiation).To(BeTrue())
		Expect(replyHdr.DestConnectionID).To(Equal(connID))
		Expect(r.Len()).To(BeZero())
		Consistently(done).ShouldNot(BeClosed())
		// make the go routine return
		ln.Close()
		Eventually(done).Should(BeClosed())
	})

	It("sends an IETF draft style Version Negotaion Packet, if the client sent a IETF draft style header", func() {
		connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		config.Versions = append(config.Versions, protocol.VersionTLS)
		b := &bytes.Buffer{}
		hdr := wire.Header{
			Type:             protocol.PacketTypeInitial,
			IsLongHeader:     true,
			DestConnectionID: connID,
			SrcConnectionID:  connID,
			PacketNumber:     0x55,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Version:          0x1234,
			PayloadLen:       protocol.MinInitialPacketSize,
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
			defer GinkgoRecover()
			ln.Accept()
			close(done)
		}()

		Eventually(func() int { return conn.dataWritten.Len() }).ShouldNot(BeZero())
		Expect(conn.dataWrittenTo).To(Equal(udpAddr))
		r := bytes.NewReader(conn.dataWritten.Bytes())
		iHdr, err := wire.ParseInvariantHeader(r, 0)
		Expect(err).ToNot(HaveOccurred())
		replyHdr, err := iHdr.Parse(r, protocol.PerspectiveServer, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(replyHdr.IsVersionNegotiation).To(BeTrue())
		Expect(replyHdr.DestConnectionID).To(Equal(connID))
		Expect(replyHdr.SrcConnectionID).To(Equal(connID))
		Expect(r.Len()).To(BeZero())
		Consistently(done).ShouldNot(BeClosed())
		// make the go routine return
		ln.Close()
		Eventually(done).Should(BeClosed())
	})

	It("ignores IETF draft style Initial packets, if it doesn't support TLS", func() {
		connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			Type:             protocol.PacketTypeInitial,
			IsLongHeader:     true,
			DestConnectionID: connID,
			SrcConnectionID:  connID,
			PacketNumber:     0x55,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Version:          protocol.VersionTLS,
		}
		err := hdr.Write(b, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		b.Write(bytes.Repeat([]byte{0}, protocol.MinClientHelloSize)) // add a fake CHLO
		conn.dataToRead <- b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, testdata.GetTLSConfig(), config)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		Consistently(func() int { return conn.dataWritten.Len() }).Should(BeZero())
	})

	It("ignores non-Initial Long Header packets for unknown connections", func() {
		connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		b := &bytes.Buffer{}
		hdr := wire.Header{
			Type:             protocol.PacketTypeHandshake,
			IsLongHeader:     true,
			DestConnectionID: connID,
			SrcConnectionID:  connID,
			PacketNumber:     0x55,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Version:          protocol.VersionTLS,
		}
		err := hdr.Write(b, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		conn.dataToRead <- b.Bytes()
		conn.dataReadFrom = udpAddr
		ln, err := Listen(conn, testdata.GetTLSConfig(), config)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
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
