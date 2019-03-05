package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server", func() {
	var (
		conn    *mockPacketConn
		tlsConf *tls.Config
	)

	getPacket := func(hdr *wire.Header, data []byte) *receivedPacket {
		buf := &bytes.Buffer{}
		Expect((&wire.ExtendedHeader{
			Header:          *hdr,
			PacketNumberLen: protocol.PacketNumberLen3,
		}).Write(buf, protocol.VersionTLS)).To(Succeed())
		return &receivedPacket{
			data:   append(buf.Bytes(), data...),
			buffer: getPacketBuffer(),
		}
	}

	BeforeEach(func() {
		conn = newMockPacketConn()
		conn.addr = &net.UDPAddr{}
		tlsConf = testdata.GetTLSConfig()
	})

	It("errors when no tls.Config is given", func() {
		_, err := ListenAddr("localhost:0", nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("quic: Certificates not set in tls.Config"))
	})

	It("errors when no certificates are set in the tls.Config is given", func() {
		_, err := ListenAddr("localhost:0", &tls.Config{}, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("quic: Certificates not set in tls.Config"))
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(nil, tlsConf, &Config{Versions: []protocol.VersionNumber{version}})
		Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
	})

	It("fills in default values if options are not set in the Config", func() {
		ln, err := Listen(conn, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.config.Versions).To(Equal(protocol.SupportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
		Expect(server.config.IdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(defaultAcceptCookie)))
		Expect(server.config.KeepAlive).To(BeFalse())
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{protocol.VersionTLS}
		acceptCookie := func(_ net.Addr, _ *Cookie) bool { return true }
		config := Config{
			Versions:         supportedVersions,
			AcceptCookie:     acceptCookie,
			HandshakeTimeout: 1337 * time.Hour,
			IdleTimeout:      42 * time.Minute,
			KeepAlive:        true,
		}
		ln, err := Listen(conn, tlsConf, &config)
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*server)
		Expect(server.sessionHandler).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.IdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.AcceptCookie)).To(Equal(reflect.ValueOf(acceptCookie)))
		Expect(server.config.KeepAlive).To(BeTrue())
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		serv := ln.(*server)
		Expect(serv.Addr().String()).To(Equal(addr))
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})

	Context("handling packets", func() {
		var serv *server

		BeforeEach(func() {
			ln, err := Listen(conn, tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			serv = ln.(*server)
		})

		parseHeader := func(data []byte) *wire.Header {
			hdr, _, _, err := wire.ParsePacket(data, 0)
			Expect(err).ToNot(HaveOccurred())
			return hdr
		}

		It("drops Initial packets with a too short connection ID", func() {
			serv.handlePacket(getPacket(&wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
				Version:          serv.config.Versions[0],
			}, nil))
			Consistently(conn.dataWritten).ShouldNot(Receive())
		})

		It("drops too small Initial", func() {
			serv.handlePacket(getPacket(&wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				Version:          serv.config.Versions[0],
			}, make([]byte, protocol.MinInitialPacketSize-100),
			))
			Consistently(conn.dataWritten).ShouldNot(Receive())
		})

		It("drops packets with a too short connection ID", func() {
			serv.handlePacket(getPacket(&wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
				Version:          serv.config.Versions[0],
			}, make([]byte, protocol.MinInitialPacketSize)))
			Consistently(conn.dataWritten).ShouldNot(Receive())
		})

		It("drops non-Initial packets", func() {
			serv.handlePacket(getPacket(
				&wire.Header{
					Type:    protocol.PacketTypeHandshake,
					Version: serv.config.Versions[0],
				},
				[]byte("invalid"),
			))
		})

		It("decodes the cookie from the Token field", func() {
			raddr := &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1337,
			}
			done := make(chan struct{})
			serv.config.AcceptCookie = func(addr net.Addr, cookie *Cookie) bool {
				Expect(addr).To(Equal(raddr))
				Expect(cookie).ToNot(BeNil())
				close(done)
				return false
			}
			token, err := serv.cookieGenerator.NewToken(raddr, nil)
			Expect(err).ToNot(HaveOccurred())
			packet := getPacket(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeInitial,
				Token:        token,
				Version:      serv.config.Versions[0],
			}, make([]byte, protocol.MinInitialPacketSize))
			packet.remoteAddr = raddr
			serv.handlePacket(packet)
			Eventually(done).Should(BeClosed())
		})

		It("passes an empty cookie to the callback, if decoding fails", func() {
			raddr := &net.UDPAddr{
				IP:   net.IPv4(192, 168, 13, 37),
				Port: 1337,
			}
			done := make(chan struct{})
			serv.config.AcceptCookie = func(addr net.Addr, cookie *Cookie) bool {
				Expect(addr).To(Equal(raddr))
				Expect(cookie).To(BeNil())
				close(done)
				return false
			}
			packet := getPacket(&wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeInitial,
				Token:        []byte("foobar"),
				Version:      serv.config.Versions[0],
			}, make([]byte, protocol.MinInitialPacketSize))
			packet.remoteAddr = raddr
			serv.handlePacket(packet)
			Eventually(done).Should(BeClosed())
		})

		It("sends a Version Negotiation Packet for unsupported versions", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
			destConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6}
			packet := getPacket(&wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  srcConnID,
				DestConnectionID: destConnID,
				Version:          0x42,
			}, make([]byte, protocol.MinInitialPacketSize))
			packet.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			serv.handlePacket(packet)
			var write mockPacketConnWrite
			Eventually(conn.dataWritten).Should(Receive(&write))
			Expect(write.to.String()).To(Equal("127.0.0.1:1337"))
			Expect(wire.IsVersionNegotiationPacket(write.data)).To(BeTrue())
			hdr := parseHeader(write.data)
			Expect(hdr.DestConnectionID).To(Equal(srcConnID))
			Expect(hdr.SrcConnectionID).To(Equal(destConnID))
			Expect(hdr.SupportedVersions).ToNot(ContainElement(protocol.VersionNumber(0x42)))
		})

		It("replies with a Retry packet, if a Cookie is required", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return false }
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
			packet.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			serv.handlePacket(packet)
			var write mockPacketConnWrite
			Eventually(conn.dataWritten).Should(Receive(&write))
			Expect(write.to.String()).To(Equal("127.0.0.1:1337"))
			replyHdr := parseHeader(write.data)
			Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
			Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
			Expect(replyHdr.OrigDestConnectionID).To(Equal(hdr.DestConnectionID))
			Expect(replyHdr.Token).ToNot(BeEmpty())
		})

		It("creates a session, if no Cookie is required", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return true }
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
			run := make(chan struct{})
			serv.newSession = func(
				_ connection,
				_ sessionRunner,
				origConnID protocol.ConnectionID,
				destConnID protocol.ConnectionID,
				srcConnID protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				Expect(origConnID).To(Equal(hdr.DestConnectionID))
				Expect(destConnID).To(Equal(hdr.SrcConnectionID))
				// make sure we're using a server-generated connection ID
				Expect(srcConnID).ToNot(Equal(hdr.DestConnectionID))
				Expect(srcConnID).ToNot(Equal(hdr.SrcConnectionID))
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().handlePacket(p)
				sess.EXPECT().run().Do(func() { close(run) })
				return sess, nil
			}

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.handlePacket(p)
				// the Handshake packet is written by the session
				Consistently(conn.dataWritten).ShouldNot(Receive())
				close(done)
			}()
			// make sure we're using a server-generated connection ID
			Eventually(run).Should(BeClosed())
			Eventually(done).Should(BeClosed())
		})

		It("rejects new connection attempts if the accept queue is full", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return true }
			senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}

			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
			p.remoteAddr = senderAddr
			serv.newSession = func(
				_ connection,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().handlePacket(p)
				sess.EXPECT().run()
				sess.EXPECT().Context().Return(context.Background())
				runner.OnHandshakeComplete(sess)
				return sess, nil
			}

			var wg sync.WaitGroup
			wg.Add(protocol.MaxAcceptQueueSize)
			for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					serv.handlePacket(p)
					Consistently(conn.dataWritten).ShouldNot(Receive())
				}()
			}
			wg.Wait()
			serv.handlePacket(p)
			var reject mockPacketConnWrite
			Eventually(conn.dataWritten).Should(Receive(&reject))
			Expect(reject.to).To(Equal(senderAddr))
			rejectHdr := parseHeader(reject.data)
			Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
			Expect(rejectHdr.Version).To(Equal(hdr.Version))
			Expect(rejectHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
			Expect(rejectHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
		})

		It("doesn't accept new sessions if they were closed in the mean time", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return true }
			senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}

			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
			p.remoteAddr = senderAddr
			ctx, cancel := context.WithCancel(context.Background())
			sessionCreated := make(chan struct{})
			sess := NewMockQuicSession(mockCtrl)
			serv.newSession = func(
				_ connection,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				sess.EXPECT().handlePacket(p)
				sess.EXPECT().run()
				sess.EXPECT().Context().Return(ctx)
				runner.OnHandshakeComplete(sess)
				close(sessionCreated)
				return sess, nil
			}

			serv.handlePacket(p)
			Consistently(conn.dataWritten).ShouldNot(Receive())
			Eventually(sessionCreated).Should(BeClosed())
			cancel()
			time.Sleep(scaleDuration(200 * time.Millisecond))

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.Accept()
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())

			// make the go routine return
			sess.EXPECT().getPerspective()
			Expect(serv.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})
	})

	Context("accepting sessions", func() {
		var serv *server

		BeforeEach(func() {
			ln, err := Listen(conn, tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			serv = ln.(*server)
		})

		It("returns Accept when an error occurs", func() {
			testErr := errors.New("test err")

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serv.Accept()
				Expect(err).To(MatchError(testErr))
				close(done)
			}()

			Expect(serv.closeWithError(testErr)).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("returns immediately, if an error occurred before", func() {
			testErr := errors.New("test err")
			Expect(serv.closeWithError(testErr)).To(Succeed())
			for i := 0; i < 3; i++ {
				_, err := serv.Accept()
				Expect(err).To(MatchError(testErr))
			}
		})

		It("accepts new sessions when the handshake completes", func() {
			sess := NewMockQuicSession(mockCtrl)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := serv.Accept()
				Expect(err).ToNot(HaveOccurred())
				Expect(s).To(Equal(sess))
				close(done)
			}()

			completeHandshake := make(chan struct{})
			serv.newSession = func(
				_ connection,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				go func() {
					<-completeHandshake
					runner.OnHandshakeComplete(sess)
				}()
				sess.EXPECT().run().Do(func() {})
				sess.EXPECT().Context().Return(context.Background())
				return sess, nil
			}
			_, err := serv.createNewSession(&net.UDPAddr{}, nil, nil, nil, nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Consistently(done).ShouldNot(BeClosed())
			close(completeHandshake)
			Eventually(done).Should(BeClosed())
		})

		It("never blocks when calling the onHandshakeComplete callback", func() {
			const num = 50

			done := make(chan struct{}, num)
			serv.newSession = func(
				_ connection,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TransportParameters,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) (quicSession, error) {
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().run().Do(func() {})
				sess.EXPECT().Context().Return(context.Background())
				runner.OnHandshakeComplete(sess)
				done <- struct{}{}
				return sess, nil
			}

			go func() {
				for i := 0; i < num; i++ {
					_, err := serv.createNewSession(&net.UDPAddr{}, nil, nil, nil, nil, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
				}
			}()
			Eventually(done).Should(HaveLen(num))
		})
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
