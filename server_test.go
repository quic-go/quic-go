package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server", func() {
	var conn *mockPacketConn

	BeforeEach(func() {
		conn = newMockPacketConn()
		conn.addr = &net.UDPAddr{}
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(nil, &tls.Config{}, &Config{Versions: []protocol.VersionNumber{version}})
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
		ln, err := Listen(conn, &tls.Config{}, &config)
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
		ln, err := ListenAddr(addr, nil, &Config{})
		Expect(err).ToNot(HaveOccurred())
		serv := ln.(*server)
		Expect(serv.Addr().String()).To(Equal(addr))
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, nil, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, nil, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})

	Context("handling packets", func() {
		var serv *server

		BeforeEach(func() {
			ln, err := Listen(conn, nil, nil)
			Expect(err).ToNot(HaveOccurred())
			serv = ln.(*server)
		})

		parseHeader := func(data []byte) *wire.Header {
			iHdr, err := wire.ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := iHdr.Parse(bytes.NewReader(data), protocol.VersionTLS)
			Expect(err).ToNot(HaveOccurred())
			return hdr
		}

		It("drops Initial packets with a too short connection ID", func() {
			serv.handlePacket(&receivedPacket{
				header: &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
					Version:          serv.config.Versions[0],
				},
			})
			Expect(conn.dataWritten.Len()).To(BeZero())
		})

		It("drops too small Initial", func() {
			serv.handlePacket(&receivedPacket{
				header: &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					Version:          serv.config.Versions[0],
				},
				data: bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize-100),
			})
			Consistently(conn.dataWritten.Len).Should(BeZero())
		})

		It("drops packets with a too short connection ID", func() {
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
				Version:          serv.config.Versions[0],
				PacketNumberLen:  protocol.PacketNumberLen1,
			}
			serv.handlePacket(&receivedPacket{
				header: hdr,
				data:   bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize),
			})
			Consistently(conn.dataWritten.Len).Should(BeZero())
		})

		It("drops non-Initial packets", func() {
			serv.logger.SetLogLevel(utils.LogLevelDebug)
			serv.handlePacket(&receivedPacket{
				header: &wire.Header{
					Type:    protocol.PacketTypeHandshake,
					Version: serv.config.Versions[0],
				},
				data: []byte("invalid"),
			})
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
			serv.handlePacket(&receivedPacket{
				remoteAddr: raddr,
				header: &wire.Header{
					Type:    protocol.PacketTypeInitial,
					Token:   token,
					Version: serv.config.Versions[0],
				},
				data: bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize),
			})
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
			serv.handlePacket(&receivedPacket{
				remoteAddr: raddr,
				header: &wire.Header{
					Type:    protocol.PacketTypeInitial,
					Token:   []byte("foobar"),
					Version: serv.config.Versions[0],
				},
				data: bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize),
			})
			Eventually(done).Should(BeClosed())
		})

		It("sends a Version Negotiation Packet for unsupported versions", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
			destConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6}
			serv.handlePacket(&receivedPacket{
				header: &wire.Header{
					IsLongHeader:     true,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Type:             protocol.PacketTypeInitial,
					Version:          0x42,
				},
			})
			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			hdr := parseHeader(conn.dataWritten.Bytes())
			Expect(hdr.IsVersionNegotiation).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(srcConnID))
			Expect(hdr.SrcConnectionID).To(Equal(destConnID))
			Expect(hdr.SupportedVersions).ToNot(ContainElement(protocol.VersionNumber(0x42)))
		})

		It("replies with a Retry packet, if a Cookie is required", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return false }
			hdr := &wire.Header{
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			serv.handleInitial(&receivedPacket{
				remoteAddr: &net.UDPAddr{},
				header:     hdr,
				data:       bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize),
			})
			Expect(conn.dataWritten.Len()).ToNot(BeZero())
			replyHdr := parseHeader(conn.dataWritten.Bytes())
			Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
			Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
			Expect(replyHdr.OrigDestConnectionID).To(Equal(hdr.DestConnectionID))
			Expect(replyHdr.Token).ToNot(BeEmpty())
		})

		It("creates a session, if no Cookie is required", func() {
			serv.config.AcceptCookie = func(_ net.Addr, _ *Cookie) bool { return true }
			hdr := &wire.Header{
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				Version:          protocol.VersionTLS,
			}
			p := &receivedPacket{
				header: hdr,
				data:   bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize),
			}
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
				Expect(conn.dataWritten.Len()).To(BeZero())
				close(done)
			}()
			// make sure we're using a server-generated connection ID
			Eventually(run).Should(BeClosed())
			Eventually(done).Should(BeClosed())
		})
	})

	Context("accepting sessions", func() {
		var serv *server

		BeforeEach(func() {
			ln, err := Listen(conn, nil, nil)
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
					runner.onHandshakeComplete(sess)
				}()
				sess.EXPECT().run().Do(func() {})
				return sess, nil
			}
			_, err := serv.createNewSession(&net.UDPAddr{}, nil, nil, nil, nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Consistently(done).ShouldNot(BeClosed())
			close(completeHandshake)
			Eventually(done).Should(BeClosed())
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
