package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Server", func() {
	var (
		conn    *MockPacketConn
		tlsConf *tls.Config
	)

	getPacket := func(hdr *wire.Header, p []byte) receivedPacket {
		buf := getPacketBuffer()
		hdr.Length = 4 + protocol.ByteCount(len(p)) + 16
		var err error
		buf.Data, err = (&wire.ExtendedHeader{
			Header:          *hdr,
			PacketNumber:    0x42,
			PacketNumberLen: protocol.PacketNumberLen4,
		}).Append(buf.Data, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		n := len(buf.Data)
		buf.Data = append(buf.Data, p...)
		data := buf.Data
		sealer, _ := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveClient, hdr.Version)
		_ = sealer.Seal(data[n:n], data[n:], 0x42, data[:n])
		data = data[:len(data)+16]
		sealer.EncryptHeader(data[n:n+16], &data[0], data[n-4:n])
		return receivedPacket{
			remoteAddr: &net.UDPAddr{IP: net.IPv4(4, 5, 6, 7), Port: 456},
			data:       data,
			buffer:     buf,
		}
	}

	getInitial := func(destConnID protocol.ConnectionID) receivedPacket {
		senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}
		hdr := &wire.Header{
			Type:             protocol.PacketTypeInitial,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
			DestConnectionID: destConnID,
			Version:          protocol.Version1,
		}
		p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
		p.buffer = getPacketBuffer()
		p.remoteAddr = senderAddr
		return p
	}

	getInitialWithRandomDestConnID := func() receivedPacket {
		b := make([]byte, 10)
		_, err := rand.Read(b)
		Expect(err).ToNot(HaveOccurred())

		return getInitial(protocol.ParseConnectionID(b))
	}

	parseHeader := func(data []byte) *wire.Header {
		hdr, _, _, err := wire.ParsePacket(data)
		Expect(err).ToNot(HaveOccurred())
		return hdr
	}

	BeforeEach(func() {
		conn = NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		wait := make(chan struct{})
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(_ []byte) (int, net.Addr, error) {
			<-wait
			return 0, nil, errors.New("done")
		}).MaxTimes(1)
		conn.EXPECT().SetReadDeadline(gomock.Any()).Do(func(time.Time) {
			close(wait)
			conn.EXPECT().SetReadDeadline(time.Time{})
		}).MaxTimes(1)
		tlsConf = testdata.GetTLSConfig()
		tlsConf.NextProtos = []string{"proto1"}
	})

	It("errors when no tls.Config is given", func() {
		_, err := ListenAddr("localhost:0", nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("quic: tls.Config not set"))
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(nil, tlsConf, &Config{Versions: []protocol.VersionNumber{version}})
		Expect(err).To(MatchError("invalid QUIC version: 0x1234"))
	})

	It("fills in default values if options are not set in the Config", func() {
		ln, err := Listen(conn, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		server := ln.baseServer
		Expect(server.config.Versions).To(Equal(protocol.SupportedVersions))
		Expect(server.config.HandshakeIdleTimeout).To(Equal(protocol.DefaultHandshakeIdleTimeout))
		Expect(server.config.MaxIdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
		Expect(server.config.RequireAddressValidation).ToNot(BeNil())
		Expect(server.config.KeepAlivePeriod).To(BeZero())
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{protocol.Version1}
		requireAddrVal := func(net.Addr) bool { return true }
		config := Config{
			Versions:                 supportedVersions,
			HandshakeIdleTimeout:     1337 * time.Hour,
			MaxIdleTimeout:           42 * time.Minute,
			KeepAlivePeriod:          5 * time.Second,
			RequireAddressValidation: requireAddrVal,
		}
		ln, err := Listen(conn, tlsConf, &config)
		Expect(err).ToNot(HaveOccurred())
		server := ln.baseServer
		Expect(server.connHandler).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeIdleTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.MaxIdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.RequireAddressValidation)).To(Equal(reflect.ValueOf(requireAddrVal)))
		Expect(server.config.KeepAlivePeriod).To(Equal(5 * time.Second))
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		Expect(ln.Addr().String()).To(Equal(addr))
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

	Context("server accepting connections that completed the handshake", func() {
		var (
			tr     *Transport
			serv   *baseServer
			phm    *MockPacketHandlerManager
			tracer *mocklogging.MockTracer
		)

		BeforeEach(func() {
			var t *logging.Tracer
			t, tracer = mocklogging.NewMockTracer(mockCtrl)
			tr = &Transport{Conn: conn, Tracer: t}
			ln, err := tr.Listen(tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			serv = ln.baseServer
			phm = NewMockPacketHandlerManager(mockCtrl)
			serv.connHandler = phm
		})

		AfterEach(func() {
			tr.Close()
		})

		Context("handling packets", func() {
			It("drops Initial packets with a too short connection ID", func() {
				p := getPacket(&wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					Version:          serv.config.Versions[0],
				}, nil)
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("drops too small Initial", func() {
				p := getPacket(&wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Version:          serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize-100))
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("drops non-Initial packets", func() {
				p := getPacket(&wire.Header{
					Type:    protocol.PacketTypeHandshake,
					Version: serv.config.Versions[0],
				}, []byte("invalid"))
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeHandshake, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("passes packets to existing connections", func() {
				connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
				p := getPacket(&wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: connID,
					Version:          serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize))
				conn := NewMockPacketHandler(mockCtrl)
				phm.EXPECT().Get(connID).Return(conn, true)
				handled := make(chan struct{})
				conn.EXPECT().handlePacket(p).Do(func(receivedPacket) { close(handled) })
				serv.handlePacket(p)
				Eventually(handled).Should(BeClosed())
			})

			It("creates a connection when the token is accepted", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				retryToken, err := serv.tokenGenerator.NewRetryToken(
					raddr,
					protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
					protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
				)
				Expect(err).ToNot(HaveOccurred())
				connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: connID,
					Version:          protocol.Version1,
					Token:            retryToken,
				}
				p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				p.remoteAddr = raddr
				run := make(chan struct{})
				var token protocol.StatelessResetToken
				rand.Read(token[:])

				var newConnID protocol.ConnectionID

				phm.EXPECT().Get(connID)
				phm.EXPECT().AddWithConnID(connID, gomock.Any(), gomock.Any()).DoAndReturn(func(_, c protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					newConnID = c
					phm.EXPECT().GetStatelessResetToken(gomock.Any()).DoAndReturn(func(c protocol.ConnectionID) protocol.StatelessResetToken {
						newConnID = c
						return token
					})
					_, ok := fn()
					return ok
				})
				conn := NewMockQUICConn(mockCtrl)
				serv.newConn = func(
					_ sendConn,
					_ connRunner,
					origDestConnID protocol.ConnectionID,
					retrySrcConnID *protocol.ConnectionID,
					clientDestConnID protocol.ConnectionID,
					destConnID protocol.ConnectionID,
					srcConnID protocol.ConnectionID,
					_ ConnectionIDGenerator,
					tokenP protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					Expect(origDestConnID).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})))
					Expect(*retrySrcConnID).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})))
					Expect(clientDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(destConnID).To(Equal(hdr.SrcConnectionID))
					// make sure we're using a server-generated connection ID
					Expect(srcConnID).ToNot(Equal(hdr.DestConnectionID))
					Expect(srcConnID).ToNot(Equal(hdr.SrcConnectionID))
					Expect(srcConnID).To(Equal(newConnID))
					Expect(tokenP).To(Equal(token))
					conn.EXPECT().handlePacket(p)
					conn.EXPECT().run().Do(func() { close(run) })
					conn.EXPECT().Context().Return(context.Background())
					conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
					return conn
				}

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.handlePacket(p)
					// the Handshake packet is written by the connection.
					// Make sure there are no Write calls on the packet conn.
					time.Sleep(50 * time.Millisecond)
					close(done)
				}()
				// make sure we're using a server-generated connection ID
				Eventually(run).Should(BeClosed())
				Eventually(done).Should(BeClosed())
			})

			It("sends a Version Negotiation Packet for unsupported versions", func() {
				srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})
				destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
				packet := getPacket(&wire.Header{
					Type:             protocol.PacketTypeHandshake,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Version:          0x42,
				}, make([]byte, protocol.MinUnknownVersionPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentVersionNegotiationPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, src, dest protocol.ArbitraryLenConnectionID, _ []protocol.VersionNumber) {
					Expect(src).To(Equal(protocol.ArbitraryLenConnectionID(destConnID.Bytes())))
					Expect(dest).To(Equal(protocol.ArbitraryLenConnectionID(srcConnID.Bytes())))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					Expect(wire.IsVersionNegotiationPacket(b)).To(BeTrue())
					dest, src, versions, err := wire.ParseVersionNegotiationPacket(b)
					Expect(err).ToNot(HaveOccurred())
					Expect(dest).To(Equal(protocol.ArbitraryLenConnectionID(srcConnID.Bytes())))
					Expect(src).To(Equal(protocol.ArbitraryLenConnectionID(destConnID.Bytes())))
					Expect(versions).ToNot(ContainElement(protocol.VersionNumber(0x42)))
					return len(b), nil
				})
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't send a Version Negotiation packets if sending them is disabled", func() {
				serv.disableVersionNegotiation = true
				srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})
				destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
				packet := getPacket(&wire.Header{
					Type:             protocol.PacketTypeHandshake,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Version:          0x42,
				}, make([]byte, protocol.MinUnknownVersionPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).Do(func() { close(done) }).Times(0)
				serv.handlePacket(packet)
				Consistently(done, 50*time.Millisecond).ShouldNot(BeClosed())
			})

			It("ignores Version Negotiation packets", func() {
				data := wire.ComposeVersionNegotiation(
					protocol.ArbitraryLenConnectionID{1, 2, 3, 4},
					protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
					[]protocol.VersionNumber{1, 2, 3},
				)
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				done := make(chan struct{})
				tracer.EXPECT().DroppedPacket(raddr, logging.PacketTypeVersionNegotiation, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(done)
				})
				serv.handlePacket(receivedPacket{
					remoteAddr: raddr,
					data:       data,
					buffer:     getPacketBuffer(),
				})
				Eventually(done).Should(BeClosed())
				// make sure no other packet is sent
				time.Sleep(scaleDuration(20 * time.Millisecond))
			})

			It("doesn't send a Version Negotiation Packet for unsupported versions, if the packet is too small", func() {
				srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})
				destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
				p := getPacket(&wire.Header{
					Type:             protocol.PacketTypeHandshake,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Version:          0x42,
				}, make([]byte, protocol.MinUnknownVersionPacketSize-50))
				Expect(p.Size()).To(BeNumerically("<", protocol.MinUnknownVersionPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				p.remoteAddr = raddr
				done := make(chan struct{})
				tracer.EXPECT().DroppedPacket(raddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropUnexpectedPacket).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(done)
				})
				serv.handlePacket(p)
				Eventually(done).Should(BeClosed())
				// make sure no other packet is sent
				time.Sleep(scaleDuration(20 * time.Millisecond))
			})

			It("replies with a Retry packet, if a token is required", func() {
				connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: connID,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), nil).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, _ []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
					Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(replyHdr.Token).ToNot(BeEmpty())
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					replyHdr := parseHeader(b)
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
					Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(replyHdr.Token).ToNot(BeEmpty())
					Expect(b[len(b)-16:]).To(Equal(handshake.GetRetryIntegrityTag(b[:len(b)-16], hdr.DestConnectionID, hdr.Version)[:]))
					return len(b), nil
				})
				phm.EXPECT().Get(connID)
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("creates a connection, if no token is required", func() {
				connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: connID,
					Version:          protocol.Version1,
				}
				p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				run := make(chan struct{})
				var token protocol.StatelessResetToken
				rand.Read(token[:])

				var newConnID protocol.ConnectionID
				gomock.InOrder(
					phm.EXPECT().Get(connID),
					phm.EXPECT().AddWithConnID(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), gomock.Any(), gomock.Any()).DoAndReturn(func(_, c protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
						newConnID = c
						phm.EXPECT().GetStatelessResetToken(gomock.Any()).DoAndReturn(func(c protocol.ConnectionID) protocol.StatelessResetToken {
							newConnID = c
							return token
						})
						_, ok := fn()
						return ok
					}),
				)

				conn := NewMockQUICConn(mockCtrl)
				serv.newConn = func(
					_ sendConn,
					_ connRunner,
					origDestConnID protocol.ConnectionID,
					retrySrcConnID *protocol.ConnectionID,
					clientDestConnID protocol.ConnectionID,
					destConnID protocol.ConnectionID,
					srcConnID protocol.ConnectionID,
					_ ConnectionIDGenerator,
					tokenP protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					Expect(origDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(retrySrcConnID).To(BeNil())
					Expect(clientDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(destConnID).To(Equal(hdr.SrcConnectionID))
					// make sure we're using a server-generated connection ID
					Expect(srcConnID).ToNot(Equal(hdr.DestConnectionID))
					Expect(srcConnID).ToNot(Equal(hdr.SrcConnectionID))
					Expect(srcConnID).To(Equal(newConnID))
					Expect(tokenP).To(Equal(token))
					conn.EXPECT().handlePacket(p)
					conn.EXPECT().run().Do(func() { close(run) })
					conn.EXPECT().Context().Return(context.Background())
					conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
					return conn
				}

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.handlePacket(p)
					// the Handshake packet is written by the connection
					// make sure there are no Write calls on the packet conn
					time.Sleep(50 * time.Millisecond)
					close(done)
				}()
				// make sure we're using a server-generated connection ID
				Eventually(run).Should(BeClosed())
				Eventually(done).Should(BeClosed())
			})

			It("drops packets if the receive queue is full", func() {
				phm.EXPECT().Get(gomock.Any()).AnyTimes()
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					_, ok := fn()
					return ok
				}).AnyTimes()

				acceptConn := make(chan struct{})
				var counter uint32 // to be used as an atomic, so we query it in Eventually
				serv.newConn = func(
					_ sendConn,
					runner connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					<-acceptConn
					atomic.AddUint32(&counter, 1)
					conn := NewMockQUICConn(mockCtrl)
					conn.EXPECT().handlePacket(gomock.Any()).MaxTimes(1)
					conn.EXPECT().run().MaxTimes(1)
					conn.EXPECT().Context().Return(context.Background()).MaxTimes(1)
					conn.EXPECT().HandshakeComplete().Return(make(chan struct{})).MaxTimes(1)
					return conn
				}

				p := getInitial(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
				serv.handlePacket(p)
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropDOSPrevention).MinTimes(1)
				var wg sync.WaitGroup
				for i := 0; i < 3*protocol.MaxServerUnprocessedPackets; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						serv.handlePacket(getInitial(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})))
					}()
				}
				wg.Wait()

				close(acceptConn)
				Eventually(
					func() uint32 { return atomic.LoadUint32(&counter) },
					scaleDuration(100*time.Millisecond),
				).Should(BeEquivalentTo(protocol.MaxServerUnprocessedPackets + 1))
				Consistently(func() uint32 { return atomic.LoadUint32(&counter) }).Should(BeEquivalentTo(protocol.MaxServerUnprocessedPackets + 1))
			})

			It("only creates a single connection for a duplicate Initial", func() {
				var createdConn bool
				serv.newConn = func(
					_ sendConn,
					runner connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					createdConn = true
					return NewMockQUICConn(mockCtrl)
				}

				connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
				p := getInitial(connID)
				phm.EXPECT().Get(connID)
				phm.EXPECT().AddWithConnID(connID, gomock.Any(), gomock.Any()).Return(false)
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Do(func([]byte, net.Addr) { close(done) })
				Expect(serv.handlePacketImpl(p)).To(BeTrue())
				Expect(createdConn).To(BeFalse())
				Eventually(done).Should(BeClosed())
			})

			It("rejects new connection attempts if the accept queue is full", func() {
				serv.newConn = func(
					_ sendConn,
					runner connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					conn := NewMockQUICConn(mockCtrl)
					conn.EXPECT().handlePacket(gomock.Any())
					conn.EXPECT().run()
					conn.EXPECT().Context().Return(context.Background())
					c := make(chan struct{})
					close(c)
					conn.EXPECT().HandshakeComplete().Return(c)
					return conn
				}

				phm.EXPECT().Get(gomock.Any()).Times(protocol.MaxAcceptQueueSize + 1)
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					_, ok := fn()
					return ok
				}).Times(protocol.MaxAcceptQueueSize)

				var wg sync.WaitGroup
				wg.Add(protocol.MaxAcceptQueueSize)
				for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						serv.handlePacket(getInitialWithRandomDestConnID())
						// make sure there are no Write calls on the packet conn
						time.Sleep(50 * time.Millisecond)
					}()
				}
				wg.Wait()
				p := getInitialWithRandomDestConnID()
				hdr, _, _, err := wire.ParsePacket(p.data)
				Expect(err).ToNot(HaveOccurred())
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), p.remoteAddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					rejectHdr := parseHeader(b)
					Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(rejectHdr.Version).To(Equal(hdr.Version))
					Expect(rejectHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(rejectHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					return len(b), nil
				})
				serv.handlePacket(p)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't accept new connections if they were closed in the mean time", func() {
				p := getInitial(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
				ctx, cancel := context.WithCancel(context.Background())
				connCreated := make(chan struct{})
				conn := NewMockQUICConn(mockCtrl)
				serv.newConn = func(
					_ sendConn,
					runner connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					conn.EXPECT().handlePacket(p)
					conn.EXPECT().run()
					conn.EXPECT().Context().Return(ctx)
					c := make(chan struct{})
					close(c)
					conn.EXPECT().HandshakeComplete().Return(c)
					close(connCreated)
					return conn
				}

				phm.EXPECT().Get(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					_, ok := fn()
					return ok
				})

				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
				Eventually(connCreated).Should(BeClosed())
				cancel()
				time.Sleep(scaleDuration(200 * time.Millisecond))

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.Accept(context.Background())
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())

				// make the go routine return
				conn.EXPECT().getPerspective().MaxTimes(2) // initOnce for every conn ID
				Expect(serv.Close()).To(Succeed())
				Eventually(done).Should(BeClosed())
			})
		})

		Context("token validation", func() {
			checkInvalidToken := func(b []byte, origHdr *wire.Header) {
				replyHdr := parseHeader(b)
				Expect(replyHdr.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(replyHdr.SrcConnectionID).To(Equal(origHdr.DestConnectionID))
				Expect(replyHdr.DestConnectionID).To(Equal(origHdr.SrcConnectionID))
				_, opener := handshake.NewInitialAEAD(origHdr.DestConnectionID, protocol.PerspectiveClient, replyHdr.Version)
				extHdr, err := unpackLongHeader(opener, replyHdr, b, origHdr.Version)
				Expect(err).ToNot(HaveOccurred())
				data, err := opener.Open(nil, b[extHdr.ParsedLen():], extHdr.PacketNumber, b[:extHdr.ParsedLen()])
				Expect(err).ToNot(HaveOccurred())
				_, f, err := wire.NewFrameParser(false).ParseNext(data, protocol.EncryptionInitial, origHdr.Version)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
				ccf := f.(*wire.ConnectionCloseFrame)
				Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.InvalidToken))
				Expect(ccf.ReasonPhrase).To(BeEmpty())
			}

			It("decodes the token from the token field", func() {
				raddr := &net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
				token, err := serv.tokenGenerator.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{})
				Expect(err).ToNot(HaveOccurred())
				packet := getPacket(&wire.Header{
					Type:    protocol.PacketTypeInitial,
					Token:   token,
					Version: serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize))
				packet.remoteAddr = raddr
				conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).MaxTimes(1)
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)

				done := make(chan struct{})
				phm.EXPECT().Get(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_, _ protocol.ConnectionID, _ func() (packetHandler, bool)) { close(done) })
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("sends an INVALID_TOKEN error, if an invalid retry token is received", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				token, err := serv.tokenGenerator.NewRetryToken(&net.UDPAddr{}, protocol.ConnectionID{}, protocol.ConnectionID{})
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
					Token:            token,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.data = append(packet.data, []byte("coalesced packet")...) // add some garbage to simulate a coalesced packet
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(replyHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(frames).To(HaveLen(1))
					Expect(frames[0]).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
					ccf := frames[0].(*logging.ConnectionCloseFrame)
					Expect(ccf.IsApplicationError).To(BeFalse())
					Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.InvalidToken))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					checkInvalidToken(b, hdr)
					return len(b), nil
				})
				phm.EXPECT().Get(gomock.Any())
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("sends an INVALID_TOKEN error, if an expired retry token is received", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				serv.config.HandshakeIdleTimeout = time.Millisecond / 2 // the maximum retry token age is equivalent to the handshake timeout
				Expect(serv.config.maxRetryTokenAge()).To(Equal(time.Millisecond))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				token, err := serv.tokenGenerator.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{})
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(2 * time.Millisecond) // make sure the token is expired
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
					Token:            token,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(replyHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(frames).To(HaveLen(1))
					Expect(frames[0]).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
					ccf := frames[0].(*logging.ConnectionCloseFrame)
					Expect(ccf.IsApplicationError).To(BeFalse())
					Expect(ccf.ErrorCode).To(BeEquivalentTo(qerr.InvalidToken))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					checkInvalidToken(b, hdr)
					return len(b), nil
				})
				phm.EXPECT().Get(gomock.Any())
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't send an INVALID_TOKEN error, if an invalid non-retry token is received", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				token, err := serv.tokenGenerator.NewToken(&net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337})
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
					Token:            token,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.data[len(packet.data)-10] ^= 0xff // corrupt the packet
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					replyHdr := parseHeader(b)
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
					return len(b), nil
				})
				phm.EXPECT().Get(gomock.Any())
				serv.handlePacket(packet)
				// make sure there are no Write calls on the packet conn
				Eventually(done).Should(BeClosed())
			})

			It("sends an INVALID_TOKEN error, if an expired non-retry token is received", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				serv.maxTokenAge = time.Millisecond
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				token, err := serv.tokenGenerator.NewToken(raddr)
				Expect(err).ToNot(HaveOccurred())
				time.Sleep(2 * time.Millisecond) // make sure the token is expired
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
					Token:            token,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					return len(b), nil
				})
				phm.EXPECT().Get(gomock.Any())
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't send an INVALID_TOKEN error, if the packet is corrupted", func() {
				serv.config.RequireAddressValidation = func(net.Addr) bool { return true }
				token, err := serv.tokenGenerator.NewRetryToken(&net.UDPAddr{}, protocol.ConnectionID{}, protocol.ConnectionID{})
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
					Token:            token,
					Version:          protocol.Version1,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.data[len(packet.data)-10] ^= 0xff // corrupt the packet
				packet.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				done := make(chan struct{})
				tracer.EXPECT().DroppedPacket(packet.remoteAddr, logging.PacketTypeInitial, packet.Size(), logging.PacketDropPayloadDecryptError).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) { close(done) })
				phm.EXPECT().Get(gomock.Any())
				serv.handlePacket(packet)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
				Eventually(done).Should(BeClosed())
			})
		})

		Context("accepting connections", func() {
			It("returns Accept when an error occurs", func() {
				testErr := errors.New("test err")

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serv.Accept(context.Background())
					Expect(err).To(MatchError(testErr))
					close(done)
				}()

				serv.setCloseError(testErr)
				Eventually(done).Should(BeClosed())
				serv.onClose() // shutdown
			})

			It("returns immediately, if an error occurred before", func() {
				testErr := errors.New("test err")
				serv.setCloseError(testErr)
				for i := 0; i < 3; i++ {
					_, err := serv.Accept(context.Background())
					Expect(err).To(MatchError(testErr))
				}
				serv.onClose() // shutdown
			})

			It("returns when the context is canceled", func() {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serv.Accept(ctx)
					Expect(err).To(MatchError("context canceled"))
					close(done)
				}()

				Consistently(done).ShouldNot(BeClosed())
				cancel()
				Eventually(done).Should(BeClosed())
			})

			It("uses the config returned by GetConfigClient", func() {
				conn := NewMockQUICConn(mockCtrl)

				conf := &Config{MaxIncomingStreams: 1234}
				serv.config = populateServerConfig(&Config{GetConfigForClient: func(*ClientHelloInfo) (*Config, error) { return conf, nil }})
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					s, err := serv.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(s).To(Equal(conn))
					close(done)
				}()

				handshakeChan := make(chan struct{})
				serv.newConn = func(
					_ sendConn,
					_ connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					conf *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					Expect(conf.MaxIncomingStreams).To(BeEquivalentTo(1234))
					conn.EXPECT().handlePacket(gomock.Any())
					conn.EXPECT().HandshakeComplete().Return(handshakeChan)
					conn.EXPECT().run().Do(func() {})
					conn.EXPECT().Context().Return(context.Background())
					return conn
				}
				phm.EXPECT().Get(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					_, ok := fn()
					return ok
				})
				serv.handleInitialImpl(
					receivedPacket{buffer: getPacketBuffer()},
					&wire.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
				)
				Consistently(done).ShouldNot(BeClosed())
				close(handshakeChan) // complete the handshake
				Eventually(done).Should(BeClosed())
			})

			It("rejects a connection attempt when GetConfigClient returns an error", func() {
				serv.config = populateServerConfig(&Config{GetConfigForClient: func(*ClientHelloInfo) (*Config, error) { return nil, errors.New("rejected") }})

				phm.EXPECT().Get(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					_, ok := fn()
					return ok
				})
				done := make(chan struct{})
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					rejectHdr := parseHeader(b)
					Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
					return len(b), nil
				})
				serv.handleInitialImpl(
					receivedPacket{buffer: getPacketBuffer()},
					&wire.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), Version: protocol.Version1},
				)
				Eventually(done).Should(BeClosed())
			})

			It("accepts new connections when the handshake completes", func() {
				conn := NewMockQUICConn(mockCtrl)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					s, err := serv.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(s).To(Equal(conn))
					close(done)
				}()

				handshakeChan := make(chan struct{})
				serv.newConn = func(
					_ sendConn,
					runner connRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ ConnectionIDGenerator,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ *logging.ConnectionTracer,
					_ uint64,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicConn {
					conn.EXPECT().handlePacket(gomock.Any())
					conn.EXPECT().HandshakeComplete().Return(handshakeChan)
					conn.EXPECT().run().Do(func() {})
					conn.EXPECT().Context().Return(context.Background())
					return conn
				}
				phm.EXPECT().Get(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					_, ok := fn()
					return ok
				})
				serv.handleInitialImpl(
					receivedPacket{buffer: getPacketBuffer()},
					&wire.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
				)
				Consistently(done).ShouldNot(BeClosed())
				close(handshakeChan) // complete the handshake
				Eventually(done).Should(BeClosed())
			})
		})
	})

	Context("server accepting connections that haven't completed the handshake", func() {
		var (
			serv *EarlyListener
			phm  *MockPacketHandlerManager
		)

		BeforeEach(func() {
			var err error
			serv, err = ListenEarly(conn, tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			phm = NewMockPacketHandlerManager(mockCtrl)
			serv.baseServer.connHandler = phm
		})

		AfterEach(func() {
			serv.Close()
		})

		It("accepts new connections when they become ready", func() {
			conn := NewMockQUICConn(mockCtrl)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := serv.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(s).To(Equal(conn))
				close(done)
			}()

			ready := make(chan struct{})
			serv.baseServer.newConn = func(
				_ sendConn,
				runner connRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ *logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				conn.EXPECT().handlePacket(gomock.Any())
				conn.EXPECT().run().Do(func() {})
				conn.EXPECT().earlyConnReady().Return(ready)
				conn.EXPECT().Context().Return(context.Background())
				return conn
			}
			phm.EXPECT().Get(gomock.Any())
			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				_, ok := fn()
				return ok
			})
			serv.baseServer.handleInitialImpl(
				receivedPacket{buffer: getPacketBuffer()},
				&wire.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
			)
			Consistently(done).ShouldNot(BeClosed())
			close(ready)
			Eventually(done).Should(BeClosed())
		})

		It("rejects new connection attempts if the accept queue is full", func() {
			senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}

			serv.baseServer.newConn = func(
				_ sendConn,
				runner connRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ *logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				ready := make(chan struct{})
				close(ready)
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().handlePacket(gomock.Any())
				conn.EXPECT().run()
				conn.EXPECT().earlyConnReady().Return(ready)
				conn.EXPECT().Context().Return(context.Background())
				return conn
			}

			phm.EXPECT().Get(gomock.Any()).AnyTimes()
			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				_, ok := fn()
				return ok
			}).Times(protocol.MaxAcceptQueueSize)
			for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
				serv.baseServer.handlePacket(getInitialWithRandomDestConnID())
			}

			Eventually(func() int32 { return atomic.LoadInt32(&serv.baseServer.connQueueLen) }).Should(BeEquivalentTo(protocol.MaxAcceptQueueSize))
			// make sure there are no Write calls on the packet conn
			time.Sleep(50 * time.Millisecond)

			p := getInitialWithRandomDestConnID()
			hdr := parseHeader(p.data)
			done := make(chan struct{})
			conn.EXPECT().WriteTo(gomock.Any(), senderAddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
				defer close(done)
				rejectHdr := parseHeader(b)
				Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(rejectHdr.Version).To(Equal(hdr.Version))
				Expect(rejectHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
				Expect(rejectHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
				return len(b), nil
			})
			serv.baseServer.handlePacket(p)
			Eventually(done).Should(BeClosed())
		})

		It("doesn't accept new connections if they were closed in the mean time", func() {
			p := getInitial(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			ctx, cancel := context.WithCancel(context.Background())
			connCreated := make(chan struct{})
			conn := NewMockQUICConn(mockCtrl)
			serv.baseServer.newConn = func(
				_ sendConn,
				runner connRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ *logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				conn.EXPECT().handlePacket(p)
				conn.EXPECT().run()
				conn.EXPECT().earlyConnReady()
				conn.EXPECT().Context().Return(ctx)
				close(connCreated)
				return conn
			}

			phm.EXPECT().Get(gomock.Any())
			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				_, ok := fn()
				return ok
			})
			serv.baseServer.handlePacket(p)
			// make sure there are no Write calls on the packet conn
			time.Sleep(50 * time.Millisecond)
			Eventually(connCreated).Should(BeClosed())
			cancel()
			time.Sleep(scaleDuration(200 * time.Millisecond))

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.Accept(context.Background())
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())

			// make the go routine return
			conn.EXPECT().getPerspective().MaxTimes(2) // initOnce for every conn ID
			Expect(serv.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})
	})

	Context("0-RTT", func() {
		var (
			tr     *Transport
			serv   *baseServer
			phm    *MockPacketHandlerManager
			tracer *mocklogging.MockTracer
		)

		BeforeEach(func() {
			var t *logging.Tracer
			t, tracer = mocklogging.NewMockTracer(mockCtrl)
			tr = &Transport{Conn: conn, Tracer: t}
			ln, err := tr.ListenEarly(tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			phm = NewMockPacketHandlerManager(mockCtrl)
			serv = ln.baseServer
			serv.connHandler = phm
		})

		AfterEach(func() {
			phm.EXPECT().CloseServer().MaxTimes(1)
			tr.Close()
		})

		It("passes packets to existing connections", func() {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
			p := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID,
				Version:          serv.config.Versions[0],
			}, make([]byte, 100))
			conn := NewMockPacketHandler(mockCtrl)
			phm.EXPECT().Get(connID).Return(conn, true)
			handled := make(chan struct{})
			conn.EXPECT().handlePacket(p).Do(func(receivedPacket) { close(handled) })
			serv.handlePacket(p)
			Eventually(handled).Should(BeClosed())
		})

		It("queues 0-RTT packets, up to Max0RTTQueueSize", func() {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

			var zeroRTTPackets []receivedPacket

			for i := 0; i < protocol.Max0RTTQueueLen; i++ {
				p := getPacket(&wire.Header{
					Type:             protocol.PacketType0RTT,
					DestConnectionID: connID,
					Version:          serv.config.Versions[0],
				}, make([]byte, 100+i))
				phm.EXPECT().Get(connID)
				serv.handlePacket(p)
				zeroRTTPackets = append(zeroRTTPackets, p)
			}

			// send one more packet, this one should be dropped
			p := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID,
				Version:          serv.config.Versions[0],
			}, make([]byte, 200))
			phm.EXPECT().Get(connID)
			tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketType0RTT, p.Size(), logging.PacketDropDOSPrevention)
			serv.handlePacket(p)

			initial := getPacket(&wire.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: connID,
				Version:          serv.config.Versions[0],
			}, make([]byte, protocol.MinInitialPacketSize))
			called := make(chan struct{})
			serv.newConn = func(
				_ sendConn,
				_ connRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ *logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				conn := NewMockQUICConn(mockCtrl)
				var calls []any
				calls = append(calls, conn.EXPECT().handlePacket(initial))
				for _, p := range zeroRTTPackets {
					calls = append(calls, conn.EXPECT().handlePacket(p))
				}
				gomock.InOrder(calls...)
				conn.EXPECT().run()
				conn.EXPECT().earlyConnReady()
				conn.EXPECT().Context().Return(context.Background())
				close(called)
				return conn
			}

			phm.EXPECT().Get(connID)
			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() (packetHandler, bool)) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				_, ok := fn()
				return ok
			})
			serv.handlePacket(initial)
			Eventually(called).Should(BeClosed())
		})

		It("limits the number of queues", func() {
			for i := 0; i < protocol.Max0RTTQueues; i++ {
				b := make([]byte, 16)
				rand.Read(b)
				connID := protocol.ParseConnectionID(b)
				p := getPacket(&wire.Header{
					Type:             protocol.PacketType0RTT,
					DestConnectionID: connID,
					Version:          serv.config.Versions[0],
				}, make([]byte, 100+i))
				phm.EXPECT().Get(connID)
				serv.handlePacket(p)
			}

			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
			p := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID,
				Version:          serv.config.Versions[0],
			}, make([]byte, 200))
			phm.EXPECT().Get(connID)
			dropped := make(chan struct{})
			tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketType0RTT, p.Size(), logging.PacketDropDOSPrevention).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
				close(dropped)
			})
			serv.handlePacket(p)
			Eventually(dropped).Should(BeClosed())
		})

		It("drops queues after a while", func() {
			now := time.Now()

			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
			p := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID,
				Version:          serv.config.Versions[0],
			}, make([]byte, 200))
			p.rcvTime = now

			connID2 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 9})
			p2Time := now.Add(protocol.Max0RTTQueueingDuration / 2)
			p2 := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID2,
				Version:          serv.config.Versions[0],
			}, make([]byte, 300))
			p2.rcvTime = p2Time // doesn't trigger the cleanup of the first packet

			dropped1 := make(chan struct{})
			dropped2 := make(chan struct{})
			// need to register the call before handling the packet to avoid race condition
			gomock.InOrder(
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketType0RTT, p.Size(), logging.PacketDropDOSPrevention).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(dropped1)
				}),
				tracer.EXPECT().DroppedPacket(p2.remoteAddr, logging.PacketType0RTT, p2.Size(), logging.PacketDropDOSPrevention).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(dropped2)
				}),
			)

			phm.EXPECT().Get(connID)
			serv.handlePacket(p)

			// There's no cleanup Go routine.
			// Cleanup is triggered when new packets are received.

			phm.EXPECT().Get(connID2)
			serv.handlePacket(p2)
			// make sure no cleanup is executed
			Consistently(dropped1, 50*time.Millisecond).ShouldNot(BeClosed())

			// There's no cleanup Go routine.
			// Cleanup is triggered when new packets are received.
			connID3 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 0})
			p3 := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID3,
				Version:          serv.config.Versions[0],
			}, make([]byte, 200))
			p3.rcvTime = now.Add(protocol.Max0RTTQueueingDuration + time.Nanosecond) // now triggers the cleanup
			phm.EXPECT().Get(connID3)
			serv.handlePacket(p3)
			Eventually(dropped1).Should(BeClosed())
			Consistently(dropped2, 50*time.Millisecond).ShouldNot(BeClosed())

			// make sure the second packet is also cleaned up
			connID4 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 1})
			p4 := getPacket(&wire.Header{
				Type:             protocol.PacketType0RTT,
				DestConnectionID: connID4,
				Version:          serv.config.Versions[0],
			}, make([]byte, 200))
			p4.rcvTime = p2Time.Add(protocol.Max0RTTQueueingDuration + time.Nanosecond) // now triggers the cleanup
			phm.EXPECT().Get(connID4)
			serv.handlePacket(p4)
			Eventually(dropped2).Should(BeClosed())
		})
	})
})
