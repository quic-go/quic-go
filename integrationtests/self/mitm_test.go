package self_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testutils"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MITM test", func() {
	const connIDLen = 6 // explicitly set the connection ID length, so the proxy can parse it

	var (
		clientUDPConn                    net.PacketConn
		serverTransport, clientTransport *quic.Transport
		serverConn                       quic.Connection
		serverConfig                     *quic.Config
	)

	startServerAndProxy := func(delayCb quicproxy.DelayCallback, dropCb quicproxy.DropCallback) (proxyPort int, closeFn func()) {
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		c, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		serverTransport = &quic.Transport{
			Conn:               c,
			ConnectionIDLength: connIDLen,
		}
		ln, err := serverTransport.Listen(getTLSConfig(), serverConfig)
		Expect(err).ToNot(HaveOccurred())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			var err error
			serverConn, err = ln.Accept(context.Background())
			if err != nil {
				return
			}
			str, err := serverConn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write(PRData)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())
		}()
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  fmt.Sprintf("localhost:%d", serverPort),
			DelayPacket: delayCb,
			DropPacket:  dropCb,
		})
		Expect(err).ToNot(HaveOccurred())
		return proxy.LocalPort(), func() {
			proxy.Close()
			ln.Close()
			serverTransport.Close()
			<-done
		}
	}

	BeforeEach(func() {
		serverConfig = getQuicConfig(nil)
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		clientUDPConn, err = net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		clientTransport = &quic.Transport{
			Conn:               clientUDPConn,
			ConnectionIDLength: connIDLen,
		}
	})

	Context("unsuccessful attacks", func() {
		AfterEach(func() {
			Eventually(serverConn.Context().Done()).Should(BeClosed())
			// Test shutdown is tricky due to the proxy. Just wait for a bit.
			time.Sleep(50 * time.Millisecond)
			Expect(clientUDPConn.Close()).To(Succeed())
			Expect(clientTransport.Close()).To(Succeed())
		})

		Context("injecting invalid packets", func() {
			const rtt = 20 * time.Millisecond

			sendRandomPacketsOfSameType := func(conn *quic.Transport, remoteAddr net.Addr, raw []byte) {
				defer GinkgoRecover()
				const numPackets = 10
				ticker := time.NewTicker(rtt / numPackets)
				defer ticker.Stop()

				if wire.IsLongHeaderPacket(raw[0]) {
					hdr, _, _, err := wire.ParsePacket(raw)
					Expect(err).ToNot(HaveOccurred())
					replyHdr := &wire.ExtendedHeader{
						Header: wire.Header{
							DestConnectionID: hdr.DestConnectionID,
							SrcConnectionID:  hdr.SrcConnectionID,
							Type:             hdr.Type,
							Version:          hdr.Version,
						},
						PacketNumber:    protocol.PacketNumber(rand.Int31n(math.MaxInt32 / 4)),
						PacketNumberLen: protocol.PacketNumberLen(rand.Int31n(4) + 1),
					}

					for i := 0; i < numPackets; i++ {
						payloadLen := rand.Int31n(100)
						replyHdr.Length = protocol.ByteCount(rand.Int31n(payloadLen + 1))
						b, err := replyHdr.Append(nil, hdr.Version)
						Expect(err).ToNot(HaveOccurred())
						r := make([]byte, payloadLen)
						rand.Read(r)
						b = append(b, r...)
						if _, err := conn.WriteTo(b, remoteAddr); err != nil {
							return
						}
						<-ticker.C
					}
				} else {
					connID, err := wire.ParseConnectionID(raw, connIDLen)
					Expect(err).ToNot(HaveOccurred())
					_, pn, pnLen, _, err := wire.ParseShortHeader(raw, connIDLen)
					if err != nil { // normally, ParseShortHeader is called after decrypting the header
						Expect(err).To(MatchError(wire.ErrInvalidReservedBits))
					}
					for i := 0; i < numPackets; i++ {
						b, err := wire.AppendShortHeader(nil, connID, pn, pnLen, protocol.KeyPhaseBit(rand.Intn(2)))
						Expect(err).ToNot(HaveOccurred())
						payloadLen := rand.Int31n(100)
						r := make([]byte, payloadLen)
						rand.Read(r)
						b = append(b, r...)
						if _, err := conn.WriteTo(b, remoteAddr); err != nil {
							return
						}
						<-ticker.C
					}
				}
			}

			runTest := func(delayCb quicproxy.DelayCallback) {
				proxyPort, closeFn := startServerAndProxy(delayCb, nil)
				defer closeFn()
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
				Expect(err).ToNot(HaveOccurred())
				conn, err := clientTransport.Dial(
					context.Background(),
					raddr,
					getTLSClientConfig(),
					getQuicConfig(nil),
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRData))
				Expect(conn.CloseWithError(0, "")).To(Succeed())
			}

			It("downloads a message when the packets are injected towards the server", func() {
				delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
					if dir == quicproxy.DirectionIncoming {
						defer GinkgoRecover()
						go sendRandomPacketsOfSameType(clientTransport, serverTransport.Conn.LocalAddr(), raw)
					}
					return rtt / 2
				}
				runTest(delayCb)
			})

			It("downloads a message when the packets are injected towards the client", func() {
				delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
					if dir == quicproxy.DirectionOutgoing {
						defer GinkgoRecover()
						go sendRandomPacketsOfSameType(serverTransport, clientTransport.Conn.LocalAddr(), raw)
					}
					return rtt / 2
				}
				runTest(delayCb)
			})
		})

		runTest := func(dropCb quicproxy.DropCallback) {
			proxyPort, closeFn := startServerAndProxy(nil, dropCb)
			defer closeFn()
			raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
			Expect(err).ToNot(HaveOccurred())
			conn, err := clientTransport.Dial(
				context.Background(),
				raddr,
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(PRData))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
		}

		Context("duplicating packets", func() {
			It("downloads a message when packets are duplicated towards the server", func() {
				dropCb := func(dir quicproxy.Direction, raw []byte) bool {
					defer GinkgoRecover()
					if dir == quicproxy.DirectionIncoming {
						_, err := clientTransport.WriteTo(raw, serverTransport.Conn.LocalAddr())
						Expect(err).ToNot(HaveOccurred())
					}
					return false
				}
				runTest(dropCb)
			})

			It("downloads a message when packets are duplicated towards the client", func() {
				dropCb := func(dir quicproxy.Direction, raw []byte) bool {
					defer GinkgoRecover()
					if dir == quicproxy.DirectionOutgoing {
						_, err := serverTransport.WriteTo(raw, clientTransport.Conn.LocalAddr())
						Expect(err).ToNot(HaveOccurred())
					}
					return false
				}
				runTest(dropCb)
			})
		})

		Context("corrupting packets", func() {
			const idleTimeout = time.Second

			var numCorrupted, numPackets int32

			BeforeEach(func() {
				numCorrupted = 0
				numPackets = 0
				serverConfig.MaxIdleTimeout = idleTimeout
			})

			AfterEach(func() {
				num := atomic.LoadInt32(&numCorrupted)
				fmt.Fprintf(GinkgoWriter, "Corrupted %d of %d packets.", num, atomic.LoadInt32(&numPackets))
				Expect(num).To(BeNumerically(">=", 1))
				// If the packet containing the CONNECTION_CLOSE is corrupted,
				// we have to wait for the connection to time out.
				Eventually(serverConn.Context().Done(), 3*idleTimeout).Should(BeClosed())
			})

			It("downloads a message when packet are corrupted towards the server", func() {
				const interval = 4 // corrupt every 4th packet (stochastically)
				dropCb := func(dir quicproxy.Direction, raw []byte) bool {
					defer GinkgoRecover()
					if dir == quicproxy.DirectionIncoming {
						atomic.AddInt32(&numPackets, 1)
						if rand.Intn(interval) == 0 {
							pos := rand.Intn(len(raw))
							raw[pos] = byte(rand.Intn(256))
							_, err := clientTransport.WriteTo(raw, serverTransport.Conn.LocalAddr())
							Expect(err).ToNot(HaveOccurred())
							atomic.AddInt32(&numCorrupted, 1)
							return true
						}
					}
					return false
				}
				runTest(dropCb)
			})

			It("downloads a message when packet are corrupted towards the client", func() {
				const interval = 10 // corrupt every 10th packet (stochastically)
				dropCb := func(dir quicproxy.Direction, raw []byte) bool {
					defer GinkgoRecover()
					if dir == quicproxy.DirectionOutgoing {
						atomic.AddInt32(&numPackets, 1)
						if rand.Intn(interval) == 0 {
							pos := rand.Intn(len(raw))
							raw[pos] = byte(rand.Intn(256))
							_, err := serverTransport.WriteTo(raw, clientTransport.Conn.LocalAddr())
							Expect(err).ToNot(HaveOccurred())
							atomic.AddInt32(&numCorrupted, 1)
							return true
						}
					}
					return false
				}
				runTest(dropCb)
			})
		})
	})

	Context("successful injection attacks", func() {
		// These tests demonstrate that the QUIC protocol is vulnerable to injection attacks before the handshake
		// finishes. In particular, an adversary who can intercept packets coming from one endpoint and send a reply
		// that arrives before the real reply can tear down the connection in multiple ways.

		const rtt = 20 * time.Millisecond

		runTest := func(delayCb quicproxy.DelayCallback) (closeFn func(), err error) {
			proxyPort, serverCloseFn := startServerAndProxy(delayCb, nil)
			raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxyPort))
			Expect(err).ToNot(HaveOccurred())
			_, err = clientTransport.Dial(
				context.Background(),
				raddr,
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{HandshakeIdleTimeout: 2 * time.Second}),
			)
			return func() { clientTransport.Close(); serverCloseFn() }, err
		}

		// fails immediately because client connection closes when it can't find compatible version
		It("fails when a forged version negotiation packet is sent to client", func() {
			done := make(chan struct{})
			delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
				if dir == quicproxy.DirectionIncoming {
					defer GinkgoRecover()

					hdr, _, _, err := wire.ParsePacket(raw)
					Expect(err).ToNot(HaveOccurred())

					if hdr.Type != protocol.PacketTypeInitial {
						return 0
					}

					// Create fake version negotiation packet with no supported versions
					versions := []protocol.VersionNumber{}
					packet := wire.ComposeVersionNegotiation(
						protocol.ArbitraryLenConnectionID(hdr.SrcConnectionID.Bytes()),
						protocol.ArbitraryLenConnectionID(hdr.DestConnectionID.Bytes()),
						versions,
					)

					// Send the packet
					_, err = serverTransport.WriteTo(packet, clientTransport.Conn.LocalAddr())
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}
				return rtt / 2
			}
			closeFn, err := runTest(delayCb)
			defer closeFn()
			Expect(err).To(HaveOccurred())
			vnErr := &quic.VersionNegotiationError{}
			Expect(errors.As(err, &vnErr)).To(BeTrue())
			Eventually(done).Should(BeClosed())
		})

		// times out, because client doesn't accept subsequent real retry packets from server
		// as it has already accepted a retry.
		// TODO: determine behavior when server does not send Retry packets
		It("fails when a forged Retry packet with modified srcConnID is sent to client", func() {
			serverConfig.RequireAddressValidation = func(net.Addr) bool { return true }
			var initialPacketIntercepted bool
			done := make(chan struct{})
			delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
				if dir == quicproxy.DirectionIncoming && !initialPacketIntercepted {
					defer GinkgoRecover()
					defer close(done)

					hdr, _, _, err := wire.ParsePacket(raw)
					Expect(err).ToNot(HaveOccurred())

					if hdr.Type != protocol.PacketTypeInitial {
						return 0
					}

					initialPacketIntercepted = true
					fakeSrcConnID := protocol.ParseConnectionID([]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12})
					retryPacket := testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)

					_, err = serverTransport.WriteTo(retryPacket, clientTransport.Conn.LocalAddr())
					Expect(err).ToNot(HaveOccurred())
				}
				return rtt / 2
			}
			closeFn, err := runTest(delayCb)
			defer closeFn()
			Expect(err).To(HaveOccurred())
			Expect(err.(net.Error).Timeout()).To(BeTrue())
			Eventually(done).Should(BeClosed())
		})

		// times out, because client doesn't accept real retry packets from server because
		// it has already accepted an initial.
		// TODO: determine behavior when server does not send Retry packets
		It("fails when a forged initial packet is sent to client", func() {
			done := make(chan struct{})
			var injected bool
			delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
				if dir == quicproxy.DirectionIncoming {
					defer GinkgoRecover()

					hdr, _, _, err := wire.ParsePacket(raw)
					Expect(err).ToNot(HaveOccurred())
					if hdr.Type != protocol.PacketTypeInitial || injected {
						return 0
					}
					defer close(done)
					injected = true
					initialPacket := testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, nil)
					_, err = serverTransport.WriteTo(initialPacket, clientTransport.Conn.LocalAddr())
					Expect(err).ToNot(HaveOccurred())
				}
				return rtt
			}
			closeFn, err := runTest(delayCb)
			defer closeFn()
			Expect(err).To(HaveOccurred())
			Expect(err.(net.Error).Timeout()).To(BeTrue())
			Eventually(done).Should(BeClosed())
		})

		// client connection closes immediately on receiving ack for unsent packet
		It("fails when a forged initial packet with ack for unsent packet is sent to client", func() {
			done := make(chan struct{})
			var injected bool
			delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
				if dir == quicproxy.DirectionIncoming {
					defer GinkgoRecover()

					hdr, _, _, err := wire.ParsePacket(raw)
					Expect(err).ToNot(HaveOccurred())
					if hdr.Type != protocol.PacketTypeInitial || injected {
						return 0
					}
					defer close(done)
					injected = true
					// Fake Initial with ACK for packet 2 (unsent)
					ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
					initialPacket := testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, []wire.Frame{ack})
					_, err = serverTransport.WriteTo(initialPacket, clientTransport.Conn.LocalAddr())
					Expect(err).ToNot(HaveOccurred())
				}
				return rtt
			}
			closeFn, err := runTest(delayCb)
			defer closeFn()
			Expect(err).To(HaveOccurred())
			var transportErr *quic.TransportError
			Expect(errors.As(err, &transportErr)).To(BeTrue())
			Expect(transportErr.ErrorCode).To(Equal(quic.ProtocolViolation))
			Expect(transportErr.ErrorMessage).To(ContainSubstring("received ACK for an unsent packet"))
			Eventually(done).Should(BeClosed())
		})
	})
})
