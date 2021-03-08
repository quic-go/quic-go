package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type rcvdPacketTracer struct {
	connTracer
	closed      chan struct{}
	rcvdPackets []*logging.ExtendedHeader
}

func newRcvdPacketTracer() *rcvdPacketTracer {
	return &rcvdPacketTracer{closed: make(chan struct{})}
}

func (t *rcvdPacketTracer) ReceivedPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ []logging.Frame) {
	t.rcvdPackets = append(t.rcvdPackets, hdr)
}
func (t *rcvdPacketTracer) Close() { close(t.closed) }
func (t *rcvdPacketTracer) getRcvdPackets() []*logging.ExtendedHeader {
	<-t.closed
	return t.rcvdPackets
}

var _ = Describe("0-RTT", func() {
	rtt := scaleDuration(5 * time.Millisecond)

	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			runCountingProxy := func(serverPort int) (*quicproxy.QuicProxy, *uint32) {
				var num0RTTPackets uint32 // to be used as an atomic
				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							atomic.AddUint32(&num0RTTPackets, 1)
						}
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())

				return proxy, &num0RTTPackets
			}

			dialAndReceiveSessionTicket := func(serverConf *quic.Config) (*tls.Config, *tls.Config) {
				tlsConf := getTLSConfig()
				if serverConf == nil {
					serverConf = getQuicConfig(&quic.Config{
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
					})
					serverConf.Versions = []protocol.VersionNumber{version}
				}
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					serverConf,
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr:  fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration { return rtt / 2 },
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				// dial the first session in order to receive a session ticket
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					<-sess.Context().Done()
				}()

				clientConf := getTLSClientConfig()
				gets := make(chan string, 100)
				puts := make(chan string, 100)
				clientConf.ClientSessionCache = newClientSessionCache(gets, puts)
				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				Eventually(puts).Should(Receive())
				// received the session ticket. We're done here.
				Expect(sess.CloseWithError(0, "")).To(Succeed())
				Eventually(done).Should(BeClosed())
				return tlsConf, clientConf
			}

			transfer0RTTData := func(
				ln quic.EarlyListener,
				proxyPort int,
				clientConf *tls.Config,
				testdata []byte, // data to transfer
				expect0RTT bool, // do we expect that 0-RTT is actually used
			) {
				// now dial the second session, and use 0-RTT to send some data
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testdata))
					Expect(sess.ConnectionState().TLS.Used0RTT).To(Equal(expect0RTT))
					Expect(sess.CloseWithError(0, "")).To(Succeed())
					close(done)
				}()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxyPort),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer sess.CloseWithError(0, "")
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(testdata)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				Expect(sess.ConnectionState().TLS.Used0RTT).To(Equal(expect0RTT))
				Eventually(done).Should(BeClosed())
				Eventually(sess.Context().Done()).Should(BeClosed())
			}

			check0RTTRejected := func(
				ln quic.EarlyListener,
				proxyPort int,
				clientConf *tls.Config,
			) {
				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxyPort),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(make([]byte, 3000))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				Expect(sess.ConnectionState().TLS.Used0RTT).To(BeFalse())

				// make sure the server doesn't process the data
				ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
				defer cancel()
				serverSess, err := ln.Accept(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(serverSess.ConnectionState().TLS.Used0RTT).To(BeFalse())
				_, err = serverSess.AcceptUniStream(ctx)
				Expect(err).To(Equal(context.DeadlineExceeded))
				Expect(serverSess.CloseWithError(0, "")).To(Succeed())
				Eventually(sess.Context().Done()).Should(BeClosed())
			}

			// can be used to extract 0-RTT from a rcvdPacketTracer
			get0RTTPackets := func(hdrs []*logging.ExtendedHeader) []protocol.PacketNumber {
				var zeroRTTPackets []protocol.PacketNumber
				for _, hdr := range hdrs {
					if hdr.Type == protocol.PacketType0RTT {
						zeroRTTPackets = append(zeroRTTPackets, hdr.PacketNumber)
					}
				}
				return zeroRTTPackets
			}

			It("transfers 0-RTT data", func() {
				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions: []protocol.VersionNumber{version},
						Tracer:   newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, PRData, true)

				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
				// TODO(#2629): ensure that this is a contiguous block of packets, starting at packet 0
				Expect(get0RTTPackets(tracer.getRcvdPackets())).ToNot(BeEmpty())
			})

			// Test that data intended to be sent with 1-RTT protection is not sent in 0-RTT packets.
			It("waits until a session until the handshake is done", func() {
				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

				zeroRTTData := GeneratePRData(2 * 1100) // 2 packets
				oneRTTData := PRData

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
						Tracer:      newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				// now dial the second session, and use 0-RTT to send some data
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(zeroRTTData))
					str, err = sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err = ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(oneRTTData))
					Expect(sess.CloseWithError(0, "")).To(Succeed())
				}()

				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				sent0RTT := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(sent0RTT)
					str, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write(zeroRTTData)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
				}()
				Eventually(sent0RTT).Should(BeClosed())

				// wait for the handshake to complete
				Eventually(sess.HandshakeComplete().Done()).Should(BeClosed())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(PRData)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				<-sess.Context().Done()

				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).To(Or(BeEquivalentTo(2), BeEquivalentTo(3))) // the FIN might be sent in a separate packet
				// TODO(#2629): check that packets are sent
				// Expect(get0RTTPackets(tracer.getRcvdPackets())).ToNot(BeEmpty())
			})

			It("transfers 0-RTT data, when 0-RTT packets are lost", func() {
				var (
					num0RTTPackets uint32 // to be used as an atomic
					num0RTTDropped uint32
				)

				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions: []protocol.VersionNumber{version},
						Tracer:   newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							atomic.AddUint32(&num0RTTPackets, 1)
						}
						return rtt / 2
					},
					DropPacket: func(_ quicproxy.Direction, data []byte) bool {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							// drop 25% of the 0-RTT packets
							drop := mrand.Intn(4) == 0
							if drop {
								atomic.AddUint32(&num0RTTDropped, 1)
							}
							return drop
						}
						return false
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, PRData, true)

				num0RTT := atomic.LoadUint32(&num0RTTPackets)
				numDropped := atomic.LoadUint32(&num0RTTDropped)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets. Dropped %d of those.", num0RTT, numDropped)
				Expect(numDropped).ToNot(BeZero())
				Expect(num0RTT).ToNot(BeZero())
				Expect(get0RTTPackets(tracer.getRcvdPackets())).ToNot(BeEmpty())
			})

			It("retransmits all 0-RTT data when the server performs a Retry", func() {
				var mutex sync.Mutex
				var firstConnID, secondConnID protocol.ConnectionID
				var firstCounter, secondCounter protocol.ByteCount

				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

				countZeroRTTBytes := func(data []byte) (n protocol.ByteCount) {
					for len(data) > 0 {
						hdr, _, rest, err := wire.ParsePacket(data, 0)
						if err != nil {
							return
						}
						data = rest
						if hdr.Type == protocol.PacketType0RTT {
							n += hdr.Length - 16 /* AEAD tag */
						}
					}
					return
				}

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions: []protocol.VersionNumber{version},
						Tracer:   newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
					DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
						connID, err := wire.ParseConnectionID(data, 0)
						Expect(err).ToNot(HaveOccurred())

						mutex.Lock()
						defer mutex.Unlock()

						if zeroRTTBytes := countZeroRTTBytes(data); zeroRTTBytes > 0 {
							if firstConnID == nil {
								firstConnID = connID
								firstCounter += zeroRTTBytes
							} else if firstConnID != nil && firstConnID.Equal(connID) {
								Expect(secondConnID).To(BeNil())
								firstCounter += zeroRTTBytes
							} else if secondConnID == nil {
								secondConnID = connID
								secondCounter += zeroRTTBytes
							} else if secondConnID != nil && secondConnID.Equal(connID) {
								secondCounter += zeroRTTBytes
							} else {
								Fail("received 3 connection IDs on 0-RTT packets")
							}
						}
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, GeneratePRData(5000), true) // ~5 packets

				mutex.Lock()
				defer mutex.Unlock()
				Expect(firstCounter).To(BeNumerically("~", 5000+100 /* framing overhead */, 100)) // the FIN bit might be sent extra
				Expect(secondCounter).To(BeNumerically("~", firstCounter, 20))
				zeroRTTPackets := get0RTTPackets(tracer.getRcvdPackets())
				// TODO(#2629): We should receive 5 packets here.
				Expect(len(zeroRTTPackets)).To(BeNumerically(">=", 1))
				Expect(zeroRTTPackets[0]).To(BeNumerically(">", protocol.PacketNumber(1)))
			})

			It("rejects 0-RTT when the server's transport parameters changed", func() {
				const maxStreams = 42
				tlsConf, clientConf := dialAndReceiveSessionTicket(getQuicConfig(&quic.Config{
					MaxIncomingStreams: maxStreams,
					AcceptToken:        func(_ net.Addr, _ *quic.Token) bool { return true },
				}))

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions:           []protocol.VersionNumber{version},
						AcceptToken:        func(_ net.Addr, _ *quic.Token) bool { return true },
						MaxIncomingStreams: maxStreams + 1,
						Tracer:             newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()
				check0RTTRejected(ln, proxy.LocalPort(), clientConf)

				// The client should send 0-RTT packets, but the server doesn't process them.
				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
				Expect(get0RTTPackets(tracer.getRcvdPackets())).To(BeEmpty())
			})

			It("rejects 0-RTT when the ALPN changed", func() {
				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

				// now close the listener and dial new connection with a different ALPN
				clientConf.NextProtos = []string{"new-alpn"}
				tlsConf.NextProtos = []string{"new-alpn"}
				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
						Tracer:      newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				check0RTTRejected(ln, proxy.LocalPort(), clientConf)

				// The client should send 0-RTT packets, but the server doesn't process them.
				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
				Expect(get0RTTPackets(tracer.getRcvdPackets())).To(BeEmpty())
			})

			It("correctly deals with 0-RTT rejections", func() {
				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)
				// now dial new connection with different transport parameters
				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions:              []protocol.VersionNumber{version},
						MaxIncomingUniStreams: 1,
						Tracer:                newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(data)).To(Equal("second flight"))
					Expect(sess.CloseWithError(0, "")).To(Succeed())
				}()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				// The client remembers that it was allowed to open 2 uni-directional streams.
				for i := 0; i < 2; i++ {
					str, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					go func() {
						defer GinkgoRecover()
						_, err = str.Write([]byte("first flight"))
						Expect(err).ToNot(HaveOccurred())
					}()
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, err = sess.AcceptStream(ctx)
				Expect(err).To(Equal(quic.Err0RTTRejected))

				newSess := sess.NextSession()
				str, err := newSess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = newSess.OpenUniStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("too many open streams"))
				_, err = str.Write([]byte("second flight"))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())

				Eventually(done).Should(BeClosed())
				Eventually(sess.Context().Done()).Should(BeClosed())

				// The client should send 0-RTT packets, but the server doesn't process them.
				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
				Expect(get0RTTPackets(tracer.getRcvdPackets())).To(BeEmpty())
			})
		})
	}
})
