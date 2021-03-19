package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

type rcvdPacket struct {
	hdr    *logging.ExtendedHeader
	frames []logging.Frame
}

type rcvdPacketTracer struct {
	connTracer
	closed      chan struct{}
	rcvdPackets []rcvdPacket
}

func newRcvdPacketTracer() *rcvdPacketTracer {
	return &rcvdPacketTracer{closed: make(chan struct{})}
}

func (t *rcvdPacketTracer) ReceivedPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, frames []logging.Frame) {
	t.rcvdPackets = append(t.rcvdPackets, rcvdPacket{hdr: hdr, frames: frames})
}
func (t *rcvdPacketTracer) Close() { close(t.closed) }
func (t *rcvdPacketTracer) getRcvdPackets() []rcvdPacket {
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
				clientTLSConf *tls.Config,
				clientConf *quic.Config,
				testdata []byte, // data to transfer
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
					Expect(sess.ConnectionState().TLS.Used0RTT).To(BeTrue())
					Expect(sess.CloseWithError(0, "")).To(Succeed())
					close(done)
				}()

				if clientConf == nil {
					clientConf = getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}})
				}
				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxyPort),
					clientTLSConf,
					clientConf,
				)
				Expect(err).ToNot(HaveOccurred())
				defer sess.CloseWithError(0, "")
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(testdata)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				Expect(sess.ConnectionState().TLS.Used0RTT).To(BeTrue())
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
			get0RTTPackets := func(packets []rcvdPacket) []protocol.PacketNumber {
				var zeroRTTPackets []protocol.PacketNumber
				for _, p := range packets {
					if p.hdr.Type == protocol.PacketType0RTT {
						zeroRTTPackets = append(zeroRTTPackets, p.hdr.PacketNumber)
					}
				}
				return zeroRTTPackets
			}

			for _, l := range []int{0, 15} {
				connIDLen := l

				It(fmt.Sprintf("transfers 0-RTT data, with %d byte connection IDs", connIDLen), func() {
					tlsConf, clientTLSConf := dialAndReceiveSessionTicket(nil)

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

					transfer0RTTData(
						ln,
						proxy.LocalPort(),
						clientTLSConf,
						&quic.Config{
							ConnectionIDLength: connIDLen,
							Versions:           []protocol.VersionNumber{version},
						},
						PRData,
					)

					var numNewConnIDs int
					for _, p := range tracer.getRcvdPackets() {
						for _, f := range p.frames {
							if _, ok := f.(*logging.NewConnectionIDFrame); ok {
								numNewConnIDs++
							}
						}
					}
					if connIDLen == 0 {
						Expect(numNewConnIDs).To(BeZero())
					} else {
						Expect(numNewConnIDs).ToNot(BeZero())
					}

					num0RTT := atomic.LoadUint32(num0RTTPackets)
					fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
					Expect(num0RTT).ToNot(BeZero())
					zeroRTTPackets := get0RTTPackets(tracer.getRcvdPackets())
					Expect(len(zeroRTTPackets)).To(BeNumerically(">", 10))
					sort.Slice(zeroRTTPackets, func(i, j int) bool { return zeroRTTPackets[i] < zeroRTTPackets[j] })
					Expect(zeroRTTPackets[0]).To(Equal(protocol.PacketNumber(0)))
				})
			}

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
				Expect(get0RTTPackets(tracer.getRcvdPackets())).To(HaveLen(int(num0RTT)))
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

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, nil, PRData)

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

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, nil, GeneratePRData(5000)) // ~5 packets

				mutex.Lock()
				defer mutex.Unlock()
				Expect(firstCounter).To(BeNumerically("~", 5000+100 /* framing overhead */, 100)) // the FIN bit might be sent extra
				Expect(secondCounter).To(BeNumerically("~", firstCounter, 20))
				zeroRTTPackets := get0RTTPackets(tracer.getRcvdPackets())
				Expect(len(zeroRTTPackets)).To(BeNumerically(">=", 5))
				Expect(zeroRTTPackets[0]).To(BeNumerically(">=", protocol.PacketNumber(5)))
			})

			It("doesn't reject 0-RTT when the server's transport stream limit increased", func() {
				const maxStreams = 1
				tlsConf, clientConf := dialAndReceiveSessionTicket(getQuicConfig(&quic.Config{
					MaxIncomingUniStreams: maxStreams,
					AcceptToken:           func(_ net.Addr, _ *quic.Token) bool { return true },
				}))

				tracer := newRcvdPacketTracer()
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					tlsConf,
					getQuicConfig(&quic.Config{
						Versions:              []protocol.VersionNumber{version},
						AcceptToken:           func(_ net.Addr, _ *quic.Token) bool { return true },
						MaxIncomingUniStreams: maxStreams + 1,
						Tracer:                newTracer(func() logging.ConnectionTracer { return tracer }),
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					clientConf,
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				// The client remembers the old limit and refuses to open a new stream.
				_, err = sess.OpenUniStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("too many open streams"))
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, err = sess.OpenUniStreamSync(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.CloseWithError(0, "")).To(Succeed())

				// The client should send 0-RTT packets.
				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
				Expect(get0RTTPackets(tracer.getRcvdPackets())).ToNot(BeEmpty())
			})

			It("rejects 0-RTT when the server's stream limit decreased", func() {
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
						MaxIncomingStreams: maxStreams - 1,
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

			DescribeTable("flow control limits",
				func(addFlowControlLimit func(*quic.Config, uint64)) {
					tracer := newRcvdPacketTracer()
					firstConf := getQuicConfig(&quic.Config{
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
						Versions:    []protocol.VersionNumber{version},
					})
					addFlowControlLimit(firstConf, 3)
					tlsConf, clientConf := dialAndReceiveSessionTicket(firstConf)

					secondConf := getQuicConfig(&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
						Tracer:      newTracer(func() logging.ConnectionTracer { return tracer }),
					})
					addFlowControlLimit(secondConf, 100)
					ln, err := quic.ListenAddrEarly(
						"localhost:0",
						tlsConf,
						secondConf,
					)
					Expect(err).ToNot(HaveOccurred())
					defer ln.Close()
					proxy, _ := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
					defer proxy.Close()

					sess, err := quic.DialAddrEarly(
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						clientConf,
						getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
					)
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					written := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						defer close(written)
						_, err := str.Write([]byte("foobar"))
						Expect(err).ToNot(HaveOccurred())
						Expect(str.Close()).To(Succeed())
					}()

					Eventually(written).Should(BeClosed())

					serverSess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					rstr, err := serverSess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(rstr)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal([]byte("foobar")))
					Expect(serverSess.ConnectionState().TLS.Used0RTT).To(BeTrue())
					Expect(serverSess.CloseWithError(0, "")).To(Succeed())
					Eventually(sess.Context().Done()).Should(BeClosed())

					var processedFirst bool
					for _, p := range tracer.getRcvdPackets() {
						for _, f := range p.frames {
							if sf, ok := f.(*logging.StreamFrame); ok {
								if !processedFirst {
									// The first STREAM should have been sent in a 0-RTT packet.
									// Due to the flow control limit, the STREAM frame was limit to the first 3 bytes.
									Expect(p.hdr.Type).To(Equal(protocol.PacketType0RTT))
									Expect(sf.Length).To(BeEquivalentTo(3))
									processedFirst = true
								} else {
									// All other STREAM frames can only be sent after handshake completion.
									Expect(p.hdr.IsLongHeader).To(BeFalse())
									Expect(sf.Offset).ToNot(BeZero())
								}
							}
						}
					}
				},
				Entry("doesn't reject 0-RTT when the server's transport stream flow control limit increased", func(c *quic.Config, limit uint64) { c.InitialStreamReceiveWindow = limit }),
				Entry("doesn't reject 0-RTT when the server's transport connection flow control limit increased", func(c *quic.Config, limit uint64) { c.InitialConnectionReceiveWindow = limit }),
			)

			for _, l := range []int{0, 15} {
				connIDLen := l

				It(fmt.Sprintf("correctly deals with 0-RTT rejections, for %d byte connection IDs", connIDLen), func() {
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

					sess, err := quic.DialAddrEarly(
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						clientConf,
						getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
					)
					Expect(err).ToNot(HaveOccurred())
					// The client remembers that it was allowed to open 2 uni-directional streams.
					firstStr, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					written := make(chan struct{}, 2)
					go func() {
						defer GinkgoRecover()
						defer func() { written <- struct{}{} }()
						_, err := firstStr.Write([]byte("first flight"))
						Expect(err).ToNot(HaveOccurred())
					}()
					secondStr, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					go func() {
						defer GinkgoRecover()
						defer func() { written <- struct{}{} }()
						_, err := secondStr.Write([]byte("first flight"))
						Expect(err).ToNot(HaveOccurred())
					}()

					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_, err = sess.AcceptStream(ctx)
					Expect(err).To(MatchError(quic.Err0RTTRejected))
					Eventually(written).Should(Receive())
					Eventually(written).Should(Receive())
					_, err = firstStr.Write([]byte("foobar"))
					Expect(err).To(MatchError(quic.Err0RTTRejected))
					_, err = sess.OpenUniStream()
					Expect(err).To(MatchError(quic.Err0RTTRejected))

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
					Expect(sess.CloseWithError(0, "")).To(Succeed())

					// The client should send 0-RTT packets, but the server doesn't process them.
					num0RTT := atomic.LoadUint32(num0RTTPackets)
					fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
					Expect(num0RTT).ToNot(BeZero())
					Expect(get0RTTPackets(tracer.getRcvdPackets())).To(BeEmpty())
				})
			}

			It("queues 0-RTT packets, if the Initial is delayed", func() {
				tlsConf, clientConf := dialAndReceiveSessionTicket(nil)

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
				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: ln.Addr().String(),
					DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming && data[0]&0x80 > 0 && data[0]&0x30>>4 == 0 { // Initial packet from client
							return rtt/2 + rtt
						}
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				transfer0RTTData(ln, proxy.LocalPort(), clientConf, nil, PRData)

				Expect(tracer.rcvdPackets[0].hdr.Type).To(Equal(protocol.PacketTypeInitial))
				zeroRTTPackets := get0RTTPackets(tracer.getRcvdPackets())
				Expect(len(zeroRTTPackets)).To(BeNumerically(">", 10))
				Expect(zeroRTTPackets[0]).To(Equal(protocol.PacketNumber(0)))
			})
		})
	}
})
