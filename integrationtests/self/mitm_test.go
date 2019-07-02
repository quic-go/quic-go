package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"math"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MITM test", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			const connIDLen = 6 // explicitly set the connection ID length, so the proxy can parse it

			var (
				proxy                  *quicproxy.QuicProxy
				serverConn, clientConn *net.UDPConn
				serverSess             quic.Session
				serverConfig           *quic.Config
			)

			startServerAndProxy := func(delayCb quicproxy.DelayCallback, dropCb quicproxy.DropCallback) {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				serverConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
				ln, err := quic.Listen(serverConn, getTLSConfig(), serverConfig)
				Expect(err).ToNot(HaveOccurred())
				go func() {
					defer GinkgoRecover()
					var err error
					serverSess, err = ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := serverSess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write(testserver.PRData)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
				}()
				serverPort := ln.Addr().(*net.UDPAddr).Port
				proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr:  fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: delayCb,
					DropPacket:  dropCb,
				})
				Expect(err).ToNot(HaveOccurred())
			}

			BeforeEach(func() {
				serverConfig = &quic.Config{
					Versions:           []protocol.VersionNumber{version},
					ConnectionIDLength: connIDLen,
				}
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				clientConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				Eventually(serverSess.Context().Done()).Should(BeClosed())
				// Test shutdown is tricky due to the proxy. Just wait for a bit.
				time.Sleep(50 * time.Millisecond)
				Expect(clientConn.Close()).To(Succeed())
				Expect(serverConn.Close()).To(Succeed())
				Expect(proxy.Close()).To(Succeed())
			})

			Context("injecting invalid packets", func() {
				const rtt = 20 * time.Millisecond

				sendRandomPacketsOfSameType := func(conn net.PacketConn, remoteAddr net.Addr, raw []byte) {
					defer GinkgoRecover()
					hdr, _, _, err := wire.ParsePacket(raw, connIDLen)
					Expect(err).ToNot(HaveOccurred())
					replyHdr := &wire.ExtendedHeader{
						Header: wire.Header{
							IsLongHeader:     hdr.IsLongHeader,
							DestConnectionID: hdr.DestConnectionID,
							SrcConnectionID:  hdr.SrcConnectionID,
							Type:             hdr.Type,
							Version:          hdr.Version,
						},
						PacketNumber:    protocol.PacketNumber(mrand.Int31n(math.MaxInt32 / 4)),
						PacketNumberLen: protocol.PacketNumberLen(mrand.Int31n(4) + 1),
					}

					const numPackets = 10
					ticker := time.NewTicker(rtt / numPackets)
					for i := 0; i < numPackets; i++ {
						payloadLen := mrand.Int31n(100)
						replyHdr.Length = protocol.ByteCount(mrand.Int31n(payloadLen + 1))
						buf := &bytes.Buffer{}
						Expect(replyHdr.Write(buf, v)).To(Succeed())
						b := make([]byte, payloadLen)
						mrand.Read(b)
						buf.Write(b)
						if _, err := conn.WriteTo(buf.Bytes(), remoteAddr); err != nil {
							return
						}
						<-ticker.C
					}
				}

				runTest := func(delayCb quicproxy.DelayCallback) {
					startServerAndProxy(delayCb, nil)
					raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
					Expect(err).ToNot(HaveOccurred())
					sess, err := quic.Dial(
						clientConn,
						raddr,
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						getTLSClientConfig(),
						&quic.Config{
							Versions:           []protocol.VersionNumber{version},
							ConnectionIDLength: connIDLen,
						},
					)
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testserver.PRData))
					Expect(sess.Close()).To(Succeed())
				}

				It("downloads a message when the packets are injected towards the server", func() {
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming {
							defer GinkgoRecover()
							go sendRandomPacketsOfSameType(clientConn, serverConn.LocalAddr(), raw)
						}
						return rtt / 2
					}
					runTest(delayCb)
				})

				It("downloads a message when the packets are injected towards the client", func() {
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionOutgoing {
							defer GinkgoRecover()
							go sendRandomPacketsOfSameType(serverConn, clientConn.LocalAddr(), raw)
						}
						return rtt / 2
					}
					runTest(delayCb)
				})
			})

			runTest := func(dropCb quicproxy.DropCallback) {
				startServerAndProxy(nil, dropCb)
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
				Expect(err).ToNot(HaveOccurred())
				sess, err := quic.Dial(
					clientConn,
					raddr,
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					&quic.Config{
						Versions:           []protocol.VersionNumber{version},
						ConnectionIDLength: connIDLen,
					},
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(testserver.PRData))
				Expect(sess.Close()).To(Succeed())
			}

			Context("duplicating packets", func() {
				It("downloads a message when packets are duplicated towards the server", func() {
					dropCb := func(dir quicproxy.Direction, raw []byte) bool {
						defer GinkgoRecover()
						if dir == quicproxy.DirectionIncoming {
							_, err := clientConn.WriteTo(raw, serverConn.LocalAddr())
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
							_, err := serverConn.WriteTo(raw, clientConn.LocalAddr())
							Expect(err).ToNot(HaveOccurred())
						}
						return false
					}
					runTest(dropCb)
				})
			})

			Context("corrupting packets", func() {
				const interval = 10 // corrupt every 10th packet (stochastically)
				const idleTimeout = time.Second

				var numCorrupted int32

				BeforeEach(func() {
					numCorrupted = 0
					serverConfig.IdleTimeout = idleTimeout
				})

				AfterEach(func() {
					num := atomic.LoadInt32(&numCorrupted)
					fmt.Fprintf(GinkgoWriter, "Corrupted %d packets.", num)
					Expect(num).To(BeNumerically(">=", 1))
					// If the packet containing the CONNECTION_CLOSE is corrupted,
					// we have to wait for the session to time out.
					Eventually(serverSess.Context().Done(), 3*idleTimeout).Should(BeClosed())
				})

				It("downloads a message when packet are corrupted towards the server", func() {
					dropCb := func(dir quicproxy.Direction, raw []byte) bool {
						defer GinkgoRecover()
						if dir == quicproxy.DirectionIncoming && mrand.Intn(interval) == 0 {
							pos := mrand.Intn(len(raw))
							raw[pos] = byte(mrand.Intn(256))
							_, err := clientConn.WriteTo(raw, serverConn.LocalAddr())
							Expect(err).ToNot(HaveOccurred())
							atomic.AddInt32(&numCorrupted, 1)
							return true
						}
						return false
					}
					runTest(dropCb)
				})

				It("downloads a message when packet are corrupted towards the client", func() {
					dropCb := func(dir quicproxy.Direction, raw []byte) bool {
						defer GinkgoRecover()
						isRetry := raw[0]&0xc0 == 0xc0 // don't corrupt Retry packets
						if dir == quicproxy.DirectionOutgoing && mrand.Intn(interval) == 0 && !isRetry {
							pos := mrand.Intn(len(raw))
							raw[pos] = byte(mrand.Intn(256))
							_, err := serverConn.WriteTo(raw, clientConn.LocalAddr())
							Expect(err).ToNot(HaveOccurred())
							atomic.AddInt32(&numCorrupted, 1)
							return true
						}
						return false
					}
					runTest(dropCb)
				})
			})
		})
	}
})
