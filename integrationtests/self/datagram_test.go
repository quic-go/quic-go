package self_test

import (
	"context"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagram test", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			const num = 100

			var (
				proxy                  *quicproxy.QuicProxy
				serverConn, clientConn *net.UDPConn
				dropped, total         int32
			)

			startServerAndProxy := func(enableDatagram, expectDatagramSupport bool) {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				serverConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
				ln, err := quic.Listen(
					serverConn,
					getTLSConfig(),
					getQuicConfig(&quic.Config{
						EnableDatagrams: enableDatagram,
						Versions:        []protocol.VersionNumber{version},
					}),
				)
				Expect(err).ToNot(HaveOccurred())

				go func() {
					defer GinkgoRecover()
					conn, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())

					if expectDatagramSupport {
						Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())

						if enableDatagram {
							var wg sync.WaitGroup
							wg.Add(num)
							for i := 0; i < num; i++ {
								go func(i int) {
									defer GinkgoRecover()
									defer wg.Done()
									b := make([]byte, 8)
									binary.BigEndian.PutUint64(b, uint64(i))
									Expect(conn.SendMessage(b)).To(Succeed())
								}(i)
							}
							wg.Wait()
						}
					} else {
						Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())
					}
				}()

				serverPort := ln.Addr().(*net.UDPAddr).Port
				proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					// drop 10% of Short Header packets sent from the server
					DropPacket: func(dir quicproxy.Direction, packet []byte) bool {
						if dir == quicproxy.DirectionIncoming {
							return false
						}
						// don't drop Long Header packets
						if wire.IsLongHeaderPacket(packet[0]) {
							return false
						}
						drop := mrand.Int()%10 == 0
						if drop {
							atomic.AddInt32(&dropped, 1)
						}
						atomic.AddInt32(&total, 1)
						return drop
					},
				})
				Expect(err).ToNot(HaveOccurred())
			}

			BeforeEach(func() {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				clientConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				Expect(proxy.Close()).To(Succeed())
			})

			It("sends datagrams", func() {
				startServerAndProxy(true, true)
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
				Expect(err).ToNot(HaveOccurred())
				conn, err := quic.Dial(
					clientConn,
					raddr,
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						EnableDatagrams: true,
						Versions:        []protocol.VersionNumber{version},
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.ConnectionState().SupportsDatagrams).To(BeTrue())
				var counter int
				for {
					// Close the connection if no message is received for 100 ms.
					timer := time.AfterFunc(scaleDuration(100*time.Millisecond), func() {
						conn.CloseWithError(0, "")
					})
					if _, err := conn.ReceiveMessage(); err != nil {
						break
					}
					timer.Stop()
					counter++
				}

				numDropped := int(atomic.LoadInt32(&dropped))
				expVal := num - numDropped
				fmt.Fprintf(GinkgoWriter, "Dropped %d out of %d packets.\n", numDropped, atomic.LoadInt32(&total))
				fmt.Fprintf(GinkgoWriter, "Received %d out of %d sent datagrams.\n", counter, num)
				Expect(counter).To(And(
					BeNumerically(">", expVal*9/10),
					BeNumerically("<", num),
				))
			})

			It("server can disable datagram", func() {
				startServerAndProxy(false, true)
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
				Expect(err).ToNot(HaveOccurred())
				conn, err := quic.Dial(
					clientConn,
					raddr,
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						EnableDatagrams: true,
						Versions:        []protocol.VersionNumber{version},
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())

				conn.CloseWithError(0, "")
				<-time.After(10 * time.Millisecond)
			})

			It("client can disable datagram", func() {
				startServerAndProxy(false, true)
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
				Expect(err).ToNot(HaveOccurred())
				conn, err := quic.Dial(
					clientConn,
					raddr,
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						EnableDatagrams: true,
						Versions:        []protocol.VersionNumber{version},
					}),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.ConnectionState().SupportsDatagrams).To(BeFalse())

				Expect(conn.SendMessage([]byte{0})).To(HaveOccurred())
				conn.CloseWithError(0, "")
				<-time.After(10 * time.Millisecond)
			})
		})
	}
})
