package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var directions = []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth}

type applicationProtocol struct {
	name string
	run  func(ln *quic.Listener, port int)
}

var _ = Describe("Handshake drop tests", func() {
	data := GeneratePRData(5000)
	const timeout = 2 * time.Minute

	startListenerAndProxy := func(dropCallback quicproxy.DropCallback, doRetry bool, longCertChain bool) (ln *quic.Listener, proxyPort int, closeFn func()) {
		conf := getQuicConfig(&quic.Config{
			MaxIdleTimeout:       timeout,
			HandshakeIdleTimeout: timeout,
		})
		var tlsConf *tls.Config
		if longCertChain {
			tlsConf = getTLSConfigWithLongCertChain()
		} else {
			tlsConf = getTLSConfig()
		}
		laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", laddr)
		Expect(err).ToNot(HaveOccurred())
		tr := &quic.Transport{Conn: conn}
		if doRetry {
			tr.VerifySourceAddress = func(net.Addr) bool { return true }
		}
		ln, err = tr.Listen(tlsConf, conf)
		Expect(err).ToNot(HaveOccurred())
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DropPacket: dropCallback,
			DelayPacket: func(dir quicproxy.Direction, packet []byte) time.Duration {
				return 10 * time.Millisecond
			},
		})
		Expect(err).ToNot(HaveOccurred())

		return ln, proxy.LocalPort(), func() {
			ln.Close()
			tr.Close()
			conn.Close()
			proxy.Close()
		}
	}

	clientSpeaksFirst := &applicationProtocol{
		name: "client speaks first",
		run: func(ln *quic.Listener, port int) {
			serverConnChan := make(chan quic.Connection)
			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				defer conn.CloseWithError(0, "")
				str, err := conn.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				b, err := io.ReadAll(gbytes.TimeoutReader(str, timeout))
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(Equal(data))
				serverConnChan <- conn
			}()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())

			var serverConn quic.Connection
			Eventually(serverConnChan, timeout).Should(Receive(&serverConn))
			conn.CloseWithError(0, "")
			serverConn.CloseWithError(0, "")
		},
	}

	serverSpeaksFirst := &applicationProtocol{
		name: "server speaks first",
		run: func(ln *quic.Listener, port int) {
			serverConnChan := make(chan quic.Connection)
			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.OpenStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(data)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				serverConnChan <- conn
			}()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			b, err := io.ReadAll(gbytes.TimeoutReader(str, timeout))
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(data))

			var serverConn quic.Connection
			Eventually(serverConnChan, timeout).Should(Receive(&serverConn))
			conn.CloseWithError(0, "")
			serverConn.CloseWithError(0, "")
		},
	}

	nobodySpeaks := &applicationProtocol{
		name: "nobody speaks",
		run: func(ln *quic.Listener, port int) {
			serverConnChan := make(chan quic.Connection)
			go func() {
				defer GinkgoRecover()
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				serverConnChan <- conn
			}()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", port),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			var serverConn quic.Connection
			Eventually(serverConnChan, timeout).Should(Receive(&serverConn))
			// both server and client accepted a connection. Close now.
			conn.CloseWithError(0, "")
			serverConn.CloseWithError(0, "")
		},
	}

	for _, d := range directions {
		direction := d

		for _, dr := range []bool{true, false} {
			doRetry := dr
			desc := "when using Retry"
			if !dr {
				desc = "when not using Retry"
			}

			Context(desc, func() {
				for _, lcc := range []bool{false, true} {
					longCertChain := lcc

					Context(fmt.Sprintf("using a long certificate chain: %t", longCertChain), func() {
						for _, a := range []*applicationProtocol{clientSpeaksFirst, serverSpeaksFirst, nobodySpeaks} {
							app := a

							Context(app.name, func() {
								It(fmt.Sprintf("establishes a connection when the first packet is lost in %s direction", direction), func() {
									var incoming, outgoing atomic.Int32
									ln, proxyPort, closeFn := startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
										var p int32
										//nolint:exhaustive
										switch d {
										case quicproxy.DirectionIncoming:
											p = incoming.Add(1)
										case quicproxy.DirectionOutgoing:
											p = outgoing.Add(1)
										}
										return p == 1 && d.Is(direction)
									}, doRetry, longCertChain)
									defer closeFn()
									app.run(ln, proxyPort)
								})

								It(fmt.Sprintf("establishes a connection when the second packet is lost in %s direction", direction), func() {
									var incoming, outgoing atomic.Int32
									ln, proxyPort, closeFn := startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
										var p int32
										//nolint:exhaustive
										switch d {
										case quicproxy.DirectionIncoming:
											p = incoming.Add(1)
										case quicproxy.DirectionOutgoing:
											p = outgoing.Add(1)
										}
										return p == 2 && d.Is(direction)
									}, doRetry, longCertChain)
									defer closeFn()
									app.run(ln, proxyPort)
								})

								It(fmt.Sprintf("establishes a connection when 1/3 of the packets are lost in %s direction", direction), func() {
									const maxSequentiallyDropped = 10
									var mx sync.Mutex
									var incoming, outgoing int

									ln, proxyPort, closeFn := startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
										drop := mrand.Int63n(int64(3)) == 0

										mx.Lock()
										defer mx.Unlock()
										// never drop more than 10 consecutive packets
										if d.Is(quicproxy.DirectionIncoming) {
											if drop {
												incoming++
												if incoming > maxSequentiallyDropped {
													drop = false
												}
											}
											if !drop {
												incoming = 0
											}
										}
										if d.Is(quicproxy.DirectionOutgoing) {
											if drop {
												outgoing++
												if outgoing > maxSequentiallyDropped {
													drop = false
												}
											}
											if !drop {
												outgoing = 0
											}
										}
										return drop
									}, doRetry, longCertChain)
									defer closeFn()
									app.run(ln, proxyPort)
								})
							})
						}
					})
				}
			})
		}

		It("establishes a connection when the ClientHello is larger than 1 MTU (e.g. post-quantum)", func() {
			origAdditionalTransportParametersClient := wire.AdditionalTransportParametersClient
			defer func() {
				wire.AdditionalTransportParametersClient = origAdditionalTransportParametersClient
			}()
			b := make([]byte, 2500) // the ClientHello will now span across 3 packets
			mrand.New(mrand.NewSource(GinkgoRandomSeed())).Read(b)
			wire.AdditionalTransportParametersClient = map[uint64][]byte{
				// Avoid random collisions with the greased transport parameters.
				uint64(27+31*(1000+mrand.Int63()/31)) % quicvarint.Max: b,
			}

			ln, proxyPort, closeFn := startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
				if d == quicproxy.DirectionOutgoing {
					return false
				}
				return mrand.Intn(3) == 0
			}, false, false)
			defer closeFn()
			clientSpeaksFirst.run(ln, proxyPort)
		})
	}
})
