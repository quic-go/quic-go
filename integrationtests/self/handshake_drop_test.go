package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var directions = []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth}

type applicationProtocol struct {
	name string
	run  func(protocol.VersionNumber)
}

var _ = Describe("Handshake drop tests", func() {
	var (
		proxy *quicproxy.QuicProxy
		ln    quic.Listener
	)

	data := GeneratePRData(5000)
	const timeout = 2 * time.Minute

	startListenerAndProxy := func(dropCallback quicproxy.DropCallback, doRetry bool, longCertChain bool, version protocol.VersionNumber) {
		conf := getQuicConfig(&quic.Config{
			MaxIdleTimeout:       timeout,
			HandshakeIdleTimeout: timeout,
			Versions:             []protocol.VersionNumber{version},
		})
		if !doRetry {
			conf.AcceptToken = func(net.Addr, *quic.Token) bool { return true }
		}
		var tlsConf *tls.Config
		if longCertChain {
			tlsConf = getTLSConfigWithLongCertChain()
		} else {
			tlsConf = getTLSConfig()
		}
		var err error
		ln, err = quic.ListenAddr("localhost:0", tlsConf, conf)
		Expect(err).ToNot(HaveOccurred())
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DropPacket: dropCallback,
			DelayPacket: func(dir quicproxy.Direction, packet []byte) time.Duration {
				return 10 * time.Millisecond
			},
		})
		Expect(err).ToNot(HaveOccurred())
	}

	stochasticDropper := func(freq int) bool {
		return mrand.Int63n(int64(freq)) == 0
	}

	clientSpeaksFirst := &applicationProtocol{
		name: "client speaks first",
		run: func(version protocol.VersionNumber) {
			serverSessionChan := make(chan quic.Session)
			go func() {
				defer GinkgoRecover()
				sess, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				defer sess.CloseWithError(0, "")
				str, err := sess.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				b, err := ioutil.ReadAll(gbytes.TimeoutReader(str, timeout))
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(Equal(data))
				serverSessionChan <- sess
			}()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
					Versions:             []protocol.VersionNumber{version},
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())

			var serverSession quic.Session
			Eventually(serverSessionChan, timeout).Should(Receive(&serverSession))
			sess.CloseWithError(0, "")
			serverSession.CloseWithError(0, "")
		},
	}

	serverSpeaksFirst := &applicationProtocol{
		name: "server speaks first",
		run: func(version protocol.VersionNumber) {
			serverSessionChan := make(chan quic.Session)
			go func() {
				defer GinkgoRecover()
				sess, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.OpenStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(data)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				serverSessionChan <- sess
			}()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
					Versions:             []protocol.VersionNumber{version},
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			b, err := ioutil.ReadAll(gbytes.TimeoutReader(str, timeout))
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(data))

			var serverSession quic.Session
			Eventually(serverSessionChan, timeout).Should(Receive(&serverSession))
			sess.CloseWithError(0, "")
			serverSession.CloseWithError(0, "")
		},
	}

	nobodySpeaks := &applicationProtocol{
		name: "nobody speaks",
		run: func(version protocol.VersionNumber) {
			serverSessionChan := make(chan quic.Session)
			go func() {
				defer GinkgoRecover()
				sess, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				serverSessionChan <- sess
			}()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					MaxIdleTimeout:       timeout,
					HandshakeIdleTimeout: timeout,
					Versions:             []protocol.VersionNumber{version},
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			var serverSession quic.Session
			Eventually(serverSessionChan, timeout).Should(Receive(&serverSession))
			// both server and client accepted a session. Close now.
			sess.CloseWithError(0, "")
			serverSession.CloseWithError(0, "")
		},
	}

	AfterEach(func() {
		Expect(ln.Close()).To(Succeed())
		Expect(proxy.Close()).To(Succeed())
	})

	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
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
											var incoming, outgoing int32
											startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
												var p int32
												//nolint:exhaustive
												switch d {
												case quicproxy.DirectionIncoming:
													p = atomic.AddInt32(&incoming, 1)
												case quicproxy.DirectionOutgoing:
													p = atomic.AddInt32(&outgoing, 1)
												}
												return p == 1 && d.Is(direction)
											}, doRetry, longCertChain, version)
											app.run(version)
										})

										It(fmt.Sprintf("establishes a connection when the second packet is lost in %s direction", direction), func() {
											var incoming, outgoing int32
											startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
												var p int32
												//nolint:exhaustive
												switch d {
												case quicproxy.DirectionIncoming:
													p = atomic.AddInt32(&incoming, 1)
												case quicproxy.DirectionOutgoing:
													p = atomic.AddInt32(&outgoing, 1)
												}
												return p == 2 && d.Is(direction)
											}, doRetry, longCertChain, version)
											app.run(version)
										})

										It(fmt.Sprintf("establishes a connection when 1/3 of the packets are lost in %s direction", direction), func() {
											startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
												return d.Is(direction) && stochasticDropper(3)
											}, doRetry, longCertChain, version)
											app.run(version)
										})
									})
								}
							})
						}
					})
				}
			}
		})
	}
})
