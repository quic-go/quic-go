package self_test

import (
	"context"
	"fmt"
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

	startListenerAndProxy := func(dropCallback quicproxy.DropCallback, version protocol.VersionNumber) {
		var err error
		ln, err = quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			&quic.Config{
				Versions: []protocol.VersionNumber{version},
			},
		)
		Expect(err).ToNot(HaveOccurred())
		serverPort := ln.Addr().(*net.UDPAddr).Port
		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DropPacket: dropCallback,
		},
		)
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
				defer sess.Close()
				str, err := sess.AcceptStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				b := make([]byte, 6)
				_, err = gbytes.TimeoutReader(str, 10*time.Second).Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(b)).To(Equal("foobar"))
				serverSessionChan <- sess
			}()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				&quic.Config{Versions: []protocol.VersionNumber{version}},
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			var serverSession quic.Session
			Eventually(serverSessionChan, 10*time.Second).Should(Receive(&serverSession))
			sess.Close()
			serverSession.Close()
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
				_, err = str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				serverSessionChan <- sess
			}()
			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", proxy.LocalPort()),
				getTLSClientConfig(),
				&quic.Config{Versions: []protocol.VersionNumber{version}},
			)
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			_, err = gbytes.TimeoutReader(str, 10*time.Second).Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(b)).To(Equal("foobar"))

			var serverSession quic.Session
			Eventually(serverSessionChan, 10*time.Second).Should(Receive(&serverSession))
			sess.Close()
			serverSession.Close()
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
				&quic.Config{Versions: []protocol.VersionNumber{version}},
			)
			Expect(err).ToNot(HaveOccurred())
			var serverSession quic.Session
			Eventually(serverSessionChan, 10*time.Second).Should(Receive(&serverSession))
			// both server and client accepted a session. Close now.
			sess.Close()
			serverSession.Close()
		},
	}

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
	})

	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			for _, d := range directions {
				direction := d

				for _, a := range []*applicationProtocol{clientSpeaksFirst, serverSpeaksFirst, nobodySpeaks} {
					app := a

					Context(app.name, func() {
						It(fmt.Sprintf("establishes a connection when the first packet is lost in %s direction", direction), func() {
							var incoming, outgoing int32
							startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
								var p int32
								switch d {
								case quicproxy.DirectionIncoming:
									p = atomic.AddInt32(&incoming, 1)
								case quicproxy.DirectionOutgoing:
									p = atomic.AddInt32(&outgoing, 1)
								}
								return p == 1 && d.Is(direction)
							}, version)
							app.run(version)
						})

						It(fmt.Sprintf("establishes a connection when the second packet is lost in %s direction", direction), func() {
							var incoming, outgoing int32
							startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
								var p int32
								switch d {
								case quicproxy.DirectionIncoming:
									p = atomic.AddInt32(&incoming, 1)
								case quicproxy.DirectionOutgoing:
									p = atomic.AddInt32(&outgoing, 1)
								}
								return p == 2 && d.Is(direction)
							}, version)
							app.run(version)
						})

						It(fmt.Sprintf("establishes a connection when 1/5 of the packets are lost in %s direction", direction), func() {
							startListenerAndProxy(func(d quicproxy.Direction, _ []byte) bool {
								return d.Is(direction) && stochasticDropper(5)
							}, version)
							app.run(version)
						})
					})
				}
			}
		})
	}
})
