package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("early data", func() {
	const rtt = 80 * time.Millisecond
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			It("sends 0.5-RTT data", func() {
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					getTLSConfig(),
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write([]byte("early data"))
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
					// make sure the Write finished before the handshake completed
					Expect(sess.HandshakeComplete().Done()).ToNot(BeClosed())
					Eventually(sess.HandshakeComplete().Done(), protocol.DefaultHandshakeTimeout).Should(BeClosed())
					close(done)
				}()
				serverPort := ln.Addr().(*net.UDPAddr).Port
				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: func(quicproxy.Direction, []byte) time.Duration {
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal([]byte("early data")))
				sess.Close()
				Eventually(done).Should(BeClosed())
			})
		})
	}
})
