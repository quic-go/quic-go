package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
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
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := conn.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write([]byte("early data"))
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
					// make sure the Write finished before the handshake completed
					Expect(conn.HandshakeComplete().Done()).ToNot(BeClosed())
					Eventually(conn.Context().Done()).Should(BeClosed())
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

				conn, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{version}}),
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.AcceptUniStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				data, err := io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal([]byte("early data")))
				conn.CloseWithError(0, "")
				Eventually(done).Should(BeClosed())
			})
		})
	}
})
