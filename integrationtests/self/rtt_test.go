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

var _ = Describe("non-zero RTT", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			roundTrips := [...]time.Duration{
				10 * time.Millisecond,
				50 * time.Millisecond,
				100 * time.Millisecond,
				200 * time.Millisecond,
			}

			for _, r := range roundTrips {
				rtt := r

				It(fmt.Sprintf("downloads a message with %s RTT", rtt), func() {
					ln, err := quic.ListenAddr(
						"localhost:0",
						getTLSConfig(),
						&quic.Config{
							Versions: []protocol.VersionNumber{version},
						},
					)
					Expect(err).ToNot(HaveOccurred())
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						sess, err := ln.Accept(context.Background())
						Expect(err).ToNot(HaveOccurred())
						str, err := sess.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						_, err = str.Write(PRData)
						Expect(err).ToNot(HaveOccurred())
						str.Close()
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
					str, err := sess.AcceptStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					sess.Close()
					Eventually(done).Should(BeClosed())
				})
			}
		})
	}
})
