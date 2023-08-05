package versionnegotiation

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake RTT tests", func() {
	const rtt = 400 * time.Millisecond

	expectDurationInRTTs := func(startTime time.Time, num int) {
		testDuration := time.Since(startTime)
		rtts := float32(testDuration) / float32(rtt)
		Expect(rtts).To(SatisfyAll(
			BeNumerically(">=", num),
			BeNumerically("<", num+1),
		))
	}

	It("fails when there's no matching version, after 1 RTT", func() {
		if len(protocol.SupportedVersions) == 1 {
			Skip("Test requires at least 2 supported versions.")
		}

		serverConfig := &quic.Config{}
		serverConfig.Versions = protocol.SupportedVersions[:1]
		ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		// start the proxy
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  ln.Addr().String(),
			DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration { return rtt / 2 },
		})
		Expect(err).ToNot(HaveOccurred())

		startTime := time.Now()
		_, err = quic.DialAddr(
			context.Background(),
			proxy.LocalAddr().String(),
			getTLSClientConfig(),
			maybeAddQLOGTracer(&quic.Config{Versions: protocol.SupportedVersions[1:2]}),
		)
		Expect(err).To(HaveOccurred())
		expectDurationInRTTs(startTime, 1)
	})
})
