package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake RTT tests", func() {
	var (
		proxy           *quicproxy.QuicProxy
		server          quic.Listener
		serverConfig    *quic.Config
		serverTLSConfig *tls.Config
		testStartedAt   time.Time
		acceptStopped   chan struct{}
	)

	rtt := 400 * time.Millisecond

	BeforeEach(func() {
		acceptStopped = make(chan struct{})
		serverConfig = getQuicConfig(nil)
		serverTLSConfig = getTLSConfig()
	})

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
		Expect(server.Close()).To(Succeed())
		<-acceptStopped
	})

	runServerAndProxy := func() {
		var err error
		// start the server
		server, err = quic.ListenAddr("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		// start the proxy
		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  server.Addr().String(),
			DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration { return rtt / 2 },
		})
		Expect(err).ToNot(HaveOccurred())

		testStartedAt = time.Now()

		go func() {
			defer GinkgoRecover()
			defer close(acceptStopped)
			for {
				if _, err := server.Accept(context.Background()); err != nil {
					return
				}
			}
		}()
	}

	expectDurationInRTTs := func(num int) {
		testDuration := time.Since(testStartedAt)
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
		serverConfig.Versions = protocol.SupportedVersions[:1]
		runServerAndProxy()
		clientConfig := getQuicConfig(&quic.Config{Versions: protocol.SupportedVersions[1:2]})
		_, err := quic.DialAddr(
			proxy.LocalAddr().String(),
			getTLSClientConfig(),
			clientConfig,
		)
		Expect(err).To(HaveOccurred())
		expectDurationInRTTs(1)
	})

	var clientConfig *quic.Config

	BeforeEach(func() {
		serverConfig.Versions = []protocol.VersionNumber{protocol.VersionTLS}
		clientConfig = getQuicConfig(&quic.Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}})
		clientConfig := getTLSClientConfig()
		clientConfig.InsecureSkipVerify = true
	})

	// 1 RTT for verifying the source address
	// 1 RTT for the TLS handshake
	It("is forward-secure after 2 RTTs", func() {
		serverConfig.RequireAddressValidation = func(net.Addr) bool { return true }
		runServerAndProxy()
		_, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			clientConfig,
		)
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(2)
	})

	It("establishes a connection in 1 RTT when the server doesn't require a token", func() {
		runServerAndProxy()
		_, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			clientConfig,
		)
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(1)
	})

	It("establishes a connection in 2 RTTs if a HelloRetryRequest is performed", func() {
		serverTLSConfig.CurvePreferences = []tls.CurveID{tls.CurveP384}
		runServerAndProxy()
		_, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			clientConfig,
		)
		Expect(err).ToNot(HaveOccurred())
		expectDurationInRTTs(2)
	})
})
