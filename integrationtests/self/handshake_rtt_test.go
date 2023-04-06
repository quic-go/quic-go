package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake RTT tests", func() {
	var (
		proxy           *quicproxy.QuicProxy
		serverConfig    *quic.Config
		serverTLSConfig *tls.Config
	)

	const rtt = 400 * time.Millisecond

	BeforeEach(func() {
		serverConfig = getQuicConfig(nil)
		serverTLSConfig = getTLSConfig()
	})

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
	})

	runProxy := func(serverAddr net.Addr) {
		var err error
		// start the proxy
		proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr:  serverAddr.String(),
			DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration { return rtt / 2 },
		})
		Expect(err).ToNot(HaveOccurred())
	}

	expectDurationInRTTs := func(startTime time.Time, num int) {
		testDuration := time.Since(startTime)
		rtts := float32(testDuration) / float32(rtt)
		Expect(rtts).To(SatisfyAll(
			BeNumerically(">=", num),
			BeNumerically("<", num+1),
		))
	}

	// 1 RTT for verifying the source address
	// 1 RTT for the TLS handshake
	It("is forward-secure after 2 RTTs", func() {
		serverConfig.RequireAddressValidation = func(net.Addr) bool { return true }
		ln, err := quic.ListenAddr("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		runProxy(ln.Addr())
		startTime := time.Now()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		expectDurationInRTTs(startTime, 2)
	})

	It("establishes a connection in 1 RTT when the server doesn't require a token", func() {
		ln, err := quic.ListenAddr("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		runProxy(ln.Addr())
		startTime := time.Now()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		expectDurationInRTTs(startTime, 1)
	})

	It("establishes a connection in 2 RTTs if a HelloRetryRequest is performed", func() {
		serverTLSConfig.CurvePreferences = []tls.CurveID{tls.CurveP384}
		ln, err := quic.ListenAddr("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		runProxy(ln.Addr())
		startTime := time.Now()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		expectDurationInRTTs(startTime, 2)
	})

	It("receives the first message from the server after 2 RTTs, when the server uses ListenAddr", func() {
		ln, err := quic.ListenAddr("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())
		}()
		defer ln.Close()

		runProxy(ln.Addr())
		startTime := time.Now()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foobar")))
		expectDurationInRTTs(startTime, 2)
	})

	It("receives the first message from the server after 1 RTT, when the server uses ListenAddrEarly", func() {
		ln, err := quic.ListenAddrEarly("localhost:0", serverTLSConfig, serverConfig)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			// Check the ALPN now. This is probably what an application would do.
			// It makes sure that ConnectionState does not block until the handshake completes.
			Expect(conn.ConnectionState().TLS.NegotiatedProtocol).To(Equal(alpn))
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())
		}()
		defer ln.Close()

		runProxy(ln.Addr())
		startTime := time.Now()
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalAddr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foobar")))
		expectDurationInRTTs(startTime, 1)
	})
})
