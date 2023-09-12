package versionnegotiation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/integrationtests/tools/israce"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type versioner interface {
	GetVersion() protocol.VersionNumber
}

type result struct {
	loggedVersions                 bool
	receivedVersionNegotiation     bool
	chosen                         logging.VersionNumber
	clientVersions, serverVersions []logging.VersionNumber
}

func newVersionNegotiationTracer() (*result, *logging.ConnectionTracer) {
	r := &result{}
	return r, &logging.ConnectionTracer{
		NegotiatedVersion: func(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
			if r.loggedVersions {
				Fail("only expected one call to NegotiatedVersions")
			}
			r.loggedVersions = true
			r.chosen = chosen
			r.clientVersions = clientVersions
			r.serverVersions = serverVersions
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
			r.receivedVersionNegotiation = true
		},
	}
}

var _ = Describe("Handshake tests", func() {
	startServer := func(tlsConf *tls.Config, conf *quic.Config) (*quic.Listener, func()) {
		server, err := quic.ListenAddr("localhost:0", tlsConf, conf)
		Expect(err).ToNot(HaveOccurred())

		acceptStopped := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(acceptStopped)
			for {
				if _, err := server.Accept(context.Background()); err != nil {
					return
				}
			}
		}()

		return server, func() {
			server.Close()
			<-acceptStopped
		}
	}

	var supportedVersions []protocol.VersionNumber

	BeforeEach(func() {
		supportedVersions = append([]quic.VersionNumber{}, protocol.SupportedVersions...)
		protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.VersionNumber{7, 8, 9, 10}...)
	})

	AfterEach(func() {
		protocol.SupportedVersions = supportedVersions
	})

	if !israce.Enabled {
		It("when the server supports more versions than the client", func() {
			expectedVersion := protocol.SupportedVersions[0]
			// the server doesn't support the highest supported version, which is the first one the client will try
			// but it supports a bunch of versions that the client doesn't speak
			serverConfig := &quic.Config{}
			serverConfig.Versions = []protocol.VersionNumber{7, 8, protocol.SupportedVersions[0], 9}
			serverResult, serverTracer := newVersionNegotiationTracer()
			serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return serverTracer
			}
			server, cl := startServer(getTLSConfig(), serverConfig)
			defer cl()
			clientResult, clientTracer := newVersionNegotiationTracer()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				maybeAddQLOGTracer(&quic.Config{Tracer: func(ctx context.Context, perspective logging.Perspective, id quic.ConnectionID) *logging.ConnectionTracer {
					return clientTracer
				}}),
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.(versioner).GetVersion()).To(Equal(expectedVersion))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(clientResult.chosen).To(Equal(expectedVersion))
			Expect(clientResult.receivedVersionNegotiation).To(BeFalse())
			Expect(clientResult.clientVersions).To(Equal(protocol.SupportedVersions))
			Expect(clientResult.serverVersions).To(BeEmpty())
			Expect(serverResult.chosen).To(Equal(expectedVersion))
			Expect(serverResult.serverVersions).To(Equal(serverConfig.Versions))
			Expect(serverResult.clientVersions).To(BeEmpty())
		})

		It("when the client supports more versions than the server supports", func() {
			expectedVersion := protocol.SupportedVersions[0]
			// The server doesn't support the highest supported version, which is the first one the client will try,
			// but it supports a bunch of versions that the client doesn't speak
			serverResult, serverTracer := newVersionNegotiationTracer()
			serverConfig := &quic.Config{}
			serverConfig.Versions = supportedVersions
			serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return serverTracer
			}
			server, cl := startServer(getTLSConfig(), serverConfig)
			defer cl()
			clientVersions := []protocol.VersionNumber{7, 8, 9, protocol.SupportedVersions[0], 10}
			clientResult, clientTracer := newVersionNegotiationTracer()
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				maybeAddQLOGTracer(&quic.Config{
					Versions: clientVersions,
					Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
						return clientTracer
					},
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.(versioner).GetVersion()).To(Equal(protocol.SupportedVersions[0]))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(clientResult.chosen).To(Equal(expectedVersion))
			Expect(clientResult.receivedVersionNegotiation).To(BeTrue())
			Expect(clientResult.clientVersions).To(Equal(clientVersions))
			Expect(clientResult.serverVersions).To(ContainElements(supportedVersions)) // may contain greased versions
			Expect(serverResult.chosen).To(Equal(expectedVersion))
			Expect(serverResult.serverVersions).To(Equal(serverConfig.Versions))
			Expect(serverResult.clientVersions).To(BeEmpty())
		})

		It("fails if the server disables version negotiation", func() {
			// The server doesn't support the highest supported version, which is the first one the client will try,
			// but it supports a bunch of versions that the client doesn't speak
			_, serverTracer := newVersionNegotiationTracer()
			serverConfig := &quic.Config{}
			serverConfig.Versions = supportedVersions
			serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return serverTracer
			}
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			Expect(err).ToNot(HaveOccurred())
			tr := &quic.Transport{
				Conn:                             conn,
				DisableVersionNegotiationPackets: true,
			}
			ln, err := tr.Listen(getTLSConfig(), serverConfig)
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			clientVersions := []protocol.VersionNumber{7, 8, 9, protocol.SupportedVersions[0], 10}
			clientResult, clientTracer := newVersionNegotiationTracer()
			_, err = quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", conn.LocalAddr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				maybeAddQLOGTracer(&quic.Config{
					Versions: clientVersions,
					Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
						return clientTracer
					},
					HandshakeIdleTimeout: 100 * time.Millisecond,
				}),
			)
			Expect(err).To(HaveOccurred())
			var nerr net.Error
			Expect(errors.As(err, &nerr)).To(BeTrue())
			Expect(nerr.Timeout()).To(BeTrue())
			Expect(clientResult.receivedVersionNegotiation).To(BeFalse())
		})
	}
})
