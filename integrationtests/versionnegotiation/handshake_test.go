package versionnegotiation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

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

type versionNegotiationTracer struct {
	logging.NullConnectionTracer

	loggedVersions                 bool
	receivedVersionNegotiation     bool
	chosen                         logging.VersionNumber
	clientVersions, serverVersions []logging.VersionNumber
}

var _ logging.ConnectionTracer = &versionNegotiationTracer{}

func (t *versionNegotiationTracer) NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
	if t.loggedVersions {
		Fail("only expected one call to NegotiatedVersions")
	}
	t.loggedVersions = true
	t.chosen = chosen
	t.clientVersions = clientVersions
	t.serverVersions = serverVersions
}

func (t *versionNegotiationTracer) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
	t.receivedVersionNegotiation = true
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
			serverTracer := &versionNegotiationTracer{}
			serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) logging.ConnectionTracer {
				return serverTracer
			}
			server, cl := startServer(getTLSConfig(), serverConfig)
			defer cl()
			clientTracer := &versionNegotiationTracer{}
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				maybeAddQLOGTracer(&quic.Config{Tracer: func(ctx context.Context, perspective logging.Perspective, id quic.ConnectionID) logging.ConnectionTracer {
					return clientTracer
				}}),
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.(versioner).GetVersion()).To(Equal(expectedVersion))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(clientTracer.chosen).To(Equal(expectedVersion))
			Expect(clientTracer.receivedVersionNegotiation).To(BeFalse())
			Expect(clientTracer.clientVersions).To(Equal(protocol.SupportedVersions))
			Expect(clientTracer.serverVersions).To(BeEmpty())
			Expect(serverTracer.chosen).To(Equal(expectedVersion))
			Expect(serverTracer.serverVersions).To(Equal(serverConfig.Versions))
			Expect(serverTracer.clientVersions).To(BeEmpty())
		})

		It("when the client supports more versions than the server supports", func() {
			expectedVersion := protocol.SupportedVersions[0]
			// the server doesn't support the highest supported version, which is the first one the client will try
			// but it supports a bunch of versions that the client doesn't speak
			serverTracer := &versionNegotiationTracer{}
			serverConfig := &quic.Config{}
			serverConfig.Versions = supportedVersions
			serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) logging.ConnectionTracer {
				return serverTracer
			}
			server, cl := startServer(getTLSConfig(), serverConfig)
			defer cl()
			clientVersions := []protocol.VersionNumber{7, 8, 9, protocol.SupportedVersions[0], 10}
			clientTracer := &versionNegotiationTracer{}
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				maybeAddQLOGTracer(&quic.Config{
					Versions: clientVersions,
					Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) logging.ConnectionTracer {
						return clientTracer
					},
				}),
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.(versioner).GetVersion()).To(Equal(protocol.SupportedVersions[0]))
			Expect(conn.CloseWithError(0, "")).To(Succeed())
			Expect(clientTracer.chosen).To(Equal(expectedVersion))
			Expect(clientTracer.receivedVersionNegotiation).To(BeTrue())
			Expect(clientTracer.clientVersions).To(Equal(clientVersions))
			Expect(clientTracer.serverVersions).To(ContainElements(supportedVersions)) // may contain greased versions
			Expect(serverTracer.chosen).To(Equal(expectedVersion))
			Expect(serverTracer.serverVersions).To(Equal(serverConfig.Versions))
			Expect(serverTracer.clientVersions).To(BeEmpty())
		})
	}
})
