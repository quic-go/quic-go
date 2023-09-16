package self_test

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	sentHeaders     []*logging.ShortHeader
	receivedHeaders []*logging.ShortHeader
)

func countKeyPhases() (sent, received int) {
	lastKeyPhase := protocol.KeyPhaseOne
	for _, hdr := range sentHeaders {
		if hdr.KeyPhase != lastKeyPhase {
			sent++
			lastKeyPhase = hdr.KeyPhase
		}
	}
	lastKeyPhase = protocol.KeyPhaseOne
	for _, hdr := range receivedHeaders {
		if hdr.KeyPhase != lastKeyPhase {
			received++
			lastKeyPhase = hdr.KeyPhase
		}
	}
	return
}

var keyUpdateConnTracer = &logging.ConnectionTracer{
	SentShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
		sentHeaders = append(sentHeaders, hdr)
	},
	ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ []logging.Frame) {
		receivedHeaders = append(receivedHeaders, hdr)
	},
}

var _ = Describe("Key Update tests", func() {
	It("downloads a large file", func() {
		origKeyUpdateInterval := handshake.KeyUpdateInterval
		defer func() { handshake.KeyUpdateInterval = origKeyUpdateInterval }()
		handshake.KeyUpdateInterval = 1 // update keys as frequently as possible

		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			defer str.Close()
			_, err = str.Write(PRDataLong)
			Expect(err).ToNot(HaveOccurred())
		}()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return keyUpdateConnTracer
			}}),
		)
		Expect(err).ToNot(HaveOccurred())
		str, err := conn.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRDataLong))
		Expect(conn.CloseWithError(0, "")).To(Succeed())

		keyPhasesSent, keyPhasesReceived := countKeyPhases()
		fmt.Fprintf(GinkgoWriter, "Used %d key phases on outgoing and %d key phases on incoming packets.\n", keyPhasesSent, keyPhasesReceived)
		Expect(keyPhasesReceived).To(BeNumerically(">", 10))
		Expect(keyPhasesReceived).To(BeNumerically("~", keyPhasesSent, 2))
	})
})
