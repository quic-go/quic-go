package self_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	mrand "math/rand"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type customTracer struct{ logging.NullTracer }

func (t *customTracer) TracerForConnection(context.Context, logging.Perspective, logging.ConnectionID) logging.ConnectionTracer {
	return &customConnTracer{}
}

type customConnTracer struct{ logging.NullConnectionTracer }

var _ = Describe("Handshake tests", func() {
	addTracers := func(pers protocol.Perspective, conf *quic.Config) *quic.Config {
		enableQlog := mrand.Int()%3 != 0
		enableCustomTracer := mrand.Int()%3 != 0

		fmt.Fprintf(GinkgoWriter, "%s using qlog: %t, custom: %t\n", pers, enableQlog, enableCustomTracer)

		var tracers []logging.Tracer
		if enableQlog {
			tracers = append(tracers, qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
				if mrand.Int()%2 == 0 { // simulate that a qlog collector might only want to log some connections
					fmt.Fprintf(GinkgoWriter, "%s qlog tracer deciding to not trace connection %x\n", p, connectionID)
					return nil
				}
				fmt.Fprintf(GinkgoWriter, "%s qlog tracing connection %x\n", p, connectionID)
				return utils.NewBufferedWriteCloser(bufio.NewWriter(&bytes.Buffer{}), io.NopCloser(nil))
			}))
		}
		if enableCustomTracer {
			tracers = append(tracers, &customTracer{})
		}
		c := conf.Clone()
		c.Tracer = logging.NewMultiplexedTracer(tracers...)
		return c
	}

	for i := 0; i < 3; i++ {
		It("handshakes with a random combination of tracers", func() {
			if enableQlog {
				Skip("This test sets tracers and won't produce any qlogs.")
			}
			quicClientConf := addTracers(protocol.PerspectiveClient, getQuicConfig(nil))
			quicServerConf := addTracers(protocol.PerspectiveServer, getQuicConfig(nil))

			serverChan := make(chan quic.Listener)
			go func() {
				defer GinkgoRecover()
				ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), quicServerConf)
				Expect(err).ToNot(HaveOccurred())
				serverChan <- ln
				conn, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := conn.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(PRData)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()

			ln := <-serverChan
			defer ln.Close()

			conn, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicClientConf,
			)
			Expect(err).ToNot(HaveOccurred())
			defer conn.CloseWithError(0, "")
			str, err := conn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := io.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(PRData))
		})
	}
})
