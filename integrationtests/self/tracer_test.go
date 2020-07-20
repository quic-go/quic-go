package self_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/metrics"
	"github.com/lucas-clemente/quic-go/qlog"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake tests", func() {
	addTracers := func(pers protocol.Perspective, conf *quic.Config) *quic.Config {
		enableQlog := mrand.Int()%3 != 0
		enableMetrics := mrand.Int()%3 != 0

		fmt.Fprintf(GinkgoWriter, "%s using qlog: %t, metrics: %t\n", pers, enableQlog, enableMetrics)

		var tracers []logging.Tracer
		if enableQlog {
			tracers = append(tracers, qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
				if mrand.Int()%2 == 0 { // simulate that a qlog collector might only want to log some connections
					fmt.Fprintf(GinkgoWriter, "%s qlog tracer deciding to not trace connection %x\n", p, connectionID)
					return nil
				}
				fmt.Fprintf(GinkgoWriter, "%s qlog tracing connection %x\n", p, connectionID)
				return utils.NewBufferedWriteCloser(bufio.NewWriter(&bytes.Buffer{}), ioutil.NopCloser(nil))
			}))
		}
		if enableMetrics {
			tracers = append(tracers, metrics.NewTracer())
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
				sess, err := ln.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(PRData)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()

			ln := <-serverChan
			defer ln.Close()

			sess, err := quic.DialAddr(
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
				getTLSClientConfig(),
				quicClientConf,
			)
			Expect(err).ToNot(HaveOccurred())
			defer sess.CloseWithError(0, "")
			str, err := sess.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			data, err := ioutil.ReadAll(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal(PRData))
		})
	}
})
