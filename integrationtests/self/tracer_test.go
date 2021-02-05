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
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type customTracer struct{}

var _ logging.Tracer = &customTracer{}

func (t *customTracer) TracerForConnection(p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	return &customConnTracer{}
}
func (t *customTracer) SentPacket(net.Addr, *logging.Header, logging.ByteCount, []logging.Frame) {}
func (t *customTracer) DroppedPacket(net.Addr, logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

type customConnTracer struct{}

var _ logging.ConnectionTracer = &customConnTracer{}

func (t *customConnTracer) StartedConnection(local, remote net.Addr, version logging.VersionNumber, srcConnID, destConnID logging.ConnectionID) {
}
func (t *customConnTracer) ClosedConnection(logging.CloseReason)                     {}
func (t *customConnTracer) SentTransportParameters(*logging.TransportParameters)     {}
func (t *customConnTracer) ReceivedTransportParameters(*logging.TransportParameters) {}
func (t *customConnTracer) RestoredTransportParameters(*logging.TransportParameters) {}
func (t *customConnTracer) SentPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
}

func (t *customConnTracer) ReceivedVersionNegotiationPacket(*logging.Header, []logging.VersionNumber) {
}
func (t *customConnTracer) ReceivedRetry(*logging.Header) {}
func (t *customConnTracer) ReceivedPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) {
}
func (t *customConnTracer) BufferedPacket(logging.PacketType) {}
func (t *customConnTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

func (t *customConnTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (t *customConnTracer) LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
}
func (t *customConnTracer) UpdatedCongestionState(logging.CongestionState)                     {}
func (t *customConnTracer) UpdatedPTOCount(value uint32)                                       {}
func (t *customConnTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective)     {}
func (t *customConnTracer) UpdatedKey(generation logging.KeyPhase, remote bool)                {}
func (t *customConnTracer) DroppedEncryptionLevel(logging.EncryptionLevel)                     {}
func (t *customConnTracer) DroppedKey(logging.KeyPhase)                                        {}
func (t *customConnTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {}
func (t *customConnTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel)        {}
func (t *customConnTracer) LossTimerCanceled()                                                 {}
func (t *customConnTracer) Debug(string, string)                                               {}
func (t *customConnTracer) Close()                                                             {}

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
				return utils.NewBufferedWriteCloser(bufio.NewWriter(&bytes.Buffer{}), ioutil.NopCloser(nil))
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
