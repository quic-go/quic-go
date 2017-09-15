package benchmark

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"

	quic "github.com/lucas-clemente/quic-go"
	_ "github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func init() {
	var _ = Describe("Benchmarks", func() {
		dataLen := size * /* MB */ 1e6
		data := make([]byte, dataLen)
		rand.Seed(GinkgoRandomSeed())
		rand.Read(data) // no need to check for an error. math.Rand.Read never errors

		for _, c := range conditions {
			cond := c
			Context(cond.Description, func() {
				BeforeEach(func() {
					if len(cond.Command) > 0 {
						if !netemAvailable {
							Skip("Skipping. netem not found.")
						}
						execNetem(cond.Command)
					}
				})

				AfterEach(func() {
					// TODO: make sure this is always executed
					if len(cond.Command) > 0 {
						execNetem("tc qdisc del dev lo root")
					}
				})

				Context(tcpContextLabel, func() {
					Measure(fmt.Sprintf("transferring a %d MB file", size), func(b Benchmarker) {
						serverAddr := make(chan *net.TCPAddr)
						go func() {
							defer GinkgoRecover()
							ln, err := tls.Listen(
								"tcp",
								"127.0.0.1:0",
								testdata.GetTLSConfig(),
							)
							serverAddr <- ln.Addr().(*net.TCPAddr)
							sess, err := ln.Accept()
							Expect(err).ToNot(HaveOccurred())
							_, err = sess.Write(data)
							Expect(err).ToNot(HaveOccurred())
							err = sess.Close()
							Expect(err).ToNot(HaveOccurred())
						}()

						addr := <-serverAddr
						conn, err := tls.Dial("tcp", addr.String(), &tls.Config{InsecureSkipVerify: true})
						Expect(err).ToNot(HaveOccurred())

						buf := &bytes.Buffer{}
						// measure the time it takes to download the dataLen bytes
						runtime := b.Time("transfer time", func() {
							_, err := io.Copy(buf, conn)
							Expect(err).NotTo(HaveOccurred())
						})
						Expect(buf.Bytes()).To(Equal(data))
						b.RecordValue(transferRateLabel, float64(dataLen)/(1<<20)/runtime.Seconds())
					}, 5*samples)
				})

				for i := range protocol.SupportedVersions {
					version := protocol.SupportedVersions[i]

					Context(fmt.Sprintf(quicContextLabel, version), func() {
						Measure(fmt.Sprintf("transferring a %d MB file", size), func(b Benchmarker) {
							var ln quic.Listener
							serverAddr := make(chan net.Addr)
							handshakeChan := make(chan struct{})
							// start the server
							go func() {
								defer GinkgoRecover()
								var err error
								ln, err = quic.ListenAddr(
									"localhost:0",
									testdata.GetTLSConfig(),
									&quic.Config{Versions: []protocol.VersionNumber{version}},
								)
								Expect(err).ToNot(HaveOccurred())
								serverAddr <- ln.Addr()
								sess, err := ln.Accept()
								Expect(err).ToNot(HaveOccurred())
								// wait for the client to complete the handshake before sending the data
								// this should not be necessary, but due to timing issues on the CIs, this is necessary to avoid sending too many undecryptable packets
								<-handshakeChan
								str, err := sess.OpenStream()
								Expect(err).ToNot(HaveOccurred())
								_, err = str.Write(data)
								Expect(err).ToNot(HaveOccurred())
								err = str.Close()
								Expect(err).ToNot(HaveOccurred())
							}()

							// start the client
							addr := <-serverAddr
							sess, err := quic.DialAddr(
								addr.String(),
								&tls.Config{InsecureSkipVerify: true},
								&quic.Config{Versions: []protocol.VersionNumber{version}},
							)
							Expect(err).ToNot(HaveOccurred())
							close(handshakeChan)
							str, err := sess.AcceptStream()
							Expect(err).ToNot(HaveOccurred())

							buf := &bytes.Buffer{}
							// measure the time it takes to download the dataLen bytes
							// note we're measuring the time for the transfer, i.e. excluding the handshake
							runtime := b.Time("transfer time", func() {
								_, err := io.Copy(buf, str)
								Expect(err).NotTo(HaveOccurred())
							})
							Expect(buf.Bytes()).To(Equal(data))

							transferRate := float64(dataLen) / 1e6 / runtime.Seconds()
							b.RecordValue(transferRateLabel, transferRate)
							b.RecordValue("comparison to TCP [%]", 100*transferRate/averageTCPTransferRate)

							ln.Close()
							sess.Close(nil)
						}, samples)
					})
				}
			})
		}
	})
}
