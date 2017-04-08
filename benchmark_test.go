package quic

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Benchmarks", func() {
	dataLen := 50 /* MB */ * (1 << 20)
	data := make([]byte, dataLen)

	rand.Seed(time.Now().UnixNano())

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with version %d", version), func() {
			Measure("transferring a file", func(b Benchmarker) {
				rand.Read(data) // no need to check for an error. math.Rand.Read never errors

				// start the server
				sconf := &Config{
					TLSConfig: testdata.GetTLSConfig(),
					ConnState: func(sess Session, cs ConnState) {
						if cs != ConnStateForwardSecure {
							return
						}

						defer GinkgoRecover()
						str, err := sess.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						_, err = str.Write(data)
						Expect(err).ToNot(HaveOccurred())
						err = str.Close()
						Expect(err).ToNot(HaveOccurred())
					},
				}
				ln, err := ListenAddr("localhost:0", sconf)
				Expect(err).ToNot(HaveOccurred())
				// Serve will error as soon as ln is closed. Ignore all errors here
				go ln.Serve()

				// start the client
				cconf := &Config{
					TLSConfig: &tls.Config{InsecureSkipVerify: true},
				}
				sess, err := DialAddr(ln.Addr().String(), cconf)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.AcceptStream()
				Expect(err).ToNot(HaveOccurred())

				buf := &bytes.Buffer{}
				// measure the time it takes to download the dataLen bytes
				// note we're measuring the time for the transfer, i.e. excluding the handshake
				runtime := b.Time("transfer time", func() {
					_, err := io.Copy(buf, str)
					Expect(err).NotTo(HaveOccurred())
				})
				// this is *a lot* faster than Expect(buf.Bytes()).To(Equal(data))
				Expect(bytes.Equal(buf.Bytes(), data)).To(BeTrue())

				b.RecordValue("transfer rate [MB/s]", float64(dataLen)/1e6/runtime.Seconds())

				ln.Close()
				sess.Close(nil)
			}, 6)
		})
	}
})
