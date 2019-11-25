package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID lengths tests", func() {
	randomConnIDLen := func() int {
		return 4 + int(rand.Int31n(15))
	}

	runServer := func(conf *quic.Config) quic.Listener {
		GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID for the server\n", conf.ConnectionIDLength)))
		ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), conf)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			for {
				sess, err := ln.Accept(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer GinkgoRecover()
					str, err := sess.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					defer str.Close()
					_, err = str.Write(PRData)
					Expect(err).ToNot(HaveOccurred())
				}()
			}
		}()
		return ln
	}

	runClient := func(addr net.Addr, conf *quic.Config) {
		GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID for the client\n", conf.ConnectionIDLength)))
		cl, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", addr.(*net.UDPAddr).Port),
			getTLSClientConfig(),
			conf,
		)
		Expect(err).ToNot(HaveOccurred())
		defer cl.Close()
		str, err := cl.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRData))
	}

	It("downloads a file using a 0-byte connection ID for the client", func() {
		serverConf := &quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		}
		clientConf := &quic.Config{
			Versions: []protocol.VersionNumber{protocol.VersionTLS},
		}

		ln := runServer(serverConf)
		defer ln.Close()
		runClient(ln.Addr(), clientConf)
	})

	It("downloads a file when both client and server use a random connection ID length", func() {
		serverConf := &quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		}
		clientConf := &quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		}

		ln := runServer(serverConf)
		defer ln.Close()
		runClient(ln.Addr(), clientConf)
	})
})
