package self_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type connIDGenerator struct {
	length int
}

func (c *connIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, c.length)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintf(GinkgoWriter, "generating conn ID failed: %s", err)
	}
	return protocol.ParseConnectionID(b), nil
}

func (c *connIDGenerator) ConnectionIDLen() int {
	return c.length
}

var _ = Describe("Connection ID lengths tests", func() {
	randomConnIDLen := func() int {
		return 4 + int(mrand.Int31n(15))
	}

	runServer := func(conf *quic.Config) quic.Listener {
		GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID for the server\n", conf.ConnectionIDLength)))
		ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), conf)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer GinkgoRecover()
					str, err := conn.OpenStream()
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
		defer cl.CloseWithError(0, "")
		str, err := cl.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRData))
	}

	It("downloads a file using a 0-byte connection ID for the client", func() {
		serverConf := getQuicConfig(&quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		})
		clientConf := getQuicConfig(&quic.Config{
			Versions: []protocol.VersionNumber{protocol.VersionTLS},
		})

		ln := runServer(serverConf)
		defer ln.Close()
		runClient(ln.Addr(), clientConf)
	})

	It("downloads a file when both client and server use a random connection ID length", func() {
		serverConf := getQuicConfig(&quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		})
		clientConf := getQuicConfig(&quic.Config{
			ConnectionIDLength: randomConnIDLen(),
			Versions:           []protocol.VersionNumber{protocol.VersionTLS},
		})

		ln := runServer(serverConf)
		defer ln.Close()
		runClient(ln.Addr(), clientConf)
	})

	It("downloads a file when both client and server use a custom connection ID generator", func() {
		serverConf := getQuicConfig(&quic.Config{
			Versions:              []protocol.VersionNumber{protocol.VersionTLS},
			ConnectionIDGenerator: &connIDGenerator{length: randomConnIDLen()},
		})
		clientConf := getQuicConfig(&quic.Config{
			Versions:              []protocol.VersionNumber{protocol.VersionTLS},
			ConnectionIDGenerator: &connIDGenerator{length: randomConnIDLen()},
		})

		ln := runServer(serverConf)
		defer ln.Close()
		runClient(ln.Addr(), clientConf)
	})
})
