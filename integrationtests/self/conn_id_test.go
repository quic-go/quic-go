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
	randomConnIDLen := func() int { return 4 + int(mrand.Int31n(15)) }

	// connIDLen is ignored when connIDGenerator is set
	runServer := func(connIDLen int, connIDGenerator quic.ConnectionIDGenerator) (*quic.Listener, func()) {
		if connIDGenerator != nil {
			GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID generator for the server\n", connIDGenerator.ConnectionIDLen())))
		} else {
			GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID for the server\n", connIDLen)))
		}
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		tr := &quic.Transport{
			Conn:                  conn,
			ConnectionIDLength:    connIDLen,
			ConnectionIDGenerator: connIDGenerator,
		}
		ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
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
		return ln, func() {
			ln.Close()
			tr.Close()
		}
	}

	// connIDLen is ignored when connIDGenerator is set
	runClient := func(addr net.Addr, connIDLen int, connIDGenerator quic.ConnectionIDGenerator) {
		if connIDGenerator != nil {
			GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID generator for the client\n", connIDGenerator.ConnectionIDLen())))
		} else {
			GinkgoWriter.Write([]byte(fmt.Sprintf("Using %d byte connection ID for the client\n", connIDLen)))
		}
		laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", laddr)
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()
		tr := &quic.Transport{
			Conn:                  conn,
			ConnectionIDLength:    connIDLen,
			ConnectionIDGenerator: connIDGenerator,
		}
		defer tr.Close()
		cl, err := tr.Dial(
			context.Background(),
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.(*net.UDPAddr).Port},
			getTLSClientConfig(),
			getQuicConfig(nil),
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
		ln, closeFn := runServer(randomConnIDLen(), nil)
		defer closeFn()
		runClient(ln.Addr(), 0, nil)
	})

	It("downloads a file when both client and server use a random connection ID length", func() {
		ln, closeFn := runServer(randomConnIDLen(), nil)
		defer closeFn()
		runClient(ln.Addr(), randomConnIDLen(), nil)
	})

	It("downloads a file when both client and server use a custom connection ID generator", func() {
		ln, closeFn := runServer(0, &connIDGenerator{length: randomConnIDLen()})
		defer closeFn()
		runClient(ln.Addr(), 0, &connIDGenerator{length: randomConnIDLen()})
	})
})
