package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Fake Conn", func() {
	var (
		c      *fakeConn
		stream *bytes.Buffer
	)

	BeforeEach(func() {
		stream = &bytes.Buffer{}
		c = &fakeConn{stream: stream}
	})

	Context("Reading", func() {
		It("doesn't return any new data after one Read call", func() {
			stream.Write([]byte("foobar"))
			b := make([]byte, 3)
			_, err := c.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("foo")))
			n, err := c.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(BeZero())
		})

		It("allows more Read calls after unblocking", func() {
			stream.Write([]byte("foobar"))
			b := make([]byte, 3)
			_, err := c.Read(b)
			Expect(err).ToNot(HaveOccurred())
			err = c.Continue()
			Expect(err).ToNot(HaveOccurred())
			_, err = c.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("bar")))
		})
	})

	Context("Writing", func() {
		It("writes directly when acting as a client", func() {
			c.pers = protocol.PerspectiveClient
			_, err := c.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stream.Bytes()).To(Equal([]byte("foobar")))
		})

		It("only writes after flushing when acting as a server", func() {
			c.pers = protocol.PerspectiveServer
			_, err := c.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stream.Bytes()).To(BeEmpty())
			err = c.Continue()
			Expect(err).ToNot(HaveOccurred())
			Expect(stream.Bytes()).To(Equal([]byte("foobar")))
		})
	})
})
