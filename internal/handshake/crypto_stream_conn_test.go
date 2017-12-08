package handshake

import (
	"bytes"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CryptoStreamConn", func() {
	var (
		csc        *CryptoStreamConn
		remoteAddr net.Addr
	)

	BeforeEach(func() {
		remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
		csc = NewCryptoStreamConn(remoteAddr)
	})

	It("reads from the read buffer, when no stream is set", func() {
		csc.AddDataForReading([]byte("foobar"))
		data := make([]byte, 4)
		n, err := csc.Read(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(4))
		Expect(data).To(Equal([]byte("foob")))
	})

	It("writes to the write buffer, when no stream is set", func() {
		csc.Write([]byte("foo"))
		Expect(csc.GetDataForWriting()).To(Equal([]byte("foo")))
		csc.Write([]byte("bar"))
		Expect(csc.GetDataForWriting()).To(Equal([]byte("bar")))
	})

	It("reads from the stream, if available", func() {
		csc.stream = &bytes.Buffer{}
		csc.stream.Write([]byte("foobar"))
		data := make([]byte, 3)
		n, err := csc.Read(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(data).To(Equal([]byte("foo")))
	})

	It("writes to the stream, if available", func() {
		stream := &bytes.Buffer{}
		csc.SetStream(stream)
		csc.Write([]byte("foobar"))
		Expect(stream.Bytes()).To(Equal([]byte("foobar")))
	})

	It("returns the remote address", func() {
		Expect(csc.RemoteAddr()).To(Equal(remoteAddr))
	})

	It("has unimplemented methods", func() {
		Expect(csc.Close()).ToNot(HaveOccurred())
		Expect(csc.SetDeadline(time.Time{})).ToNot(HaveOccurred())
		Expect(csc.SetReadDeadline(time.Time{})).ToNot(HaveOccurred())
		Expect(csc.SetWriteDeadline(time.Time{})).ToNot(HaveOccurred())
		Expect(csc.LocalAddr()).To(BeNil())
	})
})
