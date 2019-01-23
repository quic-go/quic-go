package h2quic

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Body", func() {
	var (
		stream *mockStream
		body   *responseBody
	)

	BeforeEach(func() {
		stream = newMockStream(42)
		body = &responseBody{dataStream: stream}
	})

	It("calls CancelRead if the stream is closed before being completely read", func() {
		stream.dataToRead = *bytes.NewBuffer([]byte("foobar"))
		n, err := body.Read(make([]byte, 3))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(body.Close()).To(Succeed())
		Expect(stream.canceledRead).To(BeTrue())
	})

	It("doesn't calls CancelRead if the stream was completely read", func() {
		stream.dataToRead = *bytes.NewBuffer([]byte("foobar"))
		close(stream.unblockRead)
		n, _ := body.Read(make([]byte, 6))
		Expect(n).To(Equal(6))
		_, err := body.Read(make([]byte, 6))
		Expect(err).To(Equal(io.EOF))
		Expect(body.Close()).To(Succeed())
		Expect(stream.canceledRead).To(BeFalse())
	})
})
