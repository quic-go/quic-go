package h2quic

import (
	"bytes"

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
		body = &responseBody{stream}
	})

	It("calls CancelRead when closing", func() {
		stream.dataToRead = *bytes.NewBuffer([]byte("foobar"))
		n, err := body.Read(make([]byte, 3))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(body.Close()).To(Succeed())
		Expect(stream.canceledRead).To(BeTrue())
	})
})
