package h2quic

import (
	"bytes"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStream struct {
	bytes.Buffer
}

func (mockStream) Close() error { return nil }

var _ = Describe("Response Writer", func() {
	var (
		w            *responseWriter
		headerStream *mockStream
	)

	BeforeEach(func() {
		headerStream = &mockStream{}
		w = newResponseWriter(headerStream, 5, nil)
	})

	It("writes status", func() {
		w.WriteHeader(http.StatusTeapot)
		Expect(headerStream.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x5, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 'H', 0x3, '4', '1', '8',
		}))
	})

	It("writes headers", func() {
		w.Header().Add("content-length", "42")
		w.WriteHeader(http.StatusTeapot)
		Expect(headerStream.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x14, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x48, 0x3, 0x34, 0x31, 0x38,
			0x40, 0x8a, 0xbc, 0x7a, 0x92, 0x5a, 0x92, 0xb6, 0x72, 0xd5, 0x32, 0x67,
			0x2, 0x34, 0x32,
		}))
	})
})
