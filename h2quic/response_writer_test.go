package h2quic

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStream struct {
	id protocol.StreamID
	bytes.Buffer
	remoteClosed bool
}

func (mockStream) Close() error                             { return nil }
func (s *mockStream) CloseRemote(offset protocol.ByteCount) { s.remoteClosed = true }
func (s mockStream) StreamID() protocol.StreamID            { return s.id }

var _ = Describe("Response Writer", func() {
	var (
		w            *responseWriter
		headerStream *mockStream
		dataStream   *mockStream
	)

	BeforeEach(func() {
		headerStream = &mockStream{}
		dataStream = &mockStream{}
		w = newResponseWriter(headerStream, &sync.Mutex{}, dataStream, 5)
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

	It("writes data", func() {
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		Expect(headerStream.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x88,
		}))
		// And foobar on the data stream
		Expect(dataStream.Bytes()).To(Equal([]byte{
			0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
		}))
	})

	It("writes data after WriteHeader is called", func() {
		w.WriteHeader(http.StatusTeapot)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		Expect(headerStream.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x5, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 'H', 0x3, '4', '1', '8',
		}))
		// And foobar on the data stream
		Expect(dataStream.Bytes()).To(Equal([]byte{
			0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
		}))
	})

	It("does not WriteHeader() twice", func() {
		w.WriteHeader(200)
		w.WriteHeader(500)
		Expect(headerStream.Bytes()).To(Equal([]byte{0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x88})) // 0x88 is 200
	})
})
