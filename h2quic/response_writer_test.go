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
	id           protocol.StreamID
	dataToRead   bytes.Buffer
	dataWritten  bytes.Buffer
	reset        bool
	closed       bool
	remoteClosed bool
}

func (s *mockStream) Close() error                          { s.closed = true; return nil }
func (s *mockStream) Reset(error)                           { s.reset = true }
func (s *mockStream) CloseRemote(offset protocol.ByteCount) { s.remoteClosed = true }
func (s mockStream) StreamID() protocol.StreamID            { return s.id }

func (s *mockStream) Read(p []byte) (int, error)  { return s.dataToRead.Read(p) }
func (s *mockStream) Write(p []byte) (int, error) { return s.dataWritten.Write(p) }

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
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x5, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 'H', 0x3, '4', '1', '8',
		}))
	})

	It("writes headers", func() {
		w.Header().Add("content-length", "42")
		w.WriteHeader(http.StatusTeapot)
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x9, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x48, 0x3, 0x34, 0x31, 0x38, 0x5c, 0x2, 0x34, 0x32,
		}))
	})

	It("writes multiple headers with the same name", func() {
		w.Header().Add("set-cookie", "test1=1; Max-Age=7200; path=/")
		w.Header().Add("set-cookie", "test2=2; Max-Age=7200; path=/")
		w.WriteHeader(http.StatusTeapot)
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{0x00, 0x00, 0x33, 0x01, 0x04, 0x00, 0x00, 0x00, 0x05,
			0x48, 0x03, 0x34, 0x31, 0x38, 0x77, 0x95, 0x49, 0x50, 0x90, 0xc0, 0x1f, 0xb5, 0x34, 0x0f, 0xca, 0xd0, 0xcc,
			0x58, 0x1d, 0x10, 0x01, 0xf6, 0xa5, 0x63, 0x4c, 0xf0, 0x31, 0x77, 0x95, 0x49, 0x50, 0x91, 0x40, 0x2f, 0xb5,
			0x34, 0x0f, 0xca, 0xd0, 0xcc, 0x58, 0x1d, 0x10, 0x01, 0xf6, 0xa5, 0x63, 0x4c, 0xf0, 0x31}))
	})

	It("writes data", func() {
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x88,
		}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte{
			0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
		}))
	})

	It("writes data after WriteHeader is called", func() {
		w.WriteHeader(http.StatusTeapot)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{
			0x0, 0x0, 0x5, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 'H', 0x3, '4', '1', '8',
		}))
		// And foobar on the data stream
		Expect(dataStream.dataWritten.Bytes()).To(Equal([]byte{
			0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
		}))
	})

	It("does not WriteHeader() twice", func() {
		w.WriteHeader(200)
		w.WriteHeader(500)
		Expect(headerStream.dataWritten.Bytes()).To(Equal([]byte{0x0, 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5, 0x88})) // 0x88 is 200
	})

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		w.WriteHeader(304)
		n, err := w.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
		Expect(dataStream.dataWritten.Bytes()).To(HaveLen(0))
	})
})
