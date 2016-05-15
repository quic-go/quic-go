package h2quic

import (
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockSession struct {
	closed bool
}

func (s *mockSession) GetOrOpenStream(id protocol.StreamID) (utils.Stream, error) {
	return &mockStream{}, nil
}

func (s *mockSession) Close(error, bool) error { s.closed = true; return nil }

var _ = Describe("H2 server", func() {
	var (
		s       *Server
		session *mockSession
	)

	BeforeEach(func() {
		var err error
		s, err = NewServer(testdata.GetTLSConfig())
		Expect(err).NotTo(HaveOccurred())
		Expect(s).NotTo(BeNil())
		session = &mockSession{}
	})

	It("uses default handler", func() {
		// We try binding to a low port number, s.t. it always fails
		err := s.ListenAndServe("127.0.0.1:80", nil)
		Expect(err).To(HaveOccurred())
		Expect(s.handler).To(Equal(http.DefaultServeMux))
	})

	It("sets handler properly", func() {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		// We try binding to a low port number, s.t. it always fails
		err := s.ListenAndServe("127.0.0.1:80", h)
		Expect(err).To(HaveOccurred())
		Expect(s.handler).NotTo(Equal(http.DefaultServeMux))
	})

	Context("handling requests", func() {
		var (
			h2framer     *http2.Framer
			hpackDecoder *hpack.Decoder
			headerStream *mockStream
		)

		BeforeEach(func() {
			headerStream = &mockStream{}
			hpackDecoder = hpack.NewDecoder(4096, nil)
			h2framer = http2.NewFramer(nil, headerStream)
		})

		It("handles a sample request", func() {
			var handlerCalled bool
			s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Host).To(Equal("www.example.com"))
				handlerCalled = true
			})
			headerStream.Write([]byte{
				0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
			})
			err := s.handleRequest(session, headerStream, hpackDecoder, h2framer)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool { return handlerCalled }).Should(BeTrue())
		})
	})

	It("handles the header stream", func() {
		var handlerCalled bool
		s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Host).To(Equal("www.example.com"))
			handlerCalled = true
		})
		headerStream := &mockStream{id: 3}
		headerStream.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		s.handleStream(session, headerStream)
		Eventually(func() bool { return handlerCalled }).Should(BeTrue())
	})

	It("ignores other streams", func() {
		var handlerCalled bool
		s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Host).To(Equal("www.example.com"))
			handlerCalled = true
		})
		headerStream := &mockStream{id: 5}
		headerStream.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		s.handleStream(session, headerStream)
		Consistently(func() bool { return handlerCalled }).Should(BeFalse())
	})

	It("supports closing after first request", func() {
		s.CloseAfterFirstRequest = true
		s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		headerStream := &mockStream{id: 3}
		headerStream.Write([]byte{
			0x0, 0x0, 0x11, 0x1, 0x4, 0x0, 0x0, 0x0, 0x5,
			// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
			0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
		})
		Expect(session.closed).To(BeFalse())
		s.handleStream(session, headerStream)
		Eventually(func() bool { return session.closed }).Should(BeTrue())
	})
})
