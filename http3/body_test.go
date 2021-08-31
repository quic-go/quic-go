package http3

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type bodyType uint8

const (
	bodyTypeRequest bodyType = iota
	bodyTypeResponse
)

func (t bodyType) String() string {
	if t == bodyTypeRequest {
		return "request"
	}
	return "response"
}

var _ = Describe("body", func() {
	var (
		rb          *body
		sess        *mockquic.MockEarlySession
		conn        *connection
		str         *mockquic.MockStream
		rstr        RequestStream
		buf         *bytes.Buffer
		trailers    []qpack.HeaderField
		trailersErr error
		reqDone     chan struct{}
	)

	onTrailers := func(fields []qpack.HeaderField, err error) {
		trailers = fields[:]
		trailersErr = err
	}

	getDataFrame := func(data []byte) []byte {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, uint64(len(data)))
		buf.Write(data)
		return buf.Bytes()
	}

	BeforeEach(func() {
		buf = &bytes.Buffer{}
	})

	for _, bt := range []bodyType{bodyTypeRequest, bodyTypeResponse} {
		bodyType := bt

		Context(fmt.Sprintf("using a %s body", bodyType), func() {
			BeforeEach(func() {
				str = mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Write(b)
				}).AnyTimes()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Read(b)
				}).AnyTimes()
				str.EXPECT().StreamID().AnyTimes()

				sess = mockquic.NewMockEarlySession(mockCtrl)
				conn = newMockConn(sess, Settings{}, Settings{})
				rstr = newRequestStream(conn, str, 0, 0)

				switch bodyType {
				case bodyTypeRequest:
					rb = newRequestBody(rstr, onTrailers)
				case bodyTypeResponse:
					reqDone = make(chan struct{})
					rb = newResponseBody(rstr, onTrailers, reqDone)
				}
			})

			It("reads DATA frames in a single run", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 6)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				Expect(b).To(Equal([]byte("foobar")))
			})

			It("reads DATA frames in multiple runs", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 3)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b).To(Equal([]byte("foo")))
				n, err = rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b).To(Equal([]byte("bar")))
			})

			It("reads DATA frames into too large buffers", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 10)
				n, err := rb.Read(b)
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(6))
				Expect(b[:n]).To(Equal([]byte("foobar")))
			})

			It("reads DATA frames into too large buffers, in multiple runs", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 4)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte("foob")))
				n, err = rb.Read(b)
				// Expect(err).ToNot(HaveOccurred())
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(2))
				Expect(b[:n]).To(Equal([]byte("ar")))
			})

			It("reads multiple DATA frames", func() {
				buf.Write(getDataFrame([]byte("foo")))
				buf.Write(getDataFrame([]byte("bar")))
				b := make([]byte, 6)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				Expect(b[:n]).To(Equal([]byte("foobar")))
			})

			It("reads trailers", func() {
				buf.Write(getDataFrame([]byte("foo")))
				buf.Write(getDataFrame([]byte("bar")))
				fields := []qpack.HeaderField{
					{Name: "foo", Value: "1"},
					{Name: "bar", Value: "2"},
				}
				err := writeHeadersFrame(buf, fields, http.DefaultMaxHeaderBytes)
				Expect(err).ToNot(HaveOccurred())
				b := make([]byte, 10)
				n, err := rb.Read(b)
				b = b[:n]
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(6))
				Expect(b).To(Equal([]byte("foobar")))
				Expect(trailers).To(Equal(fields))
				Expect(trailersErr).ToNot(HaveOccurred())
			})

			It("receives an error on malformed trailers", func() {
				buf.Write(getDataFrame([]byte("foo")))
				buf.Write(getDataFrame([]byte("bar")))
				quicvarint.Write(buf, uint64(FrameTypeHeaders))
				quicvarint.Write(buf, 0x10)
				buf.Write(make([]byte, 0x10))
				sess.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorGeneralProtocolError), gomock.Any())
				b := make([]byte, 10)
				n, err := rb.Read(b)
				b = b[:n]
				Expect(err).To(Equal(io.EOF))
				Expect(n).To(Equal(6))
				Expect(b).To(Equal([]byte("foobar")))
				Expect(trailersErr).To(HaveOccurred())
			})

			It("errors when it can't parse the frame", func() {
				buf.Write([]byte("invalid"))
				_, err := rb.Read([]byte{0})
				Expect(err).To(Equal(io.EOF))
			})

			It("errors on unexpected frames, and closes the QUIC session", func() {
				sess.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), gomock.Any())
				Settings{}.writeFrame(buf)
				_, err := rb.Read([]byte{0})
				Expect(err).To(MatchError(&FrameTypeError{Want: FrameTypeData, Type: FrameTypeSettings}))
			})

			if bodyType == bodyTypeResponse {
				It("closes the reqDone channel when Read errors", func() {
					buf.Write([]byte("invalid"))
					_, err := rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
					Expect(reqDone).To(BeClosed())
				})

				It("allows multiple calls to Read, when Read errors", func() {
					buf.Write([]byte("invalid"))
					_, err := rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
					Expect(reqDone).To(BeClosed())
					_, err = rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
				})

				It("closes responses", func() {
					str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled))
					Expect(rb.Close()).To(Succeed())
				})

				It("allows multiple calls to Close", func() {
					str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled)).MaxTimes(2)
					Expect(rb.Close()).To(Succeed())
					Expect(reqDone).To(BeClosed())
					Expect(rb.Close()).To(Succeed())
				})
			}
		})
	}
})
