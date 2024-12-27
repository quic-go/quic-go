package http3

import (
	"bytes"
	"errors"
	"io"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Response Body", func() {
	var reqDone chan struct{}

	BeforeEach(func() { reqDone = make(chan struct{}) })

	It("closes the reqDone channel when Read errors", func() {
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test error"))
		rb := newResponseBody(&stream{Stream: str}, -1, reqDone)
		_, err := rb.Read([]byte{0})
		Expect(err).To(MatchError("test error"))
		Expect(reqDone).To(BeClosed())
	})

	It("allows multiple calls to Read, when Read errors", func() {
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test error")).Times(2)
		rb := newResponseBody(&stream{Stream: str}, -1, reqDone)
		_, err := rb.Read([]byte{0})
		Expect(err).To(HaveOccurred())
		Expect(reqDone).To(BeClosed())
		_, err = rb.Read([]byte{0})
		Expect(err).To(HaveOccurred())
	})

	It("closes responses", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(&stream{Stream: str}, -1, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
		Expect(rb.Close()).To(Succeed())
	})

	It("allows multiple calls to Close", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(&stream{Stream: str}, -1, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).MaxTimes(2)
		Expect(rb.Close()).To(Succeed())
		Expect(reqDone).To(BeClosed())
		Expect(rb.Close()).To(Succeed())
	})

	It("allows concurrent calls to Close", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(&stream{Stream: str}, -1, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).MaxTimes(2)
		go func() {
			defer GinkgoRecover()
			Expect(rb.Close()).To(Succeed())
		}()
		Expect(rb.Close()).To(Succeed())
		Expect(reqDone).To(BeClosed())
	})

	Context("length limiting", func() {
		It("reads all frames", func() {
			var buf bytes.Buffer
			buf.Write(getDataFrame([]byte("foobar")))
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			rb := newResponseBody(&stream{Stream: str}, 6, reqDone)
			data, err := io.ReadAll(rb)
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))
		})

		It("errors if more data than the maximum length is sent, in the middle of a frame", func() {
			var buf bytes.Buffer
			buf.Write(getDataFrame([]byte("foo")))
			buf.Write(getDataFrame([]byte("bar")))
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
			str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
			str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			rb := newResponseBody(&stream{Stream: str}, 4, reqDone)
			data, err := io.ReadAll(rb)
			Expect(data).To(Equal([]byte("foob")))
			Expect(err).To(MatchError(errTooMuchData))
			// check that repeated calls to Read also return the right error
			n, err := rb.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError(errTooMuchData))
		})

		It("errors if more data than the maximum length is sent, as an additional frame", func() {
			var buf bytes.Buffer
			buf.Write(getDataFrame([]byte("foo")))
			buf.Write(getDataFrame([]byte("bar")))
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
			str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
			str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			rb := newResponseBody(&stream{Stream: str}, 3, reqDone)
			data, err := io.ReadAll(rb)
			Expect(err).To(MatchError(errTooMuchData))
			Expect(data).To(Equal([]byte("foo")))
		})
	})
})
