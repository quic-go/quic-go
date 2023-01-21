package http3

import (
	"errors"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Body", func() {
	var reqDone chan struct{}

	BeforeEach(func() { reqDone = make(chan struct{}) })

	It("closes the reqDone channel when Read errors", func() {
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test error"))
		rb := newResponseBody(str, nil, reqDone)
		_, err := rb.Read([]byte{0})
		Expect(err).To(MatchError("test error"))
		Expect(reqDone).To(BeClosed())
	})

	It("allows multiple calls to Read, when Read errors", func() {
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test error")).Times(2)
		rb := newResponseBody(str, nil, reqDone)
		_, err := rb.Read([]byte{0})
		Expect(err).To(HaveOccurred())
		Expect(reqDone).To(BeClosed())
		_, err = rb.Read([]byte{0})
		Expect(err).To(HaveOccurred())
	})

	It("closes responses", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(str, nil, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled))
		Expect(rb.Close()).To(Succeed())
	})

	It("allows multiple calls to Close", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(str, nil, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled)).MaxTimes(2)
		Expect(rb.Close()).To(Succeed())
		Expect(reqDone).To(BeClosed())
		Expect(rb.Close()).To(Succeed())
	})
})
