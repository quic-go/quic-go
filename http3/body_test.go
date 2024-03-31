package http3

import (
	"context"
	"errors"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Request Body", func() {
	It("makes the SETTINGS available", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rcvdSettings := make(chan struct{})
		close(rcvdSettings)
		settings := &Settings{EnableExtendedConnect: true}
		body := newRequestBody(str, context.Background(), rcvdSettings, func() *Settings { return settings })
		s, err := body.Settings(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal(settings))
	})

	It("unblocks Settings() when the connection is closed", func() {
		str := mockquic.NewMockStream(mockCtrl)
		ctx, cancel := context.WithCancelCause(context.Background())
		testErr := errors.New("test error")
		cancel(testErr)
		body := newRequestBody(str, ctx, make(chan struct{}), func() *Settings { return nil })
		_, err := body.Settings(context.Background())
		Expect(err).To(MatchError(testErr))
	})
})

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
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
		Expect(rb.Close()).To(Succeed())
	})

	It("allows multiple calls to Close", func() {
		str := mockquic.NewMockStream(mockCtrl)
		rb := newResponseBody(str, nil, reqDone)
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).MaxTimes(2)
		Expect(rb.Close()).To(Succeed())
		Expect(reqDone).To(BeClosed())
		Expect(rb.Close()).To(Succeed())
	})
})
