package http3

import (
	"github.com/golang/mock/gomock"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Body", func() {
	var (
		stream *mockquic.MockStream
		body   *responseBody
	)

	BeforeEach(func() {
		stream = mockquic.NewMockStream(mockCtrl)
		body = &responseBody{stream}
	})

	It("calls CancelRead when closing", func() {
		stream.EXPECT().CancelRead(gomock.Any())
		Expect(body.Close()).To(Succeed())
	})
})
