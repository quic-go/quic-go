package http3

import (
	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Conn", func() {
	Context("ServerConn", func() {
		Context("Accept", func() {
			It("fails when called on a client session", func() {
				sess := mockquic.NewMockEarlySession(mockCtrl)
				sess.EXPECT().Perspective().Return(quic.PerspectiveClient)
				conn, err := Accept(sess, Settings{})
				Expect(conn).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("ClientConn", func() {
		Context("Open", func() {
			It("fails when called on a server session", func() {
				sess := mockquic.NewMockEarlySession(mockCtrl)
				sess.EXPECT().Perspective().Return(quic.PerspectiveServer)
				conn, err := Open(sess, Settings{})
				Expect(conn).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
