package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Perspective", func() {
	It("has a string representation", func() {
		Expect(PerspectiveClient.String()).To(Equal("client"))
		Expect(PerspectiveServer.String()).To(Equal("server"))
		Expect(Perspective(0).String()).To(Equal("invalid perspective"))
	})

	It("returns the opposite", func() {
		Expect(PerspectiveClient.Opposite()).To(Equal(PerspectiveServer))
		Expect(PerspectiveServer.Opposite()).To(Equal(PerspectiveClient))
	})
})
