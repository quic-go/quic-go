package protocol_test

import (
	"github.com/lucas-clemente/quic-go/errorcodes"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Quic error", func() {
	It("has a string representation", func() {
		err := protocol.Error(errorcodes.InternalError, "foobar")
		Expect(err.Error()).To(Equal("InternalError: foobar"))
	})
})
