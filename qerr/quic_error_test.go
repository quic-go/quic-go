package qerr_test

import (
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Quic error", func() {
	It("has a string representation", func() {
		err := qerr.Error(qerr.InternalError, "foobar")
		Expect(err.Error()).To(Equal("InternalError: foobar"))
	})
})
