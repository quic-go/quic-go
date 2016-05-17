package qerr_test

import (
	"io"

	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Quic error", func() {
	Context("QuicError", func() {
		It("has a string representation", func() {
			err := qerr.Error(qerr.DecryptionFailure, "foobar")
			Expect(err.Error()).To(Equal("DecryptionFailure: foobar"))
		})
	})

	Context("ErrorCode", func() {
		It("works as error", func() {
			var err error = qerr.DecryptionFailure
			Expect(err).To(MatchError("DecryptionFailure"))
		})
	})

	Context("ToQuicError", func() {
		It("leaves QuicError unchanged", func() {
			err := qerr.Error(qerr.DecryptionFailure, "foo")
			Expect(qerr.ToQuicError(err)).To(Equal(err))
		})

		It("wraps ErrorCode properly", func() {
			var err error = qerr.DecryptionFailure
			Expect(qerr.ToQuicError(err)).To(Equal(qerr.Error(qerr.DecryptionFailure, "")))
		})

		It("changes default errors to InternalError", func() {
			Expect(qerr.ToQuicError(io.EOF)).To(Equal(qerr.Error(qerr.InternalError, "")))
		})
	})
})
