package qerr

import (
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Transport Errors", func() {
	Context("QuicError", func() {
		It("has a string representation", func() {
			err := Error(FlowControlError, "foobar")
			Expect(err.Error()).To(Equal("FlowControlError: foobar"))
		})
	})

	Context("ErrorCode", func() {
		It("works as error", func() {
			var err error = StreamStateError
			Expect(err).To(MatchError("StreamStateError"))
		})
	})

	Context("ToQuicError", func() {
		It("leaves QuicError unchanged", func() {
			err := Error(TransportParameterError, "foo")
			Expect(ToQuicError(err)).To(Equal(err))
		})

		It("wraps ErrorCode properly", func() {
			var err error = FinalSizeError
			Expect(ToQuicError(err)).To(Equal(Error(FinalSizeError, "")))
		})

		It("changes default errors to InternalError", func() {
			Expect(ToQuicError(io.EOF)).To(Equal(Error(InternalError, "EOF")))
		})
	})
})
