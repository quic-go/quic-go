package qerr

import (
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Transport Errors", func() {
	It("has a string representation", func() {
		err := Error(FlowControlError, "foobar")
		Expect(err.Timeout()).To(BeFalse())
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR: foobar"))
	})

	It("has a string representation for empty error phrases", func() {
		err := Error(FlowControlError, "")
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR"))
	})

	It("has a string representation for timeout errors", func() {
		err := TimeoutError("foobar")
		Expect(err.Timeout()).To(BeTrue())
		Expect(err.Error()).To(Equal("NO_ERROR: foobar"))
	})

	It("has a string representation for crypto errors", func() {
		err := CryptoError(42)
		Expect(err.Error()).To(Equal("CRYPTO_ERROR 42"))
	})

	Context("ErrorCode", func() {
		It("works as error", func() {
			var err error = StreamStateError
			Expect(err).To(MatchError("STREAM_STATE_ERROR"))
		})

		It("recognizes crypto errors", func() {
			err := ErrorCode(0x100 + 42)
			Expect(err.Error()).To(Equal("CRYPTO_ERROR 42"))
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
