package qerr

import (
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Transport Errors", func() {
	It("has a string representation", func() {
		err := NewError(FlowControlError, "foobar")
		Expect(err.Timeout()).To(BeFalse())
		Expect(err.IsApplicationError()).To(BeFalse())
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR: foobar"))
	})

	It("has a string representation for empty error phrases", func() {
		err := NewError(FlowControlError, "")
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR"))
	})

	It("includes the frame type, for errors without a message", func() {
		err := NewErrorWithFrameType(FlowControlError, 0x1337, "")
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR (frame type: 0x1337)"))
	})

	It("includes the frame type, for errors with a message", func() {
		err := NewErrorWithFrameType(FlowControlError, 0x1337, "foobar")
		Expect(err.Error()).To(Equal("FLOW_CONTROL_ERROR (frame type: 0x1337): foobar"))
	})

	It("has a string representation for timeout errors", func() {
		err := NewTimeoutError("foobar")
		Expect(err.Timeout()).To(BeTrue())
		Expect(err.Error()).To(Equal("NO_ERROR: foobar"))
	})

	Context("crypto errors", func() {
		It("has a string representation for errors with a message", func() {
			err := NewCryptoError(0x42, "foobar")
			Expect(err.Error()).To(Equal("CRYPTO_ERROR (0x142): foobar"))
		})

		It("has a string representation for errors without a message", func() {
			err := NewCryptoError(0x2a, "")
			Expect(err.Error()).To(Equal("CRYPTO_ERROR (0x12a): tls: bad certificate"))
		})

		It("says if an error is a crypto error", func() {
			Expect(NewError(FlowControlError, "").IsCryptoError()).To(BeFalse())
			err := NewCryptoError(42, "")
			Expect(err.IsCryptoError()).To(BeTrue())
			Expect(err.IsApplicationError()).To(BeFalse())
		})
	})

	Context("application errors", func() {
		It("has a string representation for errors with a message", func() {
			err := NewApplicationError(0x42, "foobar")
			Expect(err.IsApplicationError()).To(BeTrue())
			Expect(err.Error()).To(Equal("Application error 0x42: foobar"))
		})

		It("has a string representation for errors without a message", func() {
			err := NewApplicationError(0x42, "")
			Expect(err.Error()).To(Equal("Application error 0x42"))
		})
	})

	Context("ErrorCode", func() {
		It("works as error", func() {
			var err error = StreamStateError
			Expect(err).To(MatchError("STREAM_STATE_ERROR"))
		})

		It("recognizes crypto errors", func() {
			err := ErrorCode(0x100 + 0x2a)
			Expect(err.Error()).To(Equal("CRYPTO_ERROR (0x12a): tls: bad certificate"))
		})
	})

	Context("ToQuicError", func() {
		It("leaves QuicError unchanged", func() {
			err := NewError(TransportParameterError, "foo")
			Expect(ToQuicError(err)).To(Equal(err))
		})

		It("wraps ErrorCode properly", func() {
			var err error = FinalSizeError
			Expect(ToQuicError(err)).To(Equal(NewError(FinalSizeError, "")))
		})

		It("changes default errors to InternalError", func() {
			Expect(ToQuicError(io.EOF)).To(Equal(NewError(InternalError, "EOF")))
		})
	})
})
