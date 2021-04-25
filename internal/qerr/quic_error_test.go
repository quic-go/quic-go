package qerr

import (
	"errors"
	"net"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Errors", func() {
	Context("Transport Errors", func() {
		It("has a string representation", func() {
			Expect((&TransportError{
				ErrorCode:    FlowControlError,
				ErrorMessage: "foobar",
			}).Error()).To(Equal("FLOW_CONTROL_ERROR: foobar"))
		})

		It("has a string representation for empty error phrases", func() {
			Expect((&TransportError{ErrorCode: FlowControlError}).Error()).To(Equal("FLOW_CONTROL_ERROR"))
		})

		It("includes the frame type, for errors without a message", func() {
			Expect((&TransportError{
				ErrorCode: FlowControlError,
				FrameType: 0x1337,
			}).Error()).To(Equal("FLOW_CONTROL_ERROR (frame type: 0x1337)"))
		})

		It("includes the frame type, for errors with a message", func() {
			Expect((&TransportError{
				ErrorCode:    FlowControlError,
				FrameType:    0x1337,
				ErrorMessage: "foobar",
			}).Error()).To(Equal("FLOW_CONTROL_ERROR (frame type: 0x1337): foobar"))
		})

		It("works with error assertions", func() {
			Expect(errors.Is(&TransportError{ErrorCode: FlowControlError}, &TransportError{})).To(BeTrue())
			Expect(errors.Is(&TransportError{ErrorCode: FlowControlError}, &ApplicationError{})).To(BeFalse())
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
		})
	})

	Context("Application Errors", func() {
		It("has a string representation for errors with a message", func() {
			Expect((&ApplicationError{
				ErrorCode:    0x42,
				ErrorMessage: "foobar",
			}).Error()).To(Equal("Application error 0x42: foobar"))
		})

		It("has a string representation for errors without a message", func() {
			Expect((&ApplicationError{
				ErrorCode: 0x42,
			}).Error()).To(Equal("Application error 0x42"))
		})

		It("works with error assertions", func() {
			Expect(errors.Is(&ApplicationError{ErrorCode: 0x1234}, &ApplicationError{})).To(BeTrue())
			Expect(errors.Is(&ApplicationError{ErrorCode: 0x1234}, &TransportError{})).To(BeFalse())
		})
	})

	Context("timeout errors", func() {
		It("handshake timeouts", func() {
			//nolint:gosimple // we need to assign to an interface here
			var err error
			err = &HandshakeTimeoutError{}
			nerr, ok := err.(net.Error)
			Expect(ok).To(BeTrue())
			Expect(nerr.Timeout()).To(BeTrue())
			Expect(nerr.Temporary()).To(BeFalse())
			Expect(err.Error()).To(Equal("timeout: handshake did not complete in time"))
			Expect(errors.Is(err, &HandshakeTimeoutError{})).To(BeTrue())
			Expect(errors.Is(err, &IdleTimeoutError{})).To(BeFalse())
		})

		It("idle timeouts", func() {
			//nolint:gosimple // we need to assign to an interface here
			var err error
			err = &IdleTimeoutError{}
			nerr, ok := err.(net.Error)
			Expect(ok).To(BeTrue())
			Expect(nerr.Timeout()).To(BeTrue())
			Expect(nerr.Temporary()).To(BeFalse())
			Expect(err.Error()).To(Equal("timeout: no recent network activity"))
			Expect(errors.Is(err, &HandshakeTimeoutError{})).To(BeFalse())
			Expect(errors.Is(err, &IdleTimeoutError{})).To(BeTrue())
		})
	})

	Context("Version Negotiation errors", func() {
		It("is a Version Negotiation error", func() {
			Expect(errors.Is(&VersionNegotiationError{Ours: []protocol.VersionNumber{2, 3}}, &VersionNegotiationError{})).To(BeTrue())
		})

		It("has a string representation", func() {
			Expect((&VersionNegotiationError{
				Ours:   []protocol.VersionNumber{2, 3},
				Theirs: []protocol.VersionNumber{4, 5, 6},
			}).Error()).To(Equal("no compatible QUIC version found (we support [0x2 0x3], server offered [0x4 0x5 0x6])"))
		})
	})
})
