// +build go1.16

package qerr

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QUIC Errors", func() {
	It("says that errors are net.ErrClosed errors", func() {
		Expect(errors.Is(&TransportError{}, net.ErrClosed)).To(BeTrue())
		Expect(errors.Is(&ApplicationError{}, net.ErrClosed)).To(BeTrue())
		Expect(errors.Is(&IdleTimeoutError{}, net.ErrClosed)).To(BeTrue())
		Expect(errors.Is(&HandshakeTimeoutError{}, net.ErrClosed)).To(BeTrue())
		Expect(errors.Is(&StatelessResetError{}, net.ErrClosed)).To(BeTrue())
		Expect(errors.Is(&VersionNegotiationError{}, net.ErrClosed)).To(BeTrue())
	})
})
