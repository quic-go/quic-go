package logging

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Close Reason", func() {
	checkNotApplicationError := func(r CloseReason) {
		_, _, ok := r.ApplicationError()
		Expect(ok).To(BeFalse())
	}

	checkNotTransportError := func(r CloseReason) {
		_, _, ok := r.TransportError()
		Expect(ok).To(BeFalse())
	}

	checkNotStatelessReset := func(r CloseReason) {
		_, ok := r.StatelessReset()
		ExpectWithOffset(1, ok).To(BeFalse())
	}

	checkNotTimeout := func(r CloseReason) {
		_, ok := r.Timeout()
		ExpectWithOffset(1, ok).To(BeFalse())
	}

	checkNotVN := func(r CloseReason) {
		_, ok := r.VersionNegotiation()
		ExpectWithOffset(1, ok).To(BeFalse())
	}

	It("application errors", func() {
		r := NewApplicationCloseReason(1337, true)
		errorCode, remote, ok := r.ApplicationError()
		Expect(ok).To(BeTrue())
		Expect(remote).To(BeTrue())
		Expect(errorCode).To(Equal(ApplicationError(1337)))
		checkNotTransportError(r)
		checkNotStatelessReset(r)
		checkNotTimeout(r)
		checkNotVN(r)
	})

	It("transport errors", func() {
		r := NewTransportCloseReason(1337, true)
		errorCode, remote, ok := r.TransportError()
		Expect(ok).To(BeTrue())
		Expect(remote).To(BeTrue())
		Expect(errorCode).To(Equal(TransportError(1337)))
		checkNotApplicationError(r)
		checkNotStatelessReset(r)
		checkNotTimeout(r)
		checkNotVN(r)
	})

	It("transport errors", func() {
		r := NewTimeoutCloseReason(TimeoutReasonIdle)
		timeout, ok := r.Timeout()
		Expect(ok).To(BeTrue())
		Expect(timeout).To(Equal(TimeoutReasonIdle))
		checkNotApplicationError(r)
		checkNotTransportError(r)
		checkNotVN(r)
	})

	It("stateless resets", func() {
		r := NewStatelessResetCloseReason(StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		token, ok := r.StatelessReset()
		Expect(ok).To(BeTrue())
		Expect(token).To(Equal(StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
		checkNotApplicationError(r)
		checkNotTransportError(r)
		checkNotTimeout(r)
		checkNotVN(r)
	})

	It("version negotiation errors", func() {
		r := NewVersionNegotiationError([]VersionNumber{1, 2, 3})
		vn, ok := r.VersionNegotiation()
		Expect(ok).To(BeTrue())
		Expect(vn).To(Equal([]VersionNumber{1, 2, 3}))
		checkNotApplicationError(r)
		checkNotTransportError(r)
		checkNotTimeout(r)
		checkNotStatelessReset(r)
	})
})
