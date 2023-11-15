package http3

import (
	"errors"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP/3 errors", func() {
	It("converts", func() {
		Expect(maybeReplaceError(nil)).To(BeNil())
		Expect(maybeReplaceError(errors.New("foobar"))).To(MatchError("foobar"))
		Expect(maybeReplaceError(&quic.StreamError{
			ErrorCode: 1337,
			Remote:    true,
		})).To(Equal(&Error{
			Remote:    true,
			ErrorCode: 1337,
		}))
		Expect(maybeReplaceError(&quic.ApplicationError{
			ErrorCode:    42,
			Remote:       true,
			ErrorMessage: "foobar",
		})).To(Equal(&Error{
			Remote:       true,
			ErrorCode:    42,
			ErrorMessage: "foobar",
		}))
	})

	It("has a string representation", func() {
		Expect((&Error{ErrorCode: 0x10c, Remote: true}).Error()).To(Equal("H3_REQUEST_CANCELLED"))
		Expect((&Error{ErrorCode: 0x10c, Remote: true, ErrorMessage: "foobar"}).Error()).To(Equal("H3_REQUEST_CANCELLED: foobar"))
		Expect((&Error{ErrorCode: 0x10c, Remote: false}).Error()).To(Equal("H3_REQUEST_CANCELLED (local)"))
		Expect((&Error{ErrorCode: 0x10c, Remote: false, ErrorMessage: "foobar"}).Error()).To(Equal("H3_REQUEST_CANCELLED (local): foobar"))
		Expect((&Error{ErrorCode: 0x1337, Remote: true}).Error()).To(Equal("H3 error (0x1337)"))
	})
})
