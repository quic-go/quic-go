// +build go1.15

package quic

import (
	"errors"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Deadline Error", func() {
	It("is a net.Error that wraps os.ErrDeadlineError", func() {
		err := deadlineError{}
		Expect(err.Temporary()).To(BeTrue())
		Expect(err.Timeout()).To(BeTrue())
		Expect(errors.Is(err, os.ErrDeadlineExceeded)).To(BeTrue())
		Expect(errors.Unwrap(err)).To(Equal(os.ErrDeadlineExceeded))
	})
})
