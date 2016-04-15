package protocol_test

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	It("converts tags to numbers", func() {
		Expect(protocol.VersionTagToNumber('Q' + '1'<<8 + '2'<<16 + '3'<<24)).To(Equal(protocol.VersionNumber(123)))
	})

	It("converts number to tag", func() {
		Expect(protocol.VersionNumberToTag(protocol.VersionNumber(123))).To(Equal(uint32('Q' + '1'<<8 + '2'<<16 + '3'<<24)))
	})
})
