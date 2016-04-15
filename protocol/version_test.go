package protocol_test

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	It("converts tags to numbers", func() {
		Expect(protocol.VersionTagToNumber('Q' + '1'<<8 + '2'<<16 + '3'<<24)).To(Equal(protocol.VersionNumber(123)))
		Expect(protocol.VersionTagToNumber('Q' + '0'<<8 + '3'<<16 + '0'<<24)).To(Equal(protocol.VersionNumber(30)))
	})

	It("converts number to tag", func() {
		Expect(protocol.VersionNumberToTag(protocol.VersionNumber(123))).To(Equal(uint32('Q' + '1'<<8 + '2'<<16 + '3'<<24)))
		Expect(protocol.VersionNumberToTag(protocol.VersionNumber(30))).To(Equal(uint32('Q' + '0'<<8 + '3'<<16 + '0'<<24)))
	})

	It("has proper tag list", func() {
		Expect(protocol.SupportedVersionsAsTags).To(Equal([]byte("Q030Q032")))
	})
})
