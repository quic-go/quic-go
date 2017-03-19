package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	It("converts tags to numbers", func() {
		Expect(VersionTagToNumber('Q' + '1'<<8 + '2'<<16 + '3'<<24)).To(Equal(VersionNumber(123)))
	})

	It("converts number to tag", func() {
		Expect(VersionNumberToTag(VersionNumber(123))).To(Equal(uint32('Q' + '1'<<8 + '2'<<16 + '3'<<24)))
	})

	It("has proper tag list", func() {
		Expect(SupportedVersionsAsTags).To(Equal([]byte("Q035Q036")))
	})

	It("has proper version list", func() {
		Expect(SupportedVersionsAsString).To(Equal("36,35"))
	})

	It("recognizes supported versions", func() {
		Expect(IsSupportedVersion(0)).To(BeFalse())
		Expect(IsSupportedVersion(SupportedVersions[0])).To(BeTrue())
	})

	It("has supported versions in sorted order", func() {
		for i := 0; i < len(SupportedVersions)-1; i++ {
			Expect(SupportedVersions[i]).To(BeNumerically("<", SupportedVersions[i+1]))
		}
	})

	Context("highest supported version", func() {
		var initialSupportedVersions []VersionNumber

		BeforeEach(func() {
			initialSupportedVersions = make([]VersionNumber, len(SupportedVersions))
			copy(initialSupportedVersions, SupportedVersions)
		})

		AfterEach(func() {
			SupportedVersions = initialSupportedVersions
		})

		It("finds the supported version", func() {
			SupportedVersions = []VersionNumber{1, 2, 3}
			other := []VersionNumber{3, 4, 5, 6}
			found, ver := HighestSupportedVersion(other)
			Expect(found).To(BeTrue())
			Expect(ver).To(Equal(VersionNumber(3)))
		})

		It("picks the highest supported version", func() {
			SupportedVersions = []VersionNumber{1, 2, 3, 6, 7}
			other := []VersionNumber{3, 6, 1, 8, 2, 10}
			found, ver := HighestSupportedVersion(other)
			Expect(found).To(BeTrue())
			Expect(ver).To(Equal(VersionNumber(6)))
		})

		It("handles empty inputs", func() {
			SupportedVersions = []VersionNumber{101, 102}
			Expect(HighestSupportedVersion([]VersionNumber{})).To(BeFalse())
			SupportedVersions = []VersionNumber{}
			Expect(HighestSupportedVersion([]VersionNumber{1, 2})).To(BeFalse())
			Expect(HighestSupportedVersion([]VersionNumber{})).To(BeFalse())
		})
	})
})
