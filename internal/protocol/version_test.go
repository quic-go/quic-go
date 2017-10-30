package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	// version numbers taken from the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
	It("has the right gQUIC version number", func() {
		Expect(Version37).To(BeEquivalentTo(0x51303337))
		Expect(Version38).To(BeEquivalentTo(0x51303338))
		Expect(Version39).To(BeEquivalentTo(0x51303339))
	})

	It("says if a version supports TLS", func() {
		Expect(Version37.UsesTLS()).To(BeFalse())
		Expect(Version38.UsesTLS()).To(BeFalse())
		Expect(Version39.UsesTLS()).To(BeFalse())
		Expect(VersionTLS.UsesTLS()).To(BeTrue())
	})

	It("has the right string representation", func() {
		Expect(Version37.String()).To(Equal("gQUIC 37"))
		Expect(Version38.String()).To(Equal("gQUIC 38"))
		Expect(Version39.String()).To(Equal("gQUIC 39"))
		Expect(VersionTLS.String()).To(ContainSubstring("TLS"))
		Expect(VersionWhatever.String()).To(Equal("whatever"))
		Expect(VersionUnsupported.String()).To(Equal("unsupported"))
		Expect(VersionUnknown.String()).To(Equal("unknown"))
		// check with unsupported version numbers from the wiki
		Expect(VersionNumber(0x51303039).String()).To(Equal("gQUIC 9"))
		Expect(VersionNumber(0x51303133).String()).To(Equal("gQUIC 13"))
		Expect(VersionNumber(0x51303235).String()).To(Equal("gQUIC 25"))
		Expect(VersionNumber(0x51303438).String()).To(Equal("gQUIC 48"))
	})

	It("has the right representation for the H2 Alt-Svc tag", func() {
		Expect(Version37.ToAltSvc()).To(Equal("37"))
		Expect(Version38.ToAltSvc()).To(Equal("38"))
		Expect(Version39.ToAltSvc()).To(Equal("39"))
		Expect(VersionTLS.ToAltSvc()).To(Equal("101"))
		// check with unsupported version numbers from the wiki
		Expect(VersionNumber(0x51303133).ToAltSvc()).To(Equal("13"))
		Expect(VersionNumber(0x51303235).ToAltSvc()).To(Equal("25"))
		Expect(VersionNumber(0x51303438).ToAltSvc()).To(Equal("48"))

	})

	It("recognizes supported versions", func() {
		Expect(IsSupportedVersion(SupportedVersions, 0)).To(BeFalse())
		Expect(IsSupportedVersion(SupportedVersions, SupportedVersions[0])).To(BeTrue())
		Expect(IsSupportedVersion(SupportedVersions, SupportedVersions[len(SupportedVersions)-1])).To(BeTrue())
	})

	It("has supported versions in sorted order", func() {
		for i := 0; i < len(SupportedVersions)-1; i++ {
			Expect(SupportedVersions[i]).To(BeNumerically(">", SupportedVersions[i+1]))
		}
	})

	Context("highest supported version", func() {
		It("finds the supported version", func() {
			supportedVersions := []VersionNumber{1, 2, 3}
			other := []VersionNumber{6, 5, 4, 3}
			Expect(ChooseSupportedVersion(supportedVersions, other)).To(Equal(VersionNumber(3)))
		})

		It("picks the preferred version", func() {
			supportedVersions := []VersionNumber{2, 1, 3}
			other := []VersionNumber{3, 6, 1, 8, 2, 10}
			Expect(ChooseSupportedVersion(supportedVersions, other)).To(Equal(VersionNumber(2)))
		})

		It("handles empty inputs", func() {
			supportedVersions := []VersionNumber{102, 101}
			Expect(ChooseSupportedVersion(supportedVersions, nil)).To(Equal(VersionUnsupported))
			Expect(ChooseSupportedVersion(supportedVersions, []VersionNumber{})).To(Equal(VersionUnsupported))
			supportedVersions = []VersionNumber{}
			Expect(ChooseSupportedVersion(supportedVersions, []VersionNumber{1, 2})).To(Equal(VersionUnsupported))
			Expect(ChooseSupportedVersion(supportedVersions, []VersionNumber{})).To(Equal(VersionUnsupported))
		})
	})
})
