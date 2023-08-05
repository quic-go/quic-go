package protocol

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	isReservedVersion := func(v VersionNumber) bool {
		return v&0x0f0f0f0f == 0x0a0a0a0a
	}

	It("says if a version is valid", func() {
		Expect(IsValidVersion(VersionUnknown)).To(BeFalse())
		Expect(IsValidVersion(versionDraft29)).To(BeFalse())
		Expect(IsValidVersion(Version1)).To(BeTrue())
		Expect(IsValidVersion(Version2)).To(BeTrue())
		Expect(IsValidVersion(1234)).To(BeFalse())
	})

	It("has the right string representation", func() {
		Expect(VersionUnknown.String()).To(Equal("unknown"))
		Expect(versionDraft29.String()).To(Equal("draft-29"))
		Expect(Version1.String()).To(Equal("v1"))
		Expect(Version2.String()).To(Equal("v2"))
		// check with unsupported version numbers from the wiki
		Expect(VersionNumber(0x51303039).String()).To(Equal("gQUIC 9"))
		Expect(VersionNumber(0x51303133).String()).To(Equal("gQUIC 13"))
		Expect(VersionNumber(0x51303235).String()).To(Equal("gQUIC 25"))
		Expect(VersionNumber(0x51303438).String()).To(Equal("gQUIC 48"))
		Expect(VersionNumber(0x01234567).String()).To(Equal("0x1234567"))
	})

	It("recognizes supported versions", func() {
		Expect(IsSupportedVersion(SupportedVersions, 0)).To(BeFalse())
		Expect(IsSupportedVersion(SupportedVersions, SupportedVersions[0])).To(BeTrue())
		Expect(IsSupportedVersion(SupportedVersions, SupportedVersions[len(SupportedVersions)-1])).To(BeTrue())
	})

	Context("highest supported version", func() {
		It("finds the supported version", func() {
			supportedVersions := []VersionNumber{1, 2, 3}
			other := []VersionNumber{6, 5, 4, 3}
			ver, ok := ChooseSupportedVersion(supportedVersions, other)
			Expect(ok).To(BeTrue())
			Expect(ver).To(Equal(VersionNumber(3)))
		})

		It("picks the preferred version", func() {
			supportedVersions := []VersionNumber{2, 1, 3}
			other := []VersionNumber{3, 6, 1, 8, 2, 10}
			ver, ok := ChooseSupportedVersion(supportedVersions, other)
			Expect(ok).To(BeTrue())
			Expect(ver).To(Equal(VersionNumber(2)))
		})

		It("says when no matching version was found", func() {
			_, ok := ChooseSupportedVersion([]VersionNumber{1}, []VersionNumber{2})
			Expect(ok).To(BeFalse())
		})

		It("handles empty inputs", func() {
			_, ok := ChooseSupportedVersion([]VersionNumber{102, 101}, []VersionNumber{})
			Expect(ok).To(BeFalse())
			_, ok = ChooseSupportedVersion([]VersionNumber{}, []VersionNumber{1, 2})
			Expect(ok).To(BeFalse())
			_, ok = ChooseSupportedVersion([]VersionNumber{}, []VersionNumber{})
			Expect(ok).To(BeFalse())
		})
	})

	Context("reserved versions", func() {
		It("adds a greased version if passed an empty slice", func() {
			greased := GetGreasedVersions([]VersionNumber{})
			Expect(greased).To(HaveLen(1))
			Expect(isReservedVersion(greased[0])).To(BeTrue())
		})

		It("creates greased lists of version numbers", func() {
			supported := []VersionNumber{10, 18, 29}
			for _, v := range supported {
				Expect(isReservedVersion(v)).To(BeFalse())
			}
			var greasedVersionFirst, greasedVersionLast, greasedVersionMiddle int
			// check that
			// 1. the greased version sometimes appears first
			// 2. the greased version sometimes appears in the middle
			// 3. the greased version sometimes appears last
			// 4. the supported versions are kept in order
			for i := 0; i < 100; i++ {
				greased := GetGreasedVersions(supported)
				Expect(greased).To(HaveLen(4))
				var j int
				for i, v := range greased {
					if isReservedVersion(v) {
						if i == 0 {
							greasedVersionFirst++
						}
						if i == len(greased)-1 {
							greasedVersionLast++
						}
						greasedVersionMiddle++
						continue
					}
					Expect(supported[j]).To(Equal(v))
					j++
				}
			}
			Expect(greasedVersionFirst).ToNot(BeZero())
			Expect(greasedVersionLast).ToNot(BeZero())
			Expect(greasedVersionMiddle).ToNot(BeZero())
		})
	})
})
