package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Version", func() {
	isReservedVersion := func(v VersionNumber) bool {
		return v&0x0f0f0f0f == 0x0a0a0a0a
	}

	// version numbers taken from the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
	It("has the right gQUIC version number", func() {
		Expect(Version39).To(BeEquivalentTo(0x51303339))
	})

	It("says if a version supports TLS", func() {
		Expect(Version39.UsesTLS()).To(BeFalse())
		Expect(VersionTLS.UsesTLS()).To(BeTrue())
	})

	It("versions don't have reserved version numbers", func() {
		Expect(isReservedVersion(Version39)).To(BeFalse())
		Expect(isReservedVersion(VersionTLS)).To(BeFalse())
	})

	It("has the right string representation", func() {
		Expect(Version39.String()).To(Equal("gQUIC 39"))
		Expect(VersionTLS.String()).To(ContainSubstring("TLS"))
		Expect(VersionWhatever.String()).To(Equal("whatever"))
		Expect(VersionUnknown.String()).To(Equal("unknown"))
		// check with unsupported version numbers from the wiki
		Expect(VersionNumber(0x51303039).String()).To(Equal("gQUIC 9"))
		Expect(VersionNumber(0x51303133).String()).To(Equal("gQUIC 13"))
		Expect(VersionNumber(0x51303235).String()).To(Equal("gQUIC 25"))
		Expect(VersionNumber(0x51303438).String()).To(Equal("gQUIC 48"))
	})

	It("has the right representation for the H2 Alt-Svc tag", func() {
		Expect(Version39.ToAltSvc()).To(Equal("39"))
		Expect(VersionTLS.ToAltSvc()).To(Equal("101"))
		// check with unsupported version numbers from the wiki
		Expect(VersionNumber(0x51303133).ToAltSvc()).To(Equal("13"))
		Expect(VersionNumber(0x51303235).ToAltSvc()).To(Equal("25"))
		Expect(VersionNumber(0x51303438).ToAltSvc()).To(Equal("48"))
	})

	It("tells the Stream ID of the crypto stream", func() {
		Expect(Version39.CryptoStreamID()).To(Equal(StreamID(1)))
		Expect(VersionTLS.CryptoStreamID()).To(Equal(StreamID(0)))
	})

	It("tells if a version uses the IETF frame types", func() {
		Expect(Version39.UsesIETFFrameFormat()).To(BeFalse())
		Expect(VersionTLS.UsesIETFFrameFormat()).To(BeTrue())
	})

	It("tells if a version uses the IETF frame types", func() {
		Expect(Version39.UsesIETFFrameFormat()).To(BeFalse())
		Expect(VersionTLS.UsesIETFFrameFormat()).To(BeTrue())
	})

	It("says if a stream contributes to connection-level flowcontrol, for gQUIC", func() {
		Expect(Version39.StreamContributesToConnectionFlowControl(1)).To(BeFalse())
		Expect(Version39.StreamContributesToConnectionFlowControl(2)).To(BeTrue())
		Expect(Version39.StreamContributesToConnectionFlowControl(3)).To(BeFalse())
		Expect(Version39.StreamContributesToConnectionFlowControl(4)).To(BeTrue())
		Expect(Version39.StreamContributesToConnectionFlowControl(5)).To(BeTrue())
	})

	It("says if a stream contributes to connection-level flowcontrol, for TLS", func() {
		Expect(VersionTLS.StreamContributesToConnectionFlowControl(0)).To(BeFalse())
		Expect(VersionTLS.StreamContributesToConnectionFlowControl(1)).To(BeTrue())
		Expect(VersionTLS.StreamContributesToConnectionFlowControl(2)).To(BeTrue())
		Expect(VersionTLS.StreamContributesToConnectionFlowControl(3)).To(BeTrue())
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
