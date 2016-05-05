package handshake

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConnectionsParameterManager", func() {
	var cpm *ConnectionParametersManager
	BeforeEach(func() {
		cpm = NewConnectionParamatersManager()
	})

	It("stores and retrieves a value", func() {
		kexs := []byte{0xDE, 0xCA, 0xFB, 0xAD}
		icsl := []byte{0x13, 0x37}
		values := map[Tag][]byte{
			TagKEXS: kexs,
			TagICSL: icsl,
		}

		cpm.SetFromMap(values)

		val, err := cpm.GetRawValue(TagKEXS)
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(kexs))

		val, err = cpm.GetRawValue(TagICSL)
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(icsl))
	})

	It("returns an error for a tag that is not set", func() {
		_, err := cpm.GetRawValue(TagKEXS)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrTagNotInConnectionParameterMap))
	})

	It("returns all parameters necessary for the SHLO", func() {
		entryMap := cpm.GetSHLOMap()
		Expect(entryMap).To(HaveKey(TagICSL))
		Expect(entryMap).To(HaveKey(TagMSPC))
	})

	Context("flow control", func() {
		It("has the correct default flow control window", func() {
			val, err := cpm.GetStreamFlowControlWindow()
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(protocol.ByteCount(0x4000)))
		})

		It("reads the stream-level flowControlWindow", func() {
			cpm.params[TagSFCW] = []byte{0xDE, 0xAD, 0xBE, 0xEF}
			val, err := cpm.GetStreamFlowControlWindow()
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})
	})
})
