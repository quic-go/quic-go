package handshake

import (
	"time"

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
		icsl := []byte{0x13, 0x37}
		values := map[Tag][]byte{
			TagICSL: icsl,
		}

		cpm.SetFromMap(values)

		val, err := cpm.GetRawValue(TagICSL)
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

	Context("Truncated connection IDs", func() {
		It("does not send truncated connection IDs if the TCID tag is missing", func() {
			Expect(cpm.TruncateConnectionID()).To(BeFalse())
		})

		It("reads the tag for truncated connection IDs", func() {
			values := map[Tag][]byte{
				TagTCID: []byte{0, 0, 0, 0},
			}
			cpm.SetFromMap(values)
			Expect(cpm.TruncateConnectionID()).To(BeTrue())
		})
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

	It("gets idle connection state lifetime", func() {
		cpm.params[TagICSL] = []byte{0xad, 0xfb, 0xca, 0xde}
		val := cpm.GetIdleConnectionStateLifetime()
		Expect(val).To(Equal(0xdecafbad * time.Second))
	})

	It("has initial idle conneciton state lifetime", func() {
		val := cpm.GetIdleConnectionStateLifetime()
		Expect(val).To(Equal(30 * time.Second))
	})
})
