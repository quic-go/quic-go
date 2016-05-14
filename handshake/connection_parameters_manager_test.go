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

		val, err := cpm.getRawValue(TagICSL)
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(icsl))
	})

	It("returns an error for a tag that is not set", func() {
		_, err := cpm.getRawValue(TagKEXS)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrTagNotInConnectionParameterMap))
	})

	Context("SHLO", func() {
		It("returns all parameters necessary for the SHLO", func() {
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap).To(HaveKey(TagMSPC))
		})

		It("returns stream-level flow control windows in SHLO", func() {
			cpm.receiveStreamFlowControlWindow = 0xDEADBEEF
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(entryMap[TagSFCW]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("returns connection-level flow control windows in SHLO", func() {
			cpm.receiveConnectionFlowControlWindow = 0xDECAFBAD
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(entryMap[TagCFCW]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})
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
		It("has the correct default stream-level flow control window for sending", func() {
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
		})

		It("has the correct default connection-level flow control window for sending", func() {
			Expect(cpm.GetSendConnectionFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
		})

		It("has the correct default stream-level flow control window for receiving", func() {
			Expect(cpm.GetReceiveStreamFlowControlWindow()).To(Equal(protocol.ReceiveStreamFlowControlWindow))
		})

		It("has the correct default connection-level flow control window for receiving", func() {
			Expect(cpm.GetReceiveConnectionFlowControlWindow()).To(Equal(protocol.ReceiveConnectionFlowControlWindow))
		})

		It("sets a new stream-level flow control window for sending", func() {
			values := map[Tag][]byte{
				TagSFCW: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the stream-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{
				TagSFCW: []byte{0xDE, 0xAD, 0xBE}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(HaveOccurred())
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
		})

		It("sets a new connection-level flow control window for sending", func() {
			values := map[Tag][]byte{
				TagCFCW: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the connection-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{
				TagSFCW: []byte{0xDE, 0xAD, 0xBE}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(HaveOccurred())
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
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
