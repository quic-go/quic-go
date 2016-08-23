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
		tcid := []byte{0x13, 0x37}
		values := map[Tag][]byte{
			TagTCID: tcid,
		}

		cpm.SetFromMap(values)

		val, err := cpm.getRawValue(TagTCID)
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(tcid))
	})

	It("returns an error for a tag that is not set", func() {
		_, err := cpm.getRawValue(TagKEXS)
		Expect(err).To(MatchError(errTagNotInConnectionParameterMap))
	})

	Context("SHLO", func() {
		It("returns all parameters necessary for the SHLO", func() {
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap).To(HaveKey(TagMSPC))
			Expect(entryMap).To(HaveKey(TagMIDS))
		})

		It("sets the stream-level flow control windows in SHLO", func() {
			cpm.receiveStreamFlowControlWindow = 0xDEADBEEF
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(entryMap[TagSFCW]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			cpm.receiveConnectionFlowControlWindow = 0xDECAFBAD
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(entryMap[TagCFCW]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			cpm.idleConnectionStateLifetime = 0xDECAFBAD * time.Second
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap[TagICSL]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})

		It("sets the maximum streams per connection in SHLO", func() {
			cpm.maxStreamsPerConnection = 0xDEADBEEF
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagMSPC))
			Expect(entryMap[TagMSPC]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("sets the maximum incoming dynamic streams per connection in SHLO", func() {
			entryMap := cpm.GetSHLOMap()
			Expect(entryMap).To(HaveKey(TagMIDS))
			Expect(entryMap[TagMIDS]).To(Equal([]byte{100, 0, 0, 0}))
		})
	})

	Context("Truncated connection IDs", func() {
		It("does not send truncated connection IDs if the TCID tag is missing", func() {
			Expect(cpm.TruncateConnectionID()).To(BeFalse())
		})

		It("reads the tag for truncated connection IDs", func() {
			values := map[Tag][]byte{
				TagTCID: {0, 0, 0, 0},
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
				TagSFCW: {0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the stream-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{
				TagSFCW: {0xDE, 0xAD, 0xBE}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
		})

		It("sets a new connection-level flow control window for sending", func() {
			values := map[Tag][]byte{
				TagCFCW: {0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the connection-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{
				TagSFCW: {0xDE, 0xAD, 0xBE}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
		})

		It("does not allow renegotiation of flow control parameters", func() {
			values := map[Tag][]byte{
				TagCFCW: {0xDE, 0xAD, 0xBE, 0xEF},
				TagSFCW: {0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			values = map[Tag][]byte{
				TagCFCW: {0x13, 0x37, 0x13, 0x37},
				TagSFCW: {0x13, 0x37, 0x13, 0x37},
			}
			err = cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrFlowControlRenegotiationNotSupported))
			Expect(cpm.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
			Expect(cpm.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})
	})

	Context("idle connection state lifetime", func() {
		It("has initial idle connection state lifetime", func() {
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(protocol.InitialIdleConnectionStateLifetime))
		})

		It("negotiates correctly when the client wants a longer lifetime", func() {
			Expect(cpm.negotiateIdleConnectionStateLifetime(protocol.MaxIdleConnectionStateLifetime + 10*time.Second)).To(Equal(protocol.MaxIdleConnectionStateLifetime))
		})

		It("negotiates correctly when the client wants a shorter lifetime", func() {
			Expect(cpm.negotiateIdleConnectionStateLifetime(protocol.MaxIdleConnectionStateLifetime - 1*time.Second)).To(Equal(protocol.MaxIdleConnectionStateLifetime - 1*time.Second))
		})

		It("sets the negotiated lifetime", func() {
			// this test only works if the value given here is smaller than protocol.MaxIdleConnectionStateLifetime
			values := map[Tag][]byte{
				TagICSL: {10, 0, 0, 0},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(10 * time.Second))
		})

		It("does not change the idle connection state lifetime when given an invalid value", func() {
			values := map[Tag][]byte{
				TagSFCW: {0xDE, 0xAD, 0xBE}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(protocol.InitialIdleConnectionStateLifetime))
		})

		It("gets idle connection state lifetime", func() {
			value := 0xDECAFBAD * time.Second
			cpm.idleConnectionStateLifetime = value
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(value))
		})
	})

	Context("max streams per connection", func() {
		It("negotiates correctly when the client wants a larger number", func() {
			Expect(cpm.negotiateMaxStreamsPerConnection(protocol.MaxStreamsPerConnection + 10)).To(Equal(uint32(protocol.MaxStreamsPerConnection)))
		})

		It("negotiates correctly when the client wants a smaller number", func() {
			Expect(cpm.negotiateMaxStreamsPerConnection(protocol.MaxStreamsPerConnection - 1)).To(Equal(uint32(protocol.MaxStreamsPerConnection - 1)))
		})

		It("sets the negotiated max streams per connection value", func() {
			// this test only works if the value given here is smaller than protocol.MaxStreamsPerConnection
			values := map[Tag][]byte{
				TagMSPC: {2, 0, 0, 0},
			}
			err := cpm.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(cpm.GetMaxStreamsPerConnection()).To(Equal(uint32(2)))
		})

		It("errors when given an invalid max streams per connection value", func() {
			values := map[Tag][]byte{
				TagMSPC: {2, 0, 0}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
		})

		It("gets the max streams per connection value", func() {
			var value uint32 = 0xDECAFBAD
			cpm.maxStreamsPerConnection = value
			Expect(cpm.GetMaxStreamsPerConnection()).To(Equal(value))
		})
	})
})
