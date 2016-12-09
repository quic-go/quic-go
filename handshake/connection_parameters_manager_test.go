package handshake

import (
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConnectionsParameterManager", func() {
	var cpm *connectionParametersManager
	BeforeEach(func() {
		cpm = NewConnectionParamatersManager(protocol.PerspectiveServer, protocol.Version36).(*connectionParametersManager)
	})

	Context("SHLO", func() {
		It("returns all parameters necessary for the SHLO", func() {
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap).To(HaveKey(TagMSPC))
			Expect(entryMap).To(HaveKey(TagMIDS))
		})

		It("doesn't add the MaximumIncomingDynamicStreams tag for QUIC 34", func() {
			cpm.version = protocol.Version34
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).ToNot(HaveKey(TagMIDS))
		})

		It("sets the stream-level flow control windows in SHLO", func() {
			cpm.receiveStreamFlowControlWindow = 0xDEADBEEF
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(entryMap[TagSFCW]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			cpm.receiveConnectionFlowControlWindow = 0xDECAFBAD
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(entryMap[TagCFCW]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			cpm.idleConnectionStateLifetime = 0xDECAFBAD * time.Second
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap[TagICSL]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})

		It("sets the negotiated value for maximum streams in the SHLO", func() {
			val := 50
			Expect(val).To(BeNumerically("<", protocol.MaxStreamsPerConnection))
			err := cpm.SetFromMap(map[Tag][]byte{TagMSPC: []byte{byte(val), 0, 0, 0}})
			Expect(err).ToNot(HaveOccurred())
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap[TagMSPC]).To(Equal([]byte{byte(val), 0, 0, 0}))
		})

		It("always sends its own value for the maximum incoming dynamic streams in the SHLO", func() {
			err := cpm.SetFromMap(map[Tag][]byte{TagMIDS: []byte{5, 0, 0, 0}})
			Expect(err).ToNot(HaveOccurred())
			entryMap, err := cpm.GetSHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap[TagMIDS]).To(Equal([]byte{byte(protocol.MaxIncomingDynamicStreamsPerConnection), 0, 0, 0}))
		})

		It("errors if called from a client", func() {
			cpm.perspective = protocol.PerspectiveClient
			_, err := cpm.GetSHLOMap()
			Expect(err).To(HaveOccurred())
		})
	})

	Context("CHLO", func() {
		BeforeEach(func() {
			cpm.perspective = protocol.PerspectiveClient
		})

		It("has the right values", func() {
			entryMap, err := cpm.GetCHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(binary.LittleEndian.Uint32(entryMap[TagICSL])).To(Equal(uint32(protocol.DefaultIdleTimeout / time.Second)))
			Expect(entryMap).To(HaveKey(TagMSPC))
			Expect(binary.LittleEndian.Uint32(entryMap[TagMSPC])).To(Equal(uint32(protocol.MaxStreamsPerConnection)))
			Expect(entryMap).To(HaveKey(TagMIDS))
			Expect(binary.LittleEndian.Uint32(entryMap[TagMIDS])).To(Equal(uint32(protocol.MaxIncomingDynamicStreamsPerConnection)))
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(binary.LittleEndian.Uint32(entryMap[TagSFCW])).To(Equal(uint32(protocol.InitialStreamFlowControlWindow)))
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(binary.LittleEndian.Uint32(entryMap[TagCFCW])).To(Equal(uint32(protocol.InitialConnectionFlowControlWindow)))
		})

		It("doesn't add the MIDS tag for QUIC 34", func() {
			cpm.version = protocol.Version34
			entryMap, err := cpm.GetCHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).ToNot(HaveKey(TagMIDS))
		})

		It("errors if called from a server", func() {
			cpm.perspective = protocol.PerspectiveServer
			_, err := cpm.GetCHLOMap()
			Expect(err).To(HaveOccurred())
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
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(protocol.DefaultIdleTimeout))
		})

		It("negotiates correctly when the client wants a longer lifetime", func() {
			Expect(cpm.negotiateIdleConnectionStateLifetime(protocol.MaxIdleTimeout + 10*time.Second)).To(Equal(protocol.MaxIdleTimeout))
		})

		It("negotiates correctly when the client wants a shorter lifetime", func() {
			Expect(cpm.negotiateIdleConnectionStateLifetime(protocol.MaxIdleTimeout - 1*time.Second)).To(Equal(protocol.MaxIdleTimeout - 1*time.Second))
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
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(protocol.DefaultIdleTimeout))
		})

		It("gets idle connection state lifetime", func() {
			value := 0xDECAFBAD * time.Second
			cpm.idleConnectionStateLifetime = value
			Expect(cpm.GetIdleConnectionStateLifetime()).To(Equal(value))
		})
	})

	Context("max streams per connection", func() {
		It("errors when given an invalid max streams per connection value", func() {
			values := map[Tag][]byte{
				TagMSPC: {2, 0, 0}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
		})

		It("errors when given an invalid max dynamic incoming streams per connection value", func() {
			values := map[Tag][]byte{
				TagMIDS: {2, 0, 0}, // 1 byte too short
			}
			err := cpm.SetFromMap(values)
			Expect(err).To(MatchError(ErrMalformedTag))
		})

		Context("outgoing connections", func() {
			It("sets the negotiated max streams per connection value", func() {
				// this test only works if the value given here is smaller than protocol.MaxStreamsPerConnection
				err := cpm.SetFromMap(map[Tag][]byte{
					TagMIDS: {2, 0, 0, 0},
					TagMSPC: {1, 0, 0, 0},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(cpm.GetMaxOutgoingStreams()).To(Equal(uint32(2)))
			})

			It("uses the the MSPC value, if no MIDS is given", func() {
				err := cpm.SetFromMap(map[Tag][]byte{TagMIDS: {3, 0, 0, 0}})
				Expect(err).ToNot(HaveOccurred())
				Expect(cpm.GetMaxOutgoingStreams()).To(Equal(uint32(3)))
			})

			It("uses the MSPC value for QUIC 34", func() {
				cpm.version = protocol.Version34
				err := cpm.SetFromMap(map[Tag][]byte{
					TagMIDS: {2, 0, 0, 0},
					TagMSPC: {1, 0, 0, 0},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(cpm.GetMaxOutgoingStreams()).To(Equal(uint32(1)))
			})
		})

		Context("incoming connections", func() {
			It("always uses the constant value, no matter what the client sent", func() {
				err := cpm.SetFromMap(map[Tag][]byte{
					TagMSPC: {3, 0, 0, 0},
					TagMIDS: {3, 0, 0, 0},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(cpm.GetMaxIncomingStreams()).To(BeNumerically(">", protocol.MaxStreamsPerConnection))
			})

			It("uses the negotiated MSCP value, for QUIC 34", func() {
				cpm.version = protocol.Version34
				err := cpm.SetFromMap(map[Tag][]byte{TagMSPC: {60, 0, 0, 0}})
				Expect(err).ToNot(HaveOccurred())
				Expect(cpm.GetMaxIncomingStreams()).To(BeNumerically("~", 60*protocol.MaxStreamsMultiplier, 10))
			})
		})

	})
})
