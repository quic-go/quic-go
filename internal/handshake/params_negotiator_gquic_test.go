package handshake

import (
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Params Negotiator (for gQUIC)", func() {
	var pn *paramsNegotiatorGQUIC // a connectionParametersManager for a server
	var pnClient *paramsNegotiatorGQUIC
	idleTimeout := 42 * time.Second
	BeforeEach(func() {
		pn = newParamsNegotiatorGQUIC(
			protocol.PerspectiveServer,
			protocol.VersionWhatever,
			&TransportParameters{
				IdleTimeout: idleTimeout,
			},
		)
		pnClient = newParamsNegotiatorGQUIC(
			protocol.PerspectiveClient,
			protocol.VersionWhatever,
			&TransportParameters{
				IdleTimeout: idleTimeout,
			},
		)
	})

	Context("SHLO", func() {
		BeforeEach(func() {
			// these tests should only use the server connectionParametersManager. Make them panic if they don't
			pnClient = nil
		})

		It("returns all parameters necessary for the SHLO", func() {
			entryMap, err := pn.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap).To(HaveKey(TagMIDS))
		})

		It("sets the stream-level flow control windows in SHLO", func() {
			pn.receiveStreamFlowControlWindow = 0xDEADBEEF
			entryMap, err := pn.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(entryMap[TagSFCW]).To(Equal([]byte{0xEF, 0xBE, 0xAD, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			pn.receiveConnectionFlowControlWindow = 0xDECAFBAD
			entryMap, err := pn.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(entryMap[TagCFCW]).To(Equal([]byte{0xAD, 0xFB, 0xCA, 0xDE}))
		})

		It("sets the connection-level flow control windows in SHLO", func() {
			pn.idleTimeout = 0xdecafbad * time.Second
			entryMap, err := pn.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(entryMap[TagICSL]).To(Equal([]byte{0xad, 0xfb, 0xca, 0xde}))
		})

		It("always sends its own value for the maximum incoming dynamic streams in the SHLO", func() {
			err := pn.SetFromMap(map[Tag][]byte{TagMIDS: []byte{5, 0, 0, 0}})
			Expect(err).ToNot(HaveOccurred())
			entryMap, err := pn.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap[TagMIDS]).To(Equal([]byte{byte(protocol.MaxIncomingDynamicStreamsPerConnection), 0, 0, 0}))
		})
	})

	Context("CHLO", func() {
		BeforeEach(func() {
			// these tests should only use the client connectionParametersManager. Make them panic if they don't
			pn = nil
		})

		It("has the right values", func() {
			entryMap, err := pnClient.GetHelloMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(entryMap).To(HaveKey(TagICSL))
			Expect(binary.LittleEndian.Uint32(entryMap[TagICSL])).To(BeEquivalentTo(idleTimeout / time.Second))
			Expect(entryMap).To(HaveKey(TagMIDS))
			Expect(binary.LittleEndian.Uint32(entryMap[TagMIDS])).To(BeEquivalentTo(protocol.MaxIncomingDynamicStreamsPerConnection))
			Expect(entryMap).To(HaveKey(TagSFCW))
			Expect(binary.LittleEndian.Uint32(entryMap[TagSFCW])).To(BeEquivalentTo(protocol.ReceiveStreamFlowControlWindow))
			Expect(entryMap).To(HaveKey(TagCFCW))
			Expect(binary.LittleEndian.Uint32(entryMap[TagCFCW])).To(BeEquivalentTo(protocol.ReceiveConnectionFlowControlWindow))
		})
	})

	Context("Omitted connection IDs", func() {
		It("does not send omitted connection IDs if the TCID tag is missing", func() {
			Expect(pn.OmitConnectionID()).To(BeFalse())
		})

		It("reads the tag for omitted connection IDs", func() {
			values := map[Tag][]byte{TagTCID: {0, 0, 0, 0}}
			pn.SetFromMap(values)
			Expect(pn.OmitConnectionID()).To(BeTrue())
		})

		It("ignores the TCID tag, as a client", func() {
			values := map[Tag][]byte{TagTCID: {0, 0, 0, 0}}
			pnClient.SetFromMap(values)
			Expect(pnClient.OmitConnectionID()).To(BeFalse())
		})

		It("errors when given an invalid value", func() {
			values := map[Tag][]byte{TagTCID: {2, 0, 0}} // 1 byte too short
			err := pn.SetFromMap(values)
			Expect(err).To(MatchError(errMalformedTag))
		})
	})

	Context("flow control", func() {
		It("has the correct default flow control windows for sending", func() {
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
			Expect(pn.GetSendConnectionFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
			Expect(pnClient.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
			Expect(pnClient.GetSendConnectionFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
		})

		It("has the correct default flow control windows for receiving", func() {
			Expect(pn.GetReceiveStreamFlowControlWindow()).To(BeEquivalentTo(protocol.ReceiveStreamFlowControlWindow))
			Expect(pn.GetReceiveConnectionFlowControlWindow()).To(BeEquivalentTo(protocol.ReceiveConnectionFlowControlWindow))
			Expect(pnClient.GetReceiveStreamFlowControlWindow()).To(BeEquivalentTo(protocol.ReceiveStreamFlowControlWindow))
			Expect(pnClient.GetReceiveConnectionFlowControlWindow()).To(BeEquivalentTo(protocol.ReceiveConnectionFlowControlWindow))
		})

		It("sets a new stream-level flow control window for sending", func() {
			values := map[Tag][]byte{TagSFCW: {0xDE, 0xAD, 0xBE, 0xEF}}
			err := pn.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the stream-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{TagSFCW: {0xDE, 0xAD, 0xBE}} // 1 byte too short
			err := pn.SetFromMap(values)
			Expect(err).To(MatchError(errMalformedTag))
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialStreamFlowControlWindow))
		})

		It("sets a new connection-level flow control window for sending", func() {
			values := map[Tag][]byte{TagCFCW: {0xDE, 0xAD, 0xBE, 0xEF}}
			err := pn.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})

		It("does not change the connection-level flow control window when given an invalid value", func() {
			values := map[Tag][]byte{TagCFCW: {0xDE, 0xAD, 0xBE}} // 1 byte too short
			err := pn.SetFromMap(values)
			Expect(err).To(MatchError(errMalformedTag))
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.InitialConnectionFlowControlWindow))
		})

		It("does not allow renegotiation of flow control parameters", func() {
			values := map[Tag][]byte{
				TagCFCW: {0xDE, 0xAD, 0xBE, 0xEF},
				TagSFCW: {0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := pn.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			values = map[Tag][]byte{
				TagCFCW: {0x13, 0x37, 0x13, 0x37},
				TagSFCW: {0x13, 0x37, 0x13, 0x37},
			}
			err = pn.SetFromMap(values)
			Expect(err).To(MatchError(errFlowControlRenegotiationNotSupported))
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
			Expect(pn.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0xEFBEADDE)))
		})
	})

	Context("idle timeout", func() {
		It("sets the remote idle timeout", func() {
			values := map[Tag][]byte{
				TagICSL: {10, 0, 0, 0},
			}
			err := pn.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.GetRemoteIdleTimeout()).To(Equal(10 * time.Second))
		})

		It("doesn't allow values below the minimum remote idle timeout", func() {
			t := 2 * time.Second
			Expect(t).To(BeNumerically("<", protocol.MinRemoteIdleTimeout))
			values := map[Tag][]byte{
				TagICSL: {uint8(t.Seconds()), 0, 0, 0},
			}
			err := pn.SetFromMap(values)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.GetRemoteIdleTimeout()).To(Equal(protocol.MinRemoteIdleTimeout))
		})

		It("errors when given an invalid value", func() {
			values := map[Tag][]byte{TagICSL: {2, 0, 0}} // 1 byte too short
			err := pn.SetFromMap(values)
			Expect(err).To(MatchError(errMalformedTag))
		})
	})

	Context("max streams per connection", func() {
		It("errors when given an invalid max dynamic incoming streams per connection value", func() {
			values := map[Tag][]byte{TagMIDS: {2, 0, 0}} // 1 byte too short
			err := pn.SetFromMap(values)
			Expect(err).To(MatchError(errMalformedTag))
		})

		Context("outgoing connections", func() {
			It("sets the negotiated max streams per connection value", func() {
				// this test only works if the value given here is smaller than protocol.MaxStreamsPerConnection
				err := pn.SetFromMap(map[Tag][]byte{
					TagMIDS: {2, 0, 0, 0},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(pn.GetMaxOutgoingStreams()).To(Equal(uint32(2)))
			})

			It("uses the the MSPC value, if no MIDS is given", func() {
				err := pn.SetFromMap(map[Tag][]byte{
					TagMIDS: {3, 0, 0, 0},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(pn.GetMaxOutgoingStreams()).To(Equal(uint32(3)))
			})
		})
	})
})
