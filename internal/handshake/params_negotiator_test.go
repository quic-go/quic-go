package handshake

import (
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Params Negotiator (for TLS)", func() {
	var params map[transportParameterID][]byte
	var pn *paramsNegotiator

	paramsMapToList := func(p map[transportParameterID][]byte) []transportParameter {
		var list []transportParameter
		for id, val := range p {
			list = append(list, transportParameter{id, val})
		}
		return list
	}

	paramsListToMap := func(l []transportParameter) map[transportParameterID][]byte {
		p := make(map[transportParameterID][]byte)
		for _, v := range l {
			p[v.Parameter] = v.Value
		}
		return p
	}

	BeforeEach(func() {
		pn = newParamsNegotiator(
			protocol.PerspectiveServer,
			protocol.VersionWhatever,
			&TransportParameters{},
		)
		params = map[transportParameterID][]byte{
			initialMaxStreamDataParameterID: []byte{0x11, 0x22, 0x33, 0x44},
			initialMaxDataParameterID:       []byte{0x22, 0x33, 0x44, 0x55},
			initialMaxStreamIDParameterID:   []byte{0x33, 0x44, 0x55, 0x66},
			idleTimeoutParameterID:          []byte{0x13, 0x37},
		}
	})

	Context("getting", func() {
		It("creates the parameters list", func() {
			pn.idleTimeout = 0xcafe
			buf := make([]byte, 4)
			values := paramsListToMap(pn.GetTransportParameters())
			Expect(values).To(HaveLen(5))
			binary.BigEndian.PutUint32(buf, uint32(protocol.ReceiveStreamFlowControlWindow))
			Expect(values).To(HaveKeyWithValue(initialMaxStreamDataParameterID, buf))
			binary.BigEndian.PutUint32(buf, uint32(protocol.ReceiveConnectionFlowControlWindow))
			Expect(values).To(HaveKeyWithValue(initialMaxDataParameterID, buf))
			Expect(values).To(HaveKeyWithValue(initialMaxStreamIDParameterID, []byte{0xff, 0xff, 0xff, 0xff}))
			Expect(values).To(HaveKeyWithValue(idleTimeoutParameterID, []byte{0xca, 0xfe}))
			Expect(values).To(HaveKeyWithValue(maxPacketSizeParameterID, []byte{0x5, 0xac})) // 1452 = 0x5ac
		})

		It("request ommision of the connection ID", func() {
			pn.omitConnectionID = true
			values := paramsListToMap(pn.GetTransportParameters())
			Expect(values).To(HaveKeyWithValue(omitConnectionIDParameterID, []byte{}))
		})
	})

	Context("setting", func() {
		It("reads parameters", func() {
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.GetSendStreamFlowControlWindow()).To(Equal(protocol.ByteCount(0x11223344)))
			Expect(pn.GetSendConnectionFlowControlWindow()).To(Equal(protocol.ByteCount(0x22334455)))
			Expect(pn.GetIdleConnectionStateLifetime()).To(Equal(0x1337 * time.Second))
			Expect(pn.OmitConnectionID()).To(BeFalse())
		})

		It("saves if it should omit the connection ID", func() {
			params[omitConnectionIDParameterID] = []byte{}
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).ToNot(HaveOccurred())
			Expect(pn.OmitConnectionID()).To(BeTrue())
		})

		It("rejects the parameters if the initial_max_stream_data is missing", func() {
			delete(params, initialMaxStreamDataParameterID)
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("missing parameter"))
		})

		It("rejects the parameters if the initial_max_data is missing", func() {
			delete(params, initialMaxDataParameterID)
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("missing parameter"))
		})

		It("rejects the parameters if the initial_max_stream_id is missing", func() {
			delete(params, initialMaxStreamIDParameterID)
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("missing parameter"))
		})

		It("rejects the parameters if the idle_timeout is missing", func() {
			delete(params, idleTimeoutParameterID)
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("missing parameter"))
		})

		It("rejects the parameters if the initial_max_stream_data has the wrong length", func() {
			params[initialMaxStreamDataParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("wrong length for initial_max_stream_data: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_data has the wrong length", func() {
			params[initialMaxDataParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("wrong length for initial_max_data: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_stream_id has the wrong length", func() {
			params[initialMaxStreamIDParameterID] = []byte{0x11, 0x22, 0x33, 0x44, 0x55} // should be 4 bytes
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("wrong length for initial_max_stream_id: 5 (expected 4)"))
		})

		It("rejects the parameters if the initial_idle_timeout has the wrong length", func() {
			params[idleTimeoutParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("wrong length for idle_timeout: 3 (expected 2)"))
		})

		It("rejects the parameters if omit_connection_id is non-empty", func() {
			params[omitConnectionIDParameterID] = []byte{0} // should be empty
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).To(MatchError("wrong length for omit_connection_id: 1 (expected empty)"))
		})

		It("ignores unknown parameters", func() {
			params[1337] = []byte{42}
			err := pn.SetFromTransportParameters(paramsMapToList(params))
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
