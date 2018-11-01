package handshake

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport Parameters", func() {
	It("has a string representation", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:  0x1234,
			InitialMaxStreamDataBidiRemote: 0x2345,
			InitialMaxStreamDataUni:        0x3456,
			InitialMaxData:                 0x4567,
			MaxBidiStreams:                 1337,
			MaxUniStreams:                  7331,
			IdleTimeout:                    42 * time.Second,
		}
		Expect(p.String()).To(Equal("&handshake.TransportParameters{InitialMaxStreamDataBidiLocal: 0x1234, InitialMaxStreamDataBidiRemote: 0x2345, InitialMaxStreamDataUni: 0x3456, InitialMaxData: 0x4567, MaxBidiStreams: 1337, MaxUniStreams: 7331, IdleTimeout: 42s}"))
	})

	Context("parsing", func() {
		var (
			params              *TransportParameters
			parameters          map[transportParameterID][]byte
			statelessResetToken []byte
		)

		marshal := func(p map[transportParameterID][]byte) []byte {
			b := &bytes.Buffer{}
			for id, val := range p {
				utils.BigEndian.WriteUint16(b, uint16(id))
				utils.BigEndian.WriteUint16(b, uint16(len(val)))
				b.Write(val)
			}
			return b.Bytes()
		}

		BeforeEach(func() {
			params = &TransportParameters{}
			statelessResetToken = bytes.Repeat([]byte{42}, 16)
			parameters = map[transportParameterID][]byte{
				initialMaxStreamDataBidiLocalParameterID:  {0x11, 0x22, 0x33, 0x44},
				initialMaxStreamDataBidiRemoteParameterID: {0x22, 0x33, 0x44, 0x55},
				initialMaxStreamDataUniParameterID:        {0x33, 0x44, 0x55, 0x66},
				initialMaxDataParameterID:                 {0x44, 0x55, 0x66, 0x77},
				initialMaxBidiStreamsParameterID:          {0x33, 0x44},
				initialMaxUniStreamsParameterID:           {0x44, 0x55},
				idleTimeoutParameterID:                    {0x13, 0x37},
				maxPacketSizeParameterID:                  {0x73, 0x31},
				disableMigrationParameterID:               {},
				statelessResetTokenParameterID:            statelessResetToken,
			}
		})
		It("reads parameters", func() {
			Expect(params.unmarshal(marshal(parameters))).To(Succeed())
			Expect(params.InitialMaxStreamDataBidiLocal).To(Equal(protocol.ByteCount(0x11223344)))
			Expect(params.InitialMaxStreamDataBidiRemote).To(Equal(protocol.ByteCount(0x22334455)))
			Expect(params.InitialMaxStreamDataUni).To(Equal(protocol.ByteCount(0x33445566)))
			Expect(params.InitialMaxData).To(Equal(protocol.ByteCount(0x44556677)))
			Expect(params.MaxBidiStreams).To(Equal(uint16(0x3344)))
			Expect(params.MaxUniStreams).To(Equal(uint16(0x4455)))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
			Expect(params.MaxPacketSize).To(Equal(protocol.ByteCount(0x7331)))
			Expect(params.DisableMigration).To(BeTrue())
			Expect(params.StatelessResetToken).To(Equal(statelessResetToken))
		})

		It("errors if a parameter is sent twice", func() {
			data := marshal(parameters)
			parameters = map[transportParameterID][]byte{
				maxPacketSizeParameterID: {0x73, 0x31},
			}
			data = append(data, marshal(parameters)...)
			err := params.unmarshal(data)
			Expect(err).To(MatchError(fmt.Sprintf("received duplicate transport parameter %#x", maxPacketSizeParameterID)))
		})

		It("doesn't allow values below the minimum remote idle timeout", func() {
			t := 2 * time.Second
			Expect(t).To(BeNumerically("<", protocol.MinRemoteIdleTimeout))
			parameters[idleTimeoutParameterID] = []byte{0, uint8(t.Seconds())}
			err := params.unmarshal(marshal(parameters))
			Expect(err).ToNot(HaveOccurred())
			Expect(params.IdleTimeout).To(Equal(protocol.MinRemoteIdleTimeout))
		})

		It("rejects the parameters if the initial_max_stream_data_bidi_local has the wrong length", func() {
			parameters[initialMaxStreamDataBidiLocalParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_stream_data_bidi_local: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_stream_data_bidi_remote has the wrong length", func() {
			parameters[initialMaxStreamDataBidiRemoteParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_stream_data_bidi_remote: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_stream_data_uni has the wrong length", func() {
			parameters[initialMaxStreamDataUniParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_stream_data_uni: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_data has the wrong length", func() {
			parameters[initialMaxDataParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_data: 3 (expected 4)"))
		})

		It("rejects the parameters if the initial_max_stream_id_bidi has the wrong length", func() {
			parameters[initialMaxBidiStreamsParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_stream_id_bidi: 3 (expected 2)"))
		})

		It("rejects the parameters if the initial_max_stream_id_bidi has the wrong length", func() {
			parameters[initialMaxUniStreamsParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for initial_max_stream_id_uni: 3 (expected 2)"))
		})

		It("rejects the parameters if the initial_idle_timeout has the wrong length", func() {
			parameters[idleTimeoutParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for idle_timeout: 3 (expected 2)"))
		})

		It("rejects the parameters if max_packet_size has the wrong length", func() {
			parameters[maxPacketSizeParameterID] = []byte{0x11} // should be 2 bytes
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for max_packet_size: 1 (expected 2)"))
		})

		It("rejects max_packet_sizes smaller than 1200 bytes", func() {
			parameters[maxPacketSizeParameterID] = []byte{0x4, 0xaf} // 0x4af = 1199
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("invalid value for max_packet_size: 1199 (minimum 1200)"))
		})

		It("rejects the parameters if disable_connection_migration has the wrong length", func() {
			parameters[disableMigrationParameterID] = []byte{0x11} // should empty
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for disable_migration: 1 (expected empty)"))
		})

		It("rejects the parameters if the stateless_reset_token has the wrong length", func() {
			parameters[statelessResetTokenParameterID] = statelessResetToken[1:]
			err := params.unmarshal(marshal(parameters))
			Expect(err).To(MatchError("wrong length for stateless_reset_token: 15 (expected 16)"))
		})

		It("ignores unknown parameters", func() {
			parameters[1337] = []byte{42}
			err := params.unmarshal(marshal(parameters))
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("marshalling", func() {
		It("marshals", func() {
			params := &TransportParameters{
				InitialMaxStreamDataBidiLocal:  0xdeadbeef,
				InitialMaxStreamDataBidiRemote: 0xbeef,
				InitialMaxStreamDataUni:        0xcafe,
				InitialMaxData:                 0xdecafbad,
				IdleTimeout:                    0xcafe * time.Second,
				MaxBidiStreams:                 0x1234,
				MaxUniStreams:                  0x4321,
				DisableMigration:               true,
				StatelessResetToken:            bytes.Repeat([]byte{100}, 16),
			}
			b := &bytes.Buffer{}
			params.marshal(b)

			p := &TransportParameters{}
			Expect(p.unmarshal(b.Bytes())).To(Succeed())
			Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(params.InitialMaxStreamDataBidiLocal))
			Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(params.InitialMaxStreamDataBidiRemote))
			Expect(p.InitialMaxStreamDataUni).To(Equal(params.InitialMaxStreamDataUni))
			Expect(p.InitialMaxData).To(Equal(params.InitialMaxData))
			Expect(p.MaxUniStreams).To(Equal(params.MaxUniStreams))
			Expect(p.MaxBidiStreams).To(Equal(params.MaxBidiStreams))
			Expect(p.IdleTimeout).To(Equal(params.IdleTimeout))
			Expect(p.DisableMigration).To(Equal(params.DisableMigration))
			Expect(p.StatelessResetToken).To(Equal(params.StatelessResetToken))
		})
	})
})
