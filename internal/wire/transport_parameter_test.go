package wire

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport Parameters", func() {
	getRandomValue := func() uint64 {
		maxVals := []int64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
		return uint64(rand.Int63n(maxVals[int(rand.Int31n(4))]))
	}

	BeforeEach(func() {
		rand.Seed(GinkgoRandomSeed())
	})

	var token [16]byte

	addInitialSourceConnectionID := func(b *bytes.Buffer) {
		utils.WriteVarInt(b, uint64(initialSourceConnectionIDParameterID))
		utils.WriteVarInt(b, 6)
		b.Write([]byte("foobar"))
	}

	It("has a string representation", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   1234,
			InitialMaxStreamDataBidiRemote:  2345,
			InitialMaxStreamDataUni:         3456,
			InitialMaxData:                  4567,
			MaxBidiStreamNum:                1337,
			MaxUniStreamNum:                 7331,
			MaxIdleTimeout:                  42 * time.Second,
			OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			InitialSourceConnectionID:       protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
			RetrySourceConnectionID:         &protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
			AckDelayExponent:                14,
			MaxAckDelay:                     37 * time.Millisecond,
			StatelessResetToken:             &[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
			ActiveConnectionIDLimit:         123,
		}
		Expect(p.String()).To(Equal("&wire.TransportParameters{OriginalDestinationConnectionID: 0xdeadbeef, InitialSourceConnectionID: 0xdecafbad, RetrySourceConnectionID: 0xdeadc0de, InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37ms, ActiveConnectionIDLimit: 123, StatelessResetToken: 0x112233445566778899aabbccddeeff00}"))
	})

	It("has a string representation, if there's no stateless reset token and no Retry source connection id", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   1234,
			InitialMaxStreamDataBidiRemote:  2345,
			InitialMaxStreamDataUni:         3456,
			InitialMaxData:                  4567,
			MaxBidiStreamNum:                1337,
			MaxUniStreamNum:                 7331,
			MaxIdleTimeout:                  42 * time.Second,
			OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			InitialSourceConnectionID:       protocol.ConnectionID{},
			AckDelayExponent:                14,
			MaxAckDelay:                     37 * time.Second,
			ActiveConnectionIDLimit:         89,
		}
		Expect(p.String()).To(Equal("&wire.TransportParameters{OriginalDestinationConnectionID: 0xdeadbeef, InitialSourceConnectionID: (empty), InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37s, ActiveConnectionIDLimit: 89}"))
	})

	It("marshals and unmarshals", func() {
		var token [16]byte
		rand.Read(token[:])
		params := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
			InitialMaxData:                  protocol.ByteCount(getRandomValue()),
			MaxIdleTimeout:                  0xcafe * time.Second,
			MaxBidiStreamNum:                protocol.StreamNum(getRandomValue()),
			MaxUniStreamNum:                 protocol.StreamNum(getRandomValue()),
			DisableActiveMigration:          true,
			StatelessResetToken:             &token,
			OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			InitialSourceConnectionID:       protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
			RetrySourceConnectionID:         &protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
			AckDelayExponent:                13,
			MaxAckDelay:                     42 * time.Millisecond,
			ActiveConnectionIDLimit:         getRandomValue(),
		}
		data := params.Marshal(protocol.PerspectiveServer)

		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(params.InitialMaxStreamDataBidiLocal))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(params.InitialMaxStreamDataBidiRemote))
		Expect(p.InitialMaxStreamDataUni).To(Equal(params.InitialMaxStreamDataUni))
		Expect(p.InitialMaxData).To(Equal(params.InitialMaxData))
		Expect(p.MaxUniStreamNum).To(Equal(params.MaxUniStreamNum))
		Expect(p.MaxBidiStreamNum).To(Equal(params.MaxBidiStreamNum))
		Expect(p.MaxIdleTimeout).To(Equal(params.MaxIdleTimeout))
		Expect(p.DisableActiveMigration).To(Equal(params.DisableActiveMigration))
		Expect(p.StatelessResetToken).To(Equal(params.StatelessResetToken))
		Expect(p.OriginalDestinationConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
		Expect(p.InitialSourceConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		Expect(p.RetrySourceConnectionID).To(Equal(&protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde}))
		Expect(p.AckDelayExponent).To(Equal(uint8(13)))
		Expect(p.MaxAckDelay).To(Equal(42 * time.Millisecond))
		Expect(p.ActiveConnectionIDLimit).To(Equal(params.ActiveConnectionIDLimit))
	})

	It("doesn't marshal a retry_source_connection_id, if no Retry was performed", func() {
		data := (&TransportParameters{
			StatelessResetToken: &token,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).To(BeNil())
	})

	It("marshals a zero-length retry_source_connection_id", func() {
		data := (&TransportParameters{
			RetrySourceConnectionID: &protocol.ConnectionID{},
			StatelessResetToken:     &token,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).ToNot(BeNil())
		Expect(p.RetrySourceConnectionID.Len()).To(BeZero())
	})

	It("errors when the stateless_reset_token has the wrong length", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(statelessResetTokenParameterID))
		utils.WriteVarInt(b, 15)
		b.Write(make([]byte, 15))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: wrong length for stateless_reset_token: 15 (expected 16)"))
	})

	It("errors when the max_packet_size is too small", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(maxUDPPayloadSizeParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(1199)))
		utils.WriteVarInt(b, 1199)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: invalid value for max_packet_size: 1199 (minimum 1200)"))
	})

	It("errors when disable_active_migration has content", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(disableActiveMigrationParameterID))
		utils.WriteVarInt(b, 6)
		b.Write([]byte("foobar"))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: wrong length for disable_active_migration: 6 (expected empty)"))
	})

	It("errors when the server doesn't set the original_destination_connection_id", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(statelessResetTokenParameterID))
		utils.WriteVarInt(b, 16)
		b.Write(token[:])
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: missing original_destination_connection_id"))
	})

	It("errors when the initial_source_connection_id is missing", func() {
		Expect((&TransportParameters{}).Unmarshal([]byte{}, protocol.PerspectiveClient)).To(MatchError("TRANSPORT_PARAMETER_ERROR: missing initial_source_connection_id"))
	})

	It("errors when the max_ack_delay is too large", func() {
		data := (&TransportParameters{
			MaxAckDelay:         1 << 14 * time.Millisecond,
			StatelessResetToken: &token,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: invalid value for max_ack_delay: 16384ms (maximum 16383ms)"))
	})

	It("doesn't send the max_ack_delay, if it has the default value", func() {
		const num = 1000
		var defaultLen, dataLen int
		// marshal 1000 times to average out the greasing transport parameter
		maxAckDelay := protocol.DefaultMaxAckDelay + time.Millisecond
		for i := 0; i < num; i++ {
			dataDefault := (&TransportParameters{
				MaxAckDelay:         protocol.DefaultMaxAckDelay,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			defaultLen += len(dataDefault)
			data := (&TransportParameters{
				MaxAckDelay:         maxAckDelay,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			dataLen += len(data)
		}
		entryLen := utils.VarIntLen(uint64(ackDelayExponentParameterID)) /* parameter id */ + utils.VarIntLen(uint64(utils.VarIntLen(uint64(maxAckDelay.Milliseconds())))) /*length */ + utils.VarIntLen(uint64(maxAckDelay.Milliseconds())) /* value */
		Expect(float32(dataLen) / num).To(BeNumerically("~", float32(defaultLen)/num+float32(entryLen), 1))
	})

	It("errors when the ack_delay_exponenent is too large", func() {
		data := (&TransportParameters{
			AckDelayExponent:    21,
			StatelessResetToken: &token,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: invalid value for ack_delay_exponent: 21 (maximum 20)"))
	})

	It("doesn't send the ack_delay_exponent, if it has the default value", func() {
		const num = 1000
		var defaultLen, dataLen int
		// marshal 1000 times to average out the greasing transport parameter
		for i := 0; i < num; i++ {
			dataDefault := (&TransportParameters{
				AckDelayExponent:    protocol.DefaultAckDelayExponent,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			defaultLen += len(dataDefault)
			data := (&TransportParameters{
				AckDelayExponent:    protocol.DefaultAckDelayExponent + 1,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			dataLen += len(data)
		}
		entryLen := utils.VarIntLen(uint64(ackDelayExponentParameterID)) /* parameter id */ + utils.VarIntLen(uint64(utils.VarIntLen(protocol.DefaultAckDelayExponent+1))) /* length */ + utils.VarIntLen(protocol.DefaultAckDelayExponent+1) /* value */
		Expect(float32(dataLen) / num).To(BeNumerically("~", float32(defaultLen)/num+float32(entryLen), 1))
	})

	It("sets the default value for the ack_delay_exponent, when no value was sent", func() {
		data := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent,
			StatelessResetToken: &token,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.AckDelayExponent).To(BeEquivalentTo(protocol.DefaultAckDelayExponent))
	})

	It("errors when the varint value has the wrong length", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		utils.WriteVarInt(b, 2)
		val := uint64(0xdeadbeef)
		Expect(utils.VarIntLen(val)).ToNot(BeEquivalentTo(2))
		utils.WriteVarInt(b, val)
		addInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TRANSPORT_PARAMETER_ERROR: inconsistent transport parameter length"))
	})

	It("handles max_ack_delays that decode to a negative duration", func() {
		b := &bytes.Buffer{}
		val := uint64(math.MaxUint64) / 5
		utils.WriteVarInt(b, uint64(maxAckDelayParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(val)))
		utils.WriteVarInt(b, val)
		addInitialSourceConnectionID(b)
		p := &TransportParameters{}
		Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(Succeed())
		Expect(p.MaxAckDelay).To(BeNumerically(">", 290*365*24*time.Hour))
	})

	It("skips unknown parameters", func() {
		b := &bytes.Buffer{}
		// write a known parameter
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		// write an unknown parameter
		utils.WriteVarInt(b, 0x42)
		utils.WriteVarInt(b, 6)
		b.Write([]byte("foobar"))
		// write a known parameter
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(0x42)))
		utils.WriteVarInt(b, 0x42)
		addInitialSourceConnectionID(b)
		p := &TransportParameters{}
		Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(protocol.ByteCount(0x1337)))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(protocol.ByteCount(0x42)))
	})

	It("rejects duplicate parameters", func() {
		b := &bytes.Buffer{}
		// write first parameter
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		// write a second parameter
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(0x42)))
		utils.WriteVarInt(b, 0x42)
		// write first parameter again
		utils.WriteVarInt(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		addInitialSourceConnectionID(b)
		err := (&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("received duplicate transport parameter"))
	})

	It("errors if there's not enough data to read", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, 0x42)
		utils.WriteVarInt(b, 7)
		b.Write([]byte("foobar"))
		p := &TransportParameters{}
		Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: remaining length (6) smaller than parameter length (7)"))
	})

	It("errors if the client sent a stateless_reset_token", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(statelessResetTokenParameterID))
		utils.WriteVarInt(b, uint64(utils.VarIntLen(16)))
		b.Write(token[:])
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError("TRANSPORT_PARAMETER_ERROR: client sent a stateless_reset_token"))
	})

	It("errors if the client sent the original_destination_connection_id", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, uint64(originalDestinationConnectionIDParameterID))
		utils.WriteVarInt(b, 6)
		b.Write([]byte("foobar"))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError("TRANSPORT_PARAMETER_ERROR: client sent an original_destination_connection_id"))
	})

	Context("preferred address", func() {
		var pa *PreferredAddress

		BeforeEach(func() {
			pa = &PreferredAddress{
				IPv4:                net.IPv4(127, 0, 0, 1),
				IPv4Port:            42,
				IPv6:                net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				IPv6Port:            13,
				ConnectionID:        protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
				StatelessResetToken: [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			}
		})

		It("marshals and unmarshals", func() {
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			p := &TransportParameters{}
			Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
			Expect(p.PreferredAddress.IPv4.String()).To(Equal(pa.IPv4.String()))
			Expect(p.PreferredAddress.IPv4Port).To(Equal(pa.IPv4Port))
			Expect(p.PreferredAddress.IPv6.String()).To(Equal(pa.IPv6.String()))
			Expect(p.PreferredAddress.IPv6Port).To(Equal(pa.IPv6Port))
			Expect(p.PreferredAddress.ConnectionID).To(Equal(pa.ConnectionID))
			Expect(p.PreferredAddress.StatelessResetToken).To(Equal(pa.StatelessResetToken))
		})

		It("errors if the client sent a preferred_address", func() {
			b := &bytes.Buffer{}
			utils.WriteVarInt(b, uint64(preferredAddressParameterID))
			utils.WriteVarInt(b, 6)
			b.Write([]byte("foobar"))
			p := &TransportParameters{}
			Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError("TRANSPORT_PARAMETER_ERROR: client sent a preferred_address"))
		})

		It("errors on zero-length connection IDs", func() {
			pa.ConnectionID = protocol.ConnectionID{}
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			p := &TransportParameters{}
			Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: invalid connection ID length: 0"))
		})

		It("errors on too long connection IDs", func() {
			pa.ConnectionID = protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
			Expect(pa.ConnectionID.Len()).To(BeNumerically(">", protocol.MaxConnIDLen))
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &token,
			}).Marshal(protocol.PerspectiveServer)
			p := &TransportParameters{}
			Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("TRANSPORT_PARAMETER_ERROR: invalid connection ID length: 21"))
		})

		It("errors on EOF", func() {
			raw := []byte{
				127, 0, 0, 1, // IPv4
				0, 42, // IPv4 Port
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // IPv6
				13, 37, // IPv6 Port,
				4, // conn ID len
				0xde, 0xad, 0xbe, 0xef,
				16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, // stateless reset token
			}
			for i := 1; i < len(raw); i++ {
				buf := &bytes.Buffer{}
				utils.WriteVarInt(buf, uint64(preferredAddressParameterID))
				buf.Write(raw[:i])
				p := &TransportParameters{}
				Expect(p.Unmarshal(buf.Bytes(), protocol.PerspectiveServer)).ToNot(Succeed())
			}
		})
	})

	Context("saving and retrieving from a session ticket", func() {
		It("saves and retrieves the parameters", func() {
			params := &TransportParameters{
				InitialMaxStreamDataBidiLocal:  protocol.ByteCount(getRandomValue()),
				InitialMaxStreamDataBidiRemote: protocol.ByteCount(getRandomValue()),
				InitialMaxStreamDataUni:        protocol.ByteCount(getRandomValue()),
				InitialMaxData:                 protocol.ByteCount(getRandomValue()),
				MaxBidiStreamNum:               protocol.StreamNum(getRandomValue()),
				MaxUniStreamNum:                protocol.StreamNum(getRandomValue()),
				ActiveConnectionIDLimit:        getRandomValue(),
			}
			Expect(params.ValidFor0RTT(params)).To(BeTrue())
			b := &bytes.Buffer{}
			params.MarshalForSessionTicket(b)
			var tp TransportParameters
			Expect(tp.UnmarshalFromSessionTicket(b.Bytes())).To(Succeed())
			Expect(tp.InitialMaxStreamDataBidiLocal).To(Equal(params.InitialMaxStreamDataBidiLocal))
			Expect(tp.InitialMaxStreamDataBidiRemote).To(Equal(params.InitialMaxStreamDataBidiRemote))
			Expect(tp.InitialMaxStreamDataUni).To(Equal(params.InitialMaxStreamDataUni))
			Expect(tp.InitialMaxData).To(Equal(params.InitialMaxData))
			Expect(tp.MaxBidiStreamNum).To(Equal(params.MaxBidiStreamNum))
			Expect(tp.MaxUniStreamNum).To(Equal(params.MaxUniStreamNum))
			Expect(tp.ActiveConnectionIDLimit).To(Equal(params.ActiveConnectionIDLimit))
		})

		It("rejects the parameters if it can't parse them", func() {
			var p TransportParameters
			Expect(p.UnmarshalFromSessionTicket([]byte("foobar"))).ToNot(Succeed())
		})

		It("rejects the parameters if the version changed", func() {
			var p TransportParameters
			buf := &bytes.Buffer{}
			p.MarshalForSessionTicket(buf)
			data := buf.Bytes()
			b := &bytes.Buffer{}
			utils.WriteVarInt(b, transportParameterMarshalingVersion+1)
			b.Write(data[utils.VarIntLen(transportParameterMarshalingVersion):])
			Expect(p.UnmarshalFromSessionTicket(b.Bytes())).To(MatchError(fmt.Sprintf("unknown transport parameter marshaling version: %d", transportParameterMarshalingVersion+1)))
		})

		Context("rejects the parameters if they changed", func() {
			var p *TransportParameters
			params := &TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
				InitialMaxStreamDataUni:        3,
				InitialMaxData:                 4,
				MaxBidiStreamNum:               5,
				MaxUniStreamNum:                6,
			}

			BeforeEach(func() {
				p = &TransportParameters{
					InitialMaxStreamDataBidiLocal:  1,
					InitialMaxStreamDataBidiRemote: 2,
					InitialMaxStreamDataUni:        3,
					InitialMaxData:                 4,
					MaxBidiStreamNum:               5,
					MaxUniStreamNum:                6,
				}
				Expect(params.ValidFor0RTT(p)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiLocal changed", func() {
				p.InitialMaxStreamDataBidiLocal = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiRemote changed", func() {
				p.InitialMaxStreamDataBidiRemote = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})

			It("rejects the parameters if the InitialMaxStreamDataUni changed", func() {
				p.InitialMaxStreamDataUni = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})

			It("rejects the parameters if the InitialMaxData changed", func() {
				p.InitialMaxData = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})

			It("rejects the parameters if the MaxBidiStreamNum changed", func() {
				p.MaxBidiStreamNum = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})

			It("rejects the parameters if the MaxUniStreamNum changed", func() {
				p.MaxUniStreamNum = 0
				Expect(params.ValidFor0RTT(p)).To(BeFalse())
			})
		})
	})
})
