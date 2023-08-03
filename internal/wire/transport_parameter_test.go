package wire

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport Parameters", func() {
	getRandomValueUpTo := func(max int64) uint64 {
		maxVals := []int64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
		m := maxVals[int(rand.Int31n(4))]
		if m > max {
			m = max
		}
		return uint64(rand.Int63n(m))
	}

	getRandomValue := func() uint64 {
		return getRandomValueUpTo(math.MaxInt64)
	}

	BeforeEach(func() {
		rand.Seed(uint64(GinkgoRandomSeed()))
	})

	appendInitialSourceConnectionID := func(b []byte) []byte {
		b = quicvarint.Append(b, uint64(initialSourceConnectionIDParameterID))
		b = quicvarint.Append(b, 6)
		return append(b, []byte("foobar")...)
	}

	It("has a string representation", func() {
		rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   1234,
			InitialMaxStreamDataBidiRemote:  2345,
			InitialMaxStreamDataUni:         3456,
			InitialMaxData:                  4567,
			MaxBidiStreamNum:                1337,
			MaxUniStreamNum:                 7331,
			MaxIdleTimeout:                  42 * time.Second,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
			RetrySourceConnectionID:         &rcid,
			AckDelayExponent:                14,
			MaxAckDelay:                     37 * time.Millisecond,
			StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
			ActiveConnectionIDLimit:         123,
			MaxDatagramFrameSize:            876,
		}
		Expect(p.String()).To(Equal("&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: decafbad, RetrySourceConnectionID: deadc0de, InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37ms, ActiveConnectionIDLimit: 123, StatelessResetToken: 0x112233445566778899aabbccddeeff00, MaxDatagramFrameSize: 876}"))
	})

	It("has a string representation, if there's no stateless reset token, no Retry source connection id and no datagram support", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   1234,
			InitialMaxStreamDataBidiRemote:  2345,
			InitialMaxStreamDataUni:         3456,
			InitialMaxData:                  4567,
			MaxBidiStreamNum:                1337,
			MaxUniStreamNum:                 7331,
			MaxIdleTimeout:                  42 * time.Second,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{}),
			AckDelayExponent:                14,
			MaxAckDelay:                     37 * time.Second,
			ActiveConnectionIDLimit:         89,
			MaxDatagramFrameSize:            protocol.InvalidByteCount,
		}
		Expect(p.String()).To(Equal("&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: (empty), InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37s, ActiveConnectionIDLimit: 89}"))
	})

	It("marshals and unmarshals", func() {
		var token protocol.StatelessResetToken
		rand.Read(token[:])
		rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
		params := &TransportParameters{
			InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
			InitialMaxData:                  protocol.ByteCount(getRandomValue()),
			MaxIdleTimeout:                  0xcafe * time.Second,
			MaxBidiStreamNum:                protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
			MaxUniStreamNum:                 protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
			DisableActiveMigration:          true,
			StatelessResetToken:             &token,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
			RetrySourceConnectionID:         &rcid,
			AckDelayExponent:                13,
			MaxAckDelay:                     42 * time.Millisecond,
			ActiveConnectionIDLimit:         2 + getRandomValueUpTo(math.MaxInt64-2),
			MaxDatagramFrameSize:            protocol.ByteCount(getRandomValue()),
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
		Expect(p.OriginalDestinationConnectionID).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})))
		Expect(p.InitialSourceConnectionID).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})))
		Expect(p.RetrySourceConnectionID).To(Equal(&rcid))
		Expect(p.AckDelayExponent).To(Equal(uint8(13)))
		Expect(p.MaxAckDelay).To(Equal(42 * time.Millisecond))
		Expect(p.ActiveConnectionIDLimit).To(Equal(params.ActiveConnectionIDLimit))
		Expect(p.MaxDatagramFrameSize).To(Equal(params.MaxDatagramFrameSize))
	})

	It("marshals additional transport parameters (used for testing large ClientHellos)", func() {
		origAdditionalTransportParametersClient := AdditionalTransportParametersClient
		defer func() {
			AdditionalTransportParametersClient = origAdditionalTransportParametersClient
		}()
		AdditionalTransportParametersClient = map[uint64][]byte{1337: []byte("foobar")}

		result := quicvarint.Append([]byte{}, 1337)
		result = quicvarint.Append(result, 6)
		result = append(result, []byte("foobar")...)

		params := &TransportParameters{}
		Expect(bytes.Contains(params.Marshal(protocol.PerspectiveClient), result)).To(BeTrue())
		Expect(bytes.Contains(params.Marshal(protocol.PerspectiveServer), result)).To(BeFalse())
	})

	It("doesn't marshal a retry_source_connection_id, if no Retry was performed", func() {
		data := (&TransportParameters{
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).To(BeNil())
	})

	It("marshals a zero-length retry_source_connection_id", func() {
		rcid := protocol.ParseConnectionID([]byte{})
		data := (&TransportParameters{
			RetrySourceConnectionID: &rcid,
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: 2,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).ToNot(BeNil())
		Expect(p.RetrySourceConnectionID.Len()).To(BeZero())
	})

	It("errors when the stateless_reset_token has the wrong length", func() {
		b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
		b = quicvarint.Append(b, 15)
		b = append(b, make([]byte, 15)...)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "wrong length for stateless_reset_token: 15 (expected 16)",
		}))
	})

	It("errors when the max_packet_size is too small", func() {
		b := quicvarint.Append(nil, uint64(maxUDPPayloadSizeParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(1199)))
		b = quicvarint.Append(b, 1199)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for max_packet_size: 1199 (minimum 1200)",
		}))
	})

	It("errors when disable_active_migration has content", func() {
		b := quicvarint.Append(nil, uint64(disableActiveMigrationParameterID))
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "wrong length for disable_active_migration: 6 (expected empty)",
		}))
	})

	It("errors when the server doesn't set the original_destination_connection_id", func() {
		b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
		b = quicvarint.Append(b, 16)
		b = append(b, make([]byte, 16)...)
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "missing original_destination_connection_id",
		}))
	})

	It("errors when the initial_source_connection_id is missing", func() {
		Expect((&TransportParameters{}).Unmarshal([]byte{}, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "missing initial_source_connection_id",
		}))
	})

	It("errors when the max_ack_delay is too large", func() {
		data := (&TransportParameters{
			MaxAckDelay:         1 << 14 * time.Millisecond,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for max_ack_delay: 16384ms (maximum 16383ms)",
		}))
	})

	It("doesn't send the max_ack_delay, if it has the default value", func() {
		const num = 1000
		var defaultLen, dataLen int
		// marshal 1000 times to average out the greasing transport parameter
		maxAckDelay := protocol.DefaultMaxAckDelay + time.Millisecond
		for i := 0; i < num; i++ {
			dataDefault := (&TransportParameters{
				MaxAckDelay:         protocol.DefaultMaxAckDelay,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			defaultLen += len(dataDefault)
			data := (&TransportParameters{
				MaxAckDelay:         maxAckDelay,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			dataLen += len(data)
		}
		entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) /* parameter id */ + quicvarint.Len(uint64(quicvarint.Len(uint64(maxAckDelay.Milliseconds())))) /*length */ + quicvarint.Len(uint64(maxAckDelay.Milliseconds())) /* value */
		Expect(float32(dataLen) / num).To(BeNumerically("~", float32(defaultLen)/num+float32(entryLen), 1))
	})

	It("errors when the active_connection_id_limit is too small", func() {
		data := (&TransportParameters{
			ActiveConnectionIDLimit: 1,
			StatelessResetToken:     &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for active_connection_id_limit: 1 (minimum 2)",
		}))
	})

	It("errors when the ack_delay_exponenent is too large", func() {
		data := (&TransportParameters{
			AckDelayExponent:    21,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for ack_delay_exponent: 21 (maximum 20)",
		}))
	})

	It("doesn't send the ack_delay_exponent, if it has the default value", func() {
		const num = 1000
		var defaultLen, dataLen int
		// marshal 1000 times to average out the greasing transport parameter
		for i := 0; i < num; i++ {
			dataDefault := (&TransportParameters{
				AckDelayExponent:    protocol.DefaultAckDelayExponent,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			defaultLen += len(dataDefault)
			data := (&TransportParameters{
				AckDelayExponent:    protocol.DefaultAckDelayExponent + 1,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			dataLen += len(data)
		}
		entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) /* parameter id */ + quicvarint.Len(uint64(quicvarint.Len(protocol.DefaultAckDelayExponent+1))) /* length */ + quicvarint.Len(protocol.DefaultAckDelayExponent+1) /* value */
		Expect(float32(dataLen) / num).To(BeNumerically("~", float32(defaultLen)/num+float32(entryLen), 1))
	})

	It("sets the default value for the ack_delay_exponent and max_active_connection_id_limit, when no values were sent", func() {
		data := (&TransportParameters{
			AckDelayExponent:        protocol.DefaultAckDelayExponent,
			StatelessResetToken:     &protocol.StatelessResetToken{},
			ActiveConnectionIDLimit: protocol.DefaultActiveConnectionIDLimit,
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.AckDelayExponent).To(BeEquivalentTo(protocol.DefaultAckDelayExponent))
		Expect(p.ActiveConnectionIDLimit).To(BeEquivalentTo(protocol.DefaultActiveConnectionIDLimit))
	})

	It("errors when the varint value has the wrong length", func() {
		b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
		b = quicvarint.Append(b, 2)
		val := uint64(0xdeadbeef)
		Expect(quicvarint.Len(val)).ToNot(BeEquivalentTo(2))
		b = quicvarint.Append(b, val)
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("inconsistent transport parameter length for transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		}))
	})

	It("errors if initial_max_streams_bidi is too large", func() {
		b := quicvarint.Append(nil, uint64(initialMaxStreamsBidiParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
		b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "initial_max_streams_bidi too large: 1152921504606846977 (maximum 1152921504606846976)",
		}))
	})

	It("errors if initial_max_streams_uni is too large", func() {
		b := quicvarint.Append(nil, uint64(initialMaxStreamsUniParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
		b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "initial_max_streams_uni too large: 1152921504606846977 (maximum 1152921504606846976)",
		}))
	})

	It("handles huge max_ack_delay values", func() {
		val := uint64(math.MaxUint64) / 5
		b := quicvarint.Append(nil, uint64(maxAckDelayParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
		b = quicvarint.Append(b, val)
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for max_ack_delay: 3689348814741910323ms (maximum 16383ms)",
		}))
	})

	It("skips unknown parameters", func() {
		// write a known parameter
		b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
		b = quicvarint.Append(b, 0x1337)
		// write an unknown parameter
		b = quicvarint.Append(b, 0x42)
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)
		// write a known parameter
		b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
		b = quicvarint.Append(b, 0x42)
		b = appendInitialSourceConnectionID(b)
		p := &TransportParameters{}
		Expect(p.Unmarshal(b, protocol.PerspectiveClient)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(protocol.ByteCount(0x1337)))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(protocol.ByteCount(0x42)))
	})

	It("rejects duplicate parameters", func() {
		// write first parameter
		b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
		b = quicvarint.Append(b, 0x1337)
		// write a second parameter
		b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
		b = quicvarint.Append(b, 0x42)
		// write first parameter again
		b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
		b = quicvarint.Append(b, 0x1337)
		b = appendInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("received duplicate transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		}))
	})

	It("errors if there's not enough data to read", func() {
		b := quicvarint.Append(nil, 0x42)
		b = quicvarint.Append(b, 7)
		b = append(b, []byte("foobar")...)
		p := &TransportParameters{}
		Expect(p.Unmarshal(b, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "remaining length (6) smaller than parameter length (7)",
		}))
	})

	It("errors if the client sent a stateless_reset_token", func() {
		b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
		b = quicvarint.Append(b, uint64(quicvarint.Len(16)))
		b = append(b, make([]byte, 16)...)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "client sent a stateless_reset_token",
		}))
	})

	It("errors if the client sent the original_destination_connection_id", func() {
		b := quicvarint.Append(nil, uint64(originalDestinationConnectionIDParameterID))
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)
		Expect((&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "client sent an original_destination_connection_id",
		}))
	})

	Context("preferred address", func() {
		var pa *PreferredAddress

		BeforeEach(func() {
			pa = &PreferredAddress{
				IPv4:                net.IPv4(127, 0, 0, 1),
				IPv4Port:            42,
				IPv6:                net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				IPv6Port:            13,
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			}
		})

		It("marshals and unmarshals", func() {
			data := (&TransportParameters{
				PreferredAddress:        pa,
				StatelessResetToken:     &protocol.StatelessResetToken{},
				ActiveConnectionIDLimit: 2,
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
			b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
			b = quicvarint.Append(b, 6)
			b = append(b, []byte("foobar")...)
			p := &TransportParameters{}
			Expect(p.Unmarshal(b, protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "client sent a preferred_address",
			}))
		})

		It("errors on zero-length connection IDs", func() {
			pa.ConnectionID = protocol.ParseConnectionID([]byte{})
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			p := &TransportParameters{}
			Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "invalid connection ID length: 0",
			}))
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
				b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
				b = append(b, raw[:i]...)
				p := &TransportParameters{}
				Expect(p.Unmarshal(b, protocol.PerspectiveServer)).ToNot(Succeed())
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
				MaxBidiStreamNum:               protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
				MaxUniStreamNum:                protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
				ActiveConnectionIDLimit:        2 + getRandomValueUpTo(math.MaxInt64-2),
				MaxDatagramFrameSize:           protocol.ByteCount(getRandomValueUpTo(int64(protocol.MaxDatagramFrameSize))),
			}
			Expect(params.ValidFor0RTT(params)).To(BeTrue())
			b := params.MarshalForSessionTicket(nil)
			var tp TransportParameters
			Expect(tp.UnmarshalFromSessionTicket(bytes.NewReader(b))).To(Succeed())
			Expect(tp.InitialMaxStreamDataBidiLocal).To(Equal(params.InitialMaxStreamDataBidiLocal))
			Expect(tp.InitialMaxStreamDataBidiRemote).To(Equal(params.InitialMaxStreamDataBidiRemote))
			Expect(tp.InitialMaxStreamDataUni).To(Equal(params.InitialMaxStreamDataUni))
			Expect(tp.InitialMaxData).To(Equal(params.InitialMaxData))
			Expect(tp.MaxBidiStreamNum).To(Equal(params.MaxBidiStreamNum))
			Expect(tp.MaxUniStreamNum).To(Equal(params.MaxUniStreamNum))
			Expect(tp.ActiveConnectionIDLimit).To(Equal(params.ActiveConnectionIDLimit))
			Expect(tp.MaxDatagramFrameSize).To(Equal(params.MaxDatagramFrameSize))
		})

		It("rejects the parameters if it can't parse them", func() {
			var p TransportParameters
			Expect(p.UnmarshalFromSessionTicket(bytes.NewReader([]byte("foobar")))).ToNot(Succeed())
		})

		It("rejects the parameters if the version changed", func() {
			var p TransportParameters
			data := p.MarshalForSessionTicket(nil)
			b := quicvarint.Append(nil, transportParameterMarshalingVersion+1)
			b = append(b, data[quicvarint.Len(transportParameterMarshalingVersion):]...)
			Expect(p.UnmarshalFromSessionTicket(bytes.NewReader(b))).To(MatchError(fmt.Sprintf("unknown transport parameter marshaling version: %d", transportParameterMarshalingVersion+1)))
		})

		Context("rejects the parameters if they changed", func() {
			var p TransportParameters
			saved := &TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
				InitialMaxStreamDataUni:        3,
				InitialMaxData:                 4,
				MaxBidiStreamNum:               5,
				MaxUniStreamNum:                6,
				ActiveConnectionIDLimit:        7,
				MaxDatagramFrameSize:           1000,
			}

			BeforeEach(func() {
				p = *saved
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiLocal was reduced", func() {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataBidiLocal was increased", func() {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiRemote was reduced", func() {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataBidiRemote was increased", func() {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataUni was reduced", func() {
				p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataUni was increased", func() {
				p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxData was reduced", func() {
				p.InitialMaxData = saved.InitialMaxData - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxData was increased", func() {
				p.InitialMaxData = saved.InitialMaxData + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxBidiStreamNum was reduced", func() {
				p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("accepts the parameters if the MaxBidiStreamNum was increased", func() {
				p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxUniStreamNum changed", func() {
				p.MaxUniStreamNum = saved.MaxUniStreamNum - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("accepts the parameters if the MaxUniStreamNum was increased", func() {
				p.MaxUniStreamNum = saved.MaxUniStreamNum + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the ActiveConnectionIDLimit changed", func() {
				p.ActiveConnectionIDLimit = 0
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})

			It("accepts the parameters if the MaxDatagramFrameSize was increased", func() {
				p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1
				Expect(p.ValidFor0RTT(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxDatagramFrameSize reduced", func() {
				p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1
				Expect(p.ValidFor0RTT(saved)).To(BeFalse())
			})
		})

		Context("client checks the parameters after successfully sending 0-RTT data", func() {
			var p TransportParameters
			saved := &TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
				InitialMaxStreamDataUni:        3,
				InitialMaxData:                 4,
				MaxBidiStreamNum:               5,
				MaxUniStreamNum:                6,
				ActiveConnectionIDLimit:        7,
				MaxDatagramFrameSize:           1000,
			}

			BeforeEach(func() {
				p = *saved
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiLocal was reduced", func() {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataBidiLocal was increased", func() {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataBidiRemote was reduced", func() {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataBidiRemote was increased", func() {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxStreamDataUni was reduced", func() {
				p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxStreamDataUni was increased", func() {
				p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the InitialMaxData was reduced", func() {
				p.InitialMaxData = saved.InitialMaxData - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the InitialMaxData was increased", func() {
				p.InitialMaxData = saved.InitialMaxData + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxBidiStreamNum was reduced", func() {
				p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the MaxBidiStreamNum was increased", func() {
				p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxUniStreamNum reduced", func() {
				p.MaxUniStreamNum = saved.MaxUniStreamNum - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the MaxUniStreamNum was increased", func() {
				p.MaxUniStreamNum = saved.MaxUniStreamNum + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the ActiveConnectionIDLimit reduced", func() {
				p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the ActiveConnectionIDLimit increased", func() {
				p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})

			It("rejects the parameters if the MaxDatagramFrameSize reduced", func() {
				p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1
				Expect(p.ValidForUpdate(saved)).To(BeFalse())
			})

			It("doesn't reject the parameters if the MaxDatagramFrameSize increased", func() {
				p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1
				Expect(p.ValidForUpdate(saved)).To(BeTrue())
			})
		})
	})
})
