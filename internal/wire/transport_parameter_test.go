package wire

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
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
		rand.Seed(GinkgoRandomSeed())
	})

	addInitialSourceConnectionID := func(b *bytes.Buffer) {
		quicvarint.Write(b, uint64(initialSourceConnectionIDParameterID))
		quicvarint.Write(b, 6)
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
			OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			InitialSourceConnectionID:       protocol.ConnectionID{},
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
			OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			InitialSourceConnectionID:       protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
			RetrySourceConnectionID:         &protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
			AckDelayExponent:                13,
			MaxAckDelay:                     42 * time.Millisecond,
			ActiveConnectionIDLimit:         getRandomValue(),
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
		Expect(p.OriginalDestinationConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
		Expect(p.InitialSourceConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		Expect(p.RetrySourceConnectionID).To(Equal(&protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde}))
		Expect(p.AckDelayExponent).To(Equal(uint8(13)))
		Expect(p.MaxAckDelay).To(Equal(42 * time.Millisecond))
		Expect(p.ActiveConnectionIDLimit).To(Equal(params.ActiveConnectionIDLimit))
		Expect(p.MaxDatagramFrameSize).To(Equal(params.MaxDatagramFrameSize))
	})

	It("doesn't marshal a retry_source_connection_id, if no Retry was performed", func() {
		data := (&TransportParameters{
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).To(BeNil())
	})

	It("marshals a zero-length retry_source_connection_id", func() {
		data := (&TransportParameters{
			RetrySourceConnectionID: &protocol.ConnectionID{},
			StatelessResetToken:     &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.RetrySourceConnectionID).ToNot(BeNil())
		Expect(p.RetrySourceConnectionID.Len()).To(BeZero())
	})

	It("errors when the stateless_reset_token has the wrong length", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(statelessResetTokenParameterID))
		quicvarint.Write(b, 15)
		b.Write(make([]byte, 15))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "wrong length for stateless_reset_token: 15 (expected 16)",
		}))
	})

	It("errors when the max_packet_size is too small", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(maxUDPPayloadSizeParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(1199)))
		quicvarint.Write(b, 1199)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for max_packet_size: 1199 (minimum 1200)",
		}))
	})

	It("errors when disable_active_migration has content", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(disableActiveMigrationParameterID))
		quicvarint.Write(b, 6)
		b.Write([]byte("foobar"))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "wrong length for disable_active_migration: 6 (expected empty)",
		}))
	})

	It("errors when the server doesn't set the original_destination_connection_id", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(statelessResetTokenParameterID))
		quicvarint.Write(b, 16)
		b.Write(make([]byte, 16))
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
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

	It("sets the default value for the ack_delay_exponent, when no value was sent", func() {
		data := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.AckDelayExponent).To(BeEquivalentTo(protocol.DefaultAckDelayExponent))
	})

	It("errors when the varint value has the wrong length", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		quicvarint.Write(b, 2)
		val := uint64(0xdeadbeef)
		Expect(quicvarint.Len(val)).ToNot(BeEquivalentTo(2))
		quicvarint.Write(b, val)
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("inconsistent transport parameter length for transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		}))
	})

	It("errors if initial_max_streams_bidi is too large", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(initialMaxStreamsBidiParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
		quicvarint.Write(b, uint64(protocol.MaxStreamCount+1))
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "initial_max_streams_bidi too large: 1152921504606846977 (maximum 1152921504606846976)",
		}))
	})

	It("errors if initial_max_streams_uni is too large", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(initialMaxStreamsUniParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
		quicvarint.Write(b, uint64(protocol.MaxStreamCount+1))
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "initial_max_streams_uni too large: 1152921504606846977 (maximum 1152921504606846976)",
		}))
	})

	It("handles huge max_ack_delay values", func() {
		b := &bytes.Buffer{}
		val := uint64(math.MaxUint64) / 5
		quicvarint.Write(b, uint64(maxAckDelayParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(val)))
		quicvarint.Write(b, val)
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "invalid value for max_ack_delay: 3689348814741910323ms (maximum 16383ms)",
		}))
	})

	It("skips unknown parameters", func() {
		b := &bytes.Buffer{}
		// write a known parameter
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(0x1337)))
		quicvarint.Write(b, 0x1337)
		// write an unknown parameter
		quicvarint.Write(b, 0x42)
		quicvarint.Write(b, 6)
		b.Write([]byte("foobar"))
		// write a known parameter
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(0x42)))
		quicvarint.Write(b, 0x42)
		addInitialSourceConnectionID(b)
		p := &TransportParameters{}
		Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(protocol.ByteCount(0x1337)))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(protocol.ByteCount(0x42)))
	})

	It("rejects duplicate parameters", func() {
		b := &bytes.Buffer{}
		// write first parameter
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(0x1337)))
		quicvarint.Write(b, 0x1337)
		// write a second parameter
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(0x42)))
		quicvarint.Write(b, 0x42)
		// write first parameter again
		quicvarint.Write(b, uint64(initialMaxStreamDataBidiLocalParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(0x1337)))
		quicvarint.Write(b, 0x1337)
		addInitialSourceConnectionID(b)
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("received duplicate transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		}))
	})

	It("errors if there's not enough data to read", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, 0x42)
		quicvarint.Write(b, 7)
		b.Write([]byte("foobar"))
		p := &TransportParameters{}
		Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "remaining length (6) smaller than parameter length (7)",
		}))
	})

	It("errors if the client sent a stateless_reset_token", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(statelessResetTokenParameterID))
		quicvarint.Write(b, uint64(quicvarint.Len(16)))
		b.Write(make([]byte, 16))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: "client sent a stateless_reset_token",
		}))
	})

	It("errors if the client sent the original_destination_connection_id", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, uint64(originalDestinationConnectionIDParameterID))
		quicvarint.Write(b, 6)
		b.Write([]byte("foobar"))
		Expect((&TransportParameters{}).Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
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
				ConnectionID:        protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
				StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			}
		})

		It("marshals and unmarshals", func() {
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &protocol.StatelessResetToken{},
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
			quicvarint.Write(b, uint64(preferredAddressParameterID))
			quicvarint.Write(b, 6)
			b.Write([]byte("foobar"))
			p := &TransportParameters{}
			Expect(p.Unmarshal(b.Bytes(), protocol.PerspectiveClient)).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "client sent a preferred_address",
			}))
		})

		It("errors on zero-length connection IDs", func() {
			pa.ConnectionID = protocol.ConnectionID{}
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

		It("errors on too long connection IDs", func() {
			pa.ConnectionID = protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
			Expect(pa.ConnectionID.Len()).To(BeNumerically(">", protocol.MaxConnIDLen))
			data := (&TransportParameters{
				PreferredAddress:    pa,
				StatelessResetToken: &protocol.StatelessResetToken{},
			}).Marshal(protocol.PerspectiveServer)
			p := &TransportParameters{}
			Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "invalid connection ID length: 21",
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
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, uint64(preferredAddressParameterID))
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
				MaxBidiStreamNum:               protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
				MaxUniStreamNum:                protocol.StreamNum(getRandomValueUpTo(int64(protocol.MaxStreamCount))),
				ActiveConnectionIDLimit:        getRandomValue(),
			}
			Expect(params.ValidFor0RTT(params)).To(BeTrue())
			b := &bytes.Buffer{}
			params.MarshalForSessionTicket(b)
			var tp TransportParameters
			Expect(tp.UnmarshalFromSessionTicket(bytes.NewReader(b.Bytes()))).To(Succeed())
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
			Expect(p.UnmarshalFromSessionTicket(bytes.NewReader([]byte("foobar")))).ToNot(Succeed())
		})

		It("rejects the parameters if the version changed", func() {
			var p TransportParameters
			buf := &bytes.Buffer{}
			p.MarshalForSessionTicket(buf)
			data := buf.Bytes()
			b := &bytes.Buffer{}
			quicvarint.Write(b, transportParameterMarshalingVersion+1)
			b.Write(data[quicvarint.Len(transportParameterMarshalingVersion):])
			Expect(p.UnmarshalFromSessionTicket(bytes.NewReader(b.Bytes()))).To(MatchError(fmt.Sprintf("unknown transport parameter marshaling version: %d", transportParameterMarshalingVersion+1)))
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
		})
	})
})
