package handshake

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport Parameters", func() {
	prependLength := func(tp []byte) []byte {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, uint16(len(tp)))
		return append(data, tp...)
	}

	It("has a string representation", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:  0x1234,
			InitialMaxStreamDataBidiRemote: 0x2345,
			InitialMaxStreamDataUni:        0x3456,
			InitialMaxData:                 0x4567,
			MaxBidiStreamNum:               1337,
			MaxUniStreamNum:                7331,
			IdleTimeout:                    42 * time.Second,
			OriginalConnectionID:           protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			AckDelayExponent:               14,
			MaxAckDelay:                    37 * time.Millisecond,
			StatelessResetToken:            &[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
		}
		Expect(p.String()).To(Equal("&handshake.TransportParameters{OriginalConnectionID: 0xdeadbeef, InitialMaxStreamDataBidiLocal: 0x1234, InitialMaxStreamDataBidiRemote: 0x2345, InitialMaxStreamDataUni: 0x3456, InitialMaxData: 0x4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, IdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37ms, StatelessResetToken: 0x112233445566778899aabbccddeeff00}"))
	})

	It("has a string representation, if there's no stateless reset token", func() {
		p := &TransportParameters{
			InitialMaxStreamDataBidiLocal:  0x1234,
			InitialMaxStreamDataBidiRemote: 0x2345,
			InitialMaxStreamDataUni:        0x3456,
			InitialMaxData:                 0x4567,
			MaxBidiStreamNum:               1337,
			MaxUniStreamNum:                7331,
			IdleTimeout:                    42 * time.Second,
			OriginalConnectionID:           protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			AckDelayExponent:               14,
			MaxAckDelay:                    37 * time.Second,
		}
		Expect(p.String()).To(Equal("&handshake.TransportParameters{OriginalConnectionID: 0xdeadbeef, InitialMaxStreamDataBidiLocal: 0x1234, InitialMaxStreamDataBidiRemote: 0x2345, InitialMaxStreamDataUni: 0x3456, InitialMaxData: 0x4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, IdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37s}"))
	})

	It("marshals and unmarshals", func() {
		rand.Seed(GinkgoRandomSeed())
		getRandomValue := func() uint64 {
			maxVals := []int64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
			return uint64(rand.Int63n(maxVals[int(rand.Int31n(4))]))
		}

		var token [16]byte
		rand.Read(token[:])
		params := &TransportParameters{
			InitialMaxStreamDataBidiLocal:  protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataBidiRemote: protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataUni:        protocol.ByteCount(getRandomValue()),
			InitialMaxData:                 protocol.ByteCount(getRandomValue()),
			IdleTimeout:                    0xcafe * time.Second,
			MaxBidiStreamNum:               protocol.StreamNum(getRandomValue()),
			MaxUniStreamNum:                protocol.StreamNum(getRandomValue()),
			DisableMigration:               true,
			StatelessResetToken:            &token,
			OriginalConnectionID:           protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			AckDelayExponent:               13,
			MaxAckDelay:                    42 * time.Millisecond,
		}
		data := params.Marshal()

		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(params.InitialMaxStreamDataBidiLocal))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(params.InitialMaxStreamDataBidiRemote))
		Expect(p.InitialMaxStreamDataUni).To(Equal(params.InitialMaxStreamDataUni))
		Expect(p.InitialMaxData).To(Equal(params.InitialMaxData))
		Expect(p.MaxUniStreamNum).To(Equal(params.MaxUniStreamNum))
		Expect(p.MaxBidiStreamNum).To(Equal(params.MaxBidiStreamNum))
		Expect(p.IdleTimeout).To(Equal(params.IdleTimeout))
		Expect(p.DisableMigration).To(Equal(params.DisableMigration))
		Expect(p.StatelessResetToken).To(Equal(params.StatelessResetToken))
		Expect(p.OriginalConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
		Expect(p.AckDelayExponent).To(Equal(uint8(13)))
		Expect(p.MaxAckDelay).To(Equal(42 * time.Millisecond))
	})

	It("errors if the transport parameters are too short to contain the length", func() {
		Expect((&TransportParameters{}).Unmarshal([]byte{0}, protocol.PerspectiveClient)).To(MatchError("transport parameter data too short"))
	})

	It("errors if the transport parameters are too short to contain the length", func() {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, 42)
		data = append(data, make([]byte, 41)...)
		Expect((&TransportParameters{}).Unmarshal(data, protocol.PerspectiveClient)).To(MatchError("expected transport parameters to be 42 bytes long, have 41"))
	})

	It("errors when the stateless_reset_token has the wrong length", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, uint16(statelessResetTokenParameterID))
		utils.BigEndian.WriteUint16(b, 15)
		b.Write(make([]byte, 15))
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(MatchError("wrong length for stateless_reset_token: 15 (expected 16)"))
	})

	It("errors when the max_packet_size is too small", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, uint16(maxPacketSizeParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(1199)))
		utils.WriteVarInt(b, 1199)
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(MatchError("invalid value for max_packet_size: 1199 (minimum 1200)"))
	})

	It("errors when disable_migration has content", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, uint16(disableMigrationParameterID))
		utils.BigEndian.WriteUint16(b, 6)
		b.Write([]byte("foobar"))
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(MatchError("wrong length for disable_migration: 6 (expected empty)"))
	})

	It("errors when the max_ack_delay is too large", func() {
		data := (&TransportParameters{MaxAckDelay: 1 << 14 * time.Millisecond}).Marshal()
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("invalid value for max_ack_delay: 16384ms (maximum 16383ms)"))
	})

	It("doesn't send the max_ack_delay, if it has the default value", func() {
		dataDefault := (&TransportParameters{MaxAckDelay: protocol.DefaultMaxAckDelay}).Marshal()
		defaultLen := len(dataDefault)
		data := (&TransportParameters{MaxAckDelay: protocol.DefaultMaxAckDelay + time.Millisecond}).Marshal()
		Expect(len(data)).To(Equal(defaultLen + 2 /* parameter ID */ + 2 /* length field */ + 1 /* value */))
	})

	It("errors when the ack_delay_exponenent is too large", func() {
		data := (&TransportParameters{AckDelayExponent: 21}).Marshal()
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(MatchError("invalid value for ack_delay_exponent: 21 (maximum 20)"))
	})

	It("doesn't send the ack_delay_exponent, if it has the default value", func() {
		dataDefault := (&TransportParameters{AckDelayExponent: protocol.DefaultAckDelayExponent}).Marshal()
		defaultLen := len(dataDefault)
		data := (&TransportParameters{AckDelayExponent: protocol.DefaultAckDelayExponent + 1}).Marshal()
		Expect(len(data)).To(Equal(defaultLen + 2 /* parameter ID */ + 2 /* length field */ + 1 /* value */))
	})

	It("sets the default value for the ack_delay_exponent, when no value was sent", func() {
		data := (&TransportParameters{AckDelayExponent: protocol.DefaultAckDelayExponent}).Marshal()
		p := &TransportParameters{}
		Expect(p.Unmarshal(data, protocol.PerspectiveServer)).To(Succeed())
		Expect(p.AckDelayExponent).To(BeEquivalentTo(protocol.DefaultAckDelayExponent))
	})

	It("errors when the varint value has the wrong length", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiLocalParameterID))
		utils.BigEndian.WriteUint16(b, 2)
		val := uint64(0xdeadbeef)
		Expect(utils.VarIntLen(val)).ToNot(BeEquivalentTo(2))
		utils.WriteVarInt(b, val)
		p := &TransportParameters{}
		err := p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("inconsistent transport parameter length"))
	})

	It("skips unknown parameters", func() {
		b := &bytes.Buffer{}
		// write a known parameter
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiLocalParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		// write an unknown parameter
		utils.BigEndian.WriteUint16(b, 0x42)
		utils.BigEndian.WriteUint16(b, 6)
		b.Write([]byte("foobar"))
		// write a known parameter
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiRemoteParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x42)))
		utils.WriteVarInt(b, 0x42)
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(Succeed())
		Expect(p.InitialMaxStreamDataBidiLocal).To(Equal(protocol.ByteCount(0x1337)))
		Expect(p.InitialMaxStreamDataBidiRemote).To(Equal(protocol.ByteCount(0x42)))
	})

	It("rejects duplicate parameters", func() {
		b := &bytes.Buffer{}
		// write first parameter
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiLocalParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		// write a second parameter
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiRemoteParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x42)))
		utils.WriteVarInt(b, 0x42)
		// write first parameter again
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiLocalParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		p := &TransportParameters{}
		err := p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("received duplicate transport parameter"))
	})

	It("errors if there's not enough data to read", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, 0x42)
		utils.BigEndian.WriteUint16(b, 7)
		b.Write([]byte("foobar"))
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(MatchError("remaining length (6) smaller than parameter length (7)"))
	})

	It("errors if there's unprocessed data after reading", func() {
		b := &bytes.Buffer{}
		utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataBidiLocalParameterID))
		utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(0x1337)))
		utils.WriteVarInt(b, 0x1337)
		b.Write([]byte("foo"))
		p := &TransportParameters{}
		Expect(p.Unmarshal(prependLength(b.Bytes()), protocol.PerspectiveServer)).To(MatchError("should have read all data. Still have 3 bytes"))
	})

	It("errors if the client sent a stateless_reset_token", func() {
		var token [16]byte
		params := &TransportParameters{StatelessResetToken: &token}
		data := params.Marshal()
		Expect((&TransportParameters{}).Unmarshal(data, protocol.PerspectiveClient)).To(MatchError("client sent a stateless_reset_token"))
	})

	It("errors if the client sent a stateless_reset_token", func() {
		params := &TransportParameters{
			OriginalConnectionID: protocol.ConnectionID{0xca, 0xfe},
		}
		data := params.Marshal()
		Expect((&TransportParameters{}).Unmarshal(data, protocol.PerspectiveClient)).To(MatchError("client sent an original_connection_id"))
	})
})
