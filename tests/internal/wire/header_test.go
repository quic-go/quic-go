package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseConnIDLongHeaderPacket(t *testing.T) {
	b, err := (&ExtendedHeader{
		Header: Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6}),
			Version:          protocol.Version1,
		},
		PacketNumberLen: 2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	connID, err := ParseConnectionID(b, 8)
	require.NoError(t, err)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}), connID)
}

func TestParseConnIDTooLong(t *testing.T) {
	b := []byte{0x80, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(protocol.Version1))
	b = append(b, 21) // dest conn id len
	b = append(b, make([]byte, 21)...)
	_, err := ParseConnectionID(b, 4)
	require.Error(t, err)
	require.ErrorIs(t, err, protocol.ErrInvalidConnectionIDLen)
}

func TestParseConnIDEOFLongHeader(t *testing.T) {
	b, err := (&ExtendedHeader{
		Header: Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad, 0x13, 0x37}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 8, 9}),
			Version:          protocol.Version1,
		},
		PacketNumberLen: 2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	data := b[:len(b)-2] // cut the packet number
	_, err = ParseConnectionID(data, 8)
	require.NoError(t, err)
	for i := 0; i < 1 /* first byte */ +4 /* version */ +1 /* conn ID lengths */ +6; /* dest conn ID */ i++ {
		b := make([]byte, i)
		copy(b, data[:i])
		_, err := ParseConnectionID(b, 8)
		require.Error(t, err)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestIs0RTT(t *testing.T) {
	t.Run("QUIC v1", func(t *testing.T) {
		zeroRTTHeader := make([]byte, 5)
		zeroRTTHeader[0] = 0x80 | 0b01<<4
		binary.BigEndian.PutUint32(zeroRTTHeader[1:], uint32(protocol.Version1))

		require.True(t, Is0RTTPacket(zeroRTTHeader))
		require.False(t, Is0RTTPacket(zeroRTTHeader[:4]))                           // too short
		require.False(t, Is0RTTPacket([]byte{zeroRTTHeader[0], 1, 2, 3, 4}))        // unknown version
		require.False(t, Is0RTTPacket([]byte{zeroRTTHeader[0] | 0x80, 1, 2, 3, 4})) // short header
		require.True(t, Is0RTTPacket(append(zeroRTTHeader, []byte("foobar")...)))
	})

	t.Run("QUIC v2", func(t *testing.T) {
		zeroRTTHeader := make([]byte, 5)
		zeroRTTHeader[0] = 0x80 | 0b10<<4
		binary.BigEndian.PutUint32(zeroRTTHeader[1:], uint32(protocol.Version2))

		require.True(t, Is0RTTPacket(zeroRTTHeader))
		require.False(t, Is0RTTPacket(zeroRTTHeader[:4]))                           // too short
		require.False(t, Is0RTTPacket([]byte{zeroRTTHeader[0], 1, 2, 3, 4}))        // unknown version
		require.False(t, Is0RTTPacket([]byte{zeroRTTHeader[0] | 0x80, 1, 2, 3, 4})) // short header
		require.True(t, Is0RTTPacket(append(zeroRTTHeader, []byte("foobar")...)))
	})
}

func TestParseVersion(t *testing.T) {
	b := []byte{0x80, 0xde, 0xad, 0xbe, 0xef}
	v, err := ParseVersion(b)
	require.NoError(t, err)
	require.Equal(t, protocol.Version(0xdeadbeef), v)

	for i := range b {
		_, err := ParseVersion(b[:i])
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestParseArbitraryLengthConnectionIDs(t *testing.T) {
	generateConnID := func(l int) protocol.ArbitraryLenConnectionID {
		c := make(protocol.ArbitraryLenConnectionID, l)
		rand.Read(c)
		return c
	}

	src := generateConnID(mrand.IntN(255) + 1)
	dest := generateConnID(mrand.IntN(255) + 1)
	b := []byte{0x80, 1, 2, 3, 4}
	b = append(b, uint8(dest.Len()))
	b = append(b, dest.Bytes()...)
	b = append(b, uint8(src.Len()))
	b = append(b, src.Bytes()...)
	l := len(b)
	b = append(b, []byte("foobar")...) // add some payload

	parsed, d, s, err := ParseArbitraryLenConnectionIDs(b)
	require.Equal(t, l, parsed)
	require.NoError(t, err)
	require.Equal(t, src, s)
	require.Equal(t, dest, d)

	for i := range b[:l] {
		_, _, _, err := ParseArbitraryLenConnectionIDs(b[:i])
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestIdentifyVersionNegotiationPackets(t *testing.T) {
	require.True(t, IsVersionNegotiationPacket([]byte{0x80 | 0x56, 0, 0, 0, 0}))
	require.False(t, IsVersionNegotiationPacket([]byte{0x56, 0, 0, 0, 0}))
	require.False(t, IsVersionNegotiationPacket([]byte{0x80, 1, 0, 0, 0}))
	require.False(t, IsVersionNegotiationPacket([]byte{0x80, 0, 1, 0, 0}))
	require.False(t, IsVersionNegotiationPacket([]byte{0x80, 0, 0, 1, 0}))
	require.False(t, IsVersionNegotiationPacket([]byte{0x80, 0, 0, 0, 1}))
}

func TestVersionNegotiationPacketEOF(t *testing.T) {
	vnp := []byte{0x80, 0, 0, 0, 0}
	for i := range vnp {
		require.False(t, IsVersionNegotiationPacket(vnp[:i]))
	}
}

func TestParseLongHeader(t *testing.T) {
	destConnID := protocol.ParseConnectionID([]byte{9, 8, 7, 6, 5, 4, 3, 2, 1})
	srcConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	data := []byte{0xc0 ^ 0x3}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 0x9) // dest conn id length
	data = append(data, destConnID.Bytes()...)
	data = append(data, 0x4) // src conn id length
	data = append(data, srcConnID.Bytes()...)
	data = append(data, encodeVarInt(6)...)  // token length
	data = append(data, []byte("foobar")...) // token
	data = append(data, encodeVarInt(10)...) // length
	hdrLen := len(data)
	data = append(data, []byte{0, 0, 0xbe, 0xef}...) // packet number
	data = append(data, []byte("foobar")...)
	require.False(t, IsVersionNegotiationPacket(data))

	hdr, pdata, rest, err := ParsePacket(data)
	require.NoError(t, err)
	require.Equal(t, data, pdata)
	require.Equal(t, destConnID, hdr.DestConnectionID)
	require.Equal(t, srcConnID, hdr.SrcConnectionID)
	require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
	require.Equal(t, []byte("foobar"), hdr.Token)
	require.Equal(t, protocol.ByteCount(10), hdr.Length)
	require.Equal(t, protocol.Version1, hdr.Version)
	require.Empty(t, rest)
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumberLen4, extHdr.PacketNumberLen)
	require.Equal(t, protocol.PacketNumber(0xbeef), extHdr.PacketNumber)
	require.Equal(t, hdrLen, int(hdr.ParsedLen()))
	require.Equal(t, hdr.ParsedLen()+4, extHdr.ParsedLen())
}

func TestErrorIfReservedBitNotSet(t *testing.T) {
	data := []byte{
		0x80 | 0x2<<4,
		0x11,                   // connection ID lengths
		0xde, 0xca, 0xfb, 0xad, // dest conn ID
		0xde, 0xad, 0xbe, 0xef, // src conn ID
	}
	_, _, _, err := ParsePacket(data)
	require.EqualError(t, err, "not a QUIC packet")
}

func TestStopParsingWhenEncounteringUnsupportedVersion(t *testing.T) {
	data := []byte{
		0xc0,
		0xde, 0xad, 0xbe, 0xef,
		0x8,                                    // dest conn ID len
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, // dest conn ID
		0x8,                                    // src conn ID len
		0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, // src conn ID
		'f', 'o', 'o', 'b', 'a', 'r', // unspecified bytes
	}
	hdr, _, rest, err := ParsePacket(data)
	require.EqualError(t, err, ErrUnsupportedVersion.Error())
	require.Equal(t, protocol.Version(0xdeadbeef), hdr.Version)
	require.Equal(t, protocol.ParseConnectionID([]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}), hdr.DestConnectionID)
	require.Equal(t, protocol.ParseConnectionID([]byte{0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1}), hdr.SrcConnectionID)
	require.Empty(t, rest)
}

func TestParseLongHeaderWithoutDestinationConnectionID(t *testing.T) {
	data := []byte{0xc0 ^ 0x1<<4}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 0)                                 // dest conn ID len
	data = append(data, 4)                                 // src conn ID len
	data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // source connection ID
	data = append(data, encodeVarInt(0)...)                // length
	data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
	hdr, _, _, err := ParsePacket(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketType0RTT, hdr.Type)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}), hdr.SrcConnectionID)
	require.Zero(t, hdr.DestConnectionID)
}

func TestParseLongHeaderWithoutSourceConnectionID(t *testing.T) {
	data := []byte{0xc0 ^ 0x2<<4}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 10)                                       // dest conn ID len
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // dest connection ID
	data = append(data, 0)                                        // src conn ID len
	data = append(data, encodeVarInt(0)...)                       // length
	data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
	hdr, _, _, err := ParsePacket(data)
	require.NoError(t, err)
	require.Zero(t, hdr.SrcConnectionID)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), hdr.DestConnectionID)
}

func TestErrorOnTooLongDestinationConnectionID(t *testing.T) {
	data := []byte{0xc0 ^ 0x2<<4}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 21)                                                                                   // dest conn ID len
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}...) // dest connection ID
	data = append(data, 0x0)                                                                                  // src conn ID len
	data = append(data, encodeVarInt(0)...)                                                                   // length
	data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
	_, _, _, err := ParsePacket(data)
	require.EqualError(t, err, protocol.ErrInvalidConnectionIDLen.Error())
}

func TestParseLongHeaderWith2BytePacketNumber(t *testing.T) {
	data := []byte{0xc0 ^ 0x1}
	data = appendVersion(data, protocol.Version1) // version number
	data = append(data, []byte{0x0, 0x0}...)      // connection ID lengths
	data = append(data, encodeVarInt(0)...)       // token length
	data = append(data, encodeVarInt(0)...)       // length
	data = append(data, []byte{0x1, 0x23}...)

	hdr, _, _, err := ParsePacket(data)
	require.NoError(t, err)
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x123), extHdr.PacketNumber)
	require.Equal(t, protocol.PacketNumberLen2, extHdr.PacketNumberLen)
	require.Equal(t, len(data), int(extHdr.ParsedLen()))
}

func TestParseRetryPacket(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			var packetType byte
			if version == protocol.Version1 {
				packetType = 0b11 << 4
			} else {
				packetType = 0b00 << 4
			}
			data := []byte{0xc0 | packetType | (10 - 3) /* connection ID length */}
			data = appendVersion(data, version)
			data = append(data, []byte{6}...)                             // dest conn ID len
			data = append(data, []byte{6, 5, 4, 3, 2, 1}...)              // dest conn ID
			data = append(data, []byte{10}...)                            // src conn ID len
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...)  // token
			data = append(data, []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}...)
			hdr, pdata, rest, err := ParsePacket(data)
			require.NoError(t, err)
			require.Equal(t, protocol.PacketTypeRetry, hdr.Type)
			require.Equal(t, version, hdr.Version)
			require.Equal(t, protocol.ParseConnectionID([]byte{6, 5, 4, 3, 2, 1}), hdr.DestConnectionID)
			require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), hdr.SrcConnectionID)
			require.Equal(t, []byte("foobar"), hdr.Token)
			require.Equal(t, data, pdata)
			require.Empty(t, rest)
		})
	}
}

func TestRetryPacketTooShortForIntegrityTag(t *testing.T) {
	data := []byte{0xc0 | 0x3<<4 | (10 - 3) /* connection ID length */}
	data = appendVersion(data, protocol.Version1)
	data = append(data, []byte{0, 0}...)                         // conn ID lens
	data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...) // token
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...)
	// this results in a token length of 0
	_, _, _, err := ParsePacket(data)
	require.Equal(t, io.EOF, err)
}

func TestTokenLengthTooLarge(t *testing.T) {
	data := []byte{0xc0 ^ 0x1}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 0x0)                   // connection ID lengths
	data = append(data, encodeVarInt(4)...)    // token length: 4 bytes (1 byte too long)
	data = append(data, encodeVarInt(0x42)...) // length, 1 byte
	data = append(data, []byte{0x12, 0x34}...) // packet number

	_, _, _, err := ParsePacket(data)
	require.Equal(t, io.EOF, err)
}

func TestErrorOn5thOr6thBitSet(t *testing.T) {
	data := []byte{0xc0 | 0x2<<4 | 0x8 /* set the 5th bit */ | 0x1 /* 2 byte packet number */}
	data = appendVersion(data, protocol.Version1)
	data = append(data, []byte{0x0, 0x0}...)   // connection ID lengths
	data = append(data, encodeVarInt(2)...)    // length
	data = append(data, []byte{0x12, 0x34}...) // packet number
	hdr, _, _, err := ParsePacket(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeHandshake, hdr.Type)
	extHdr, err := hdr.ParseExtended(data)
	require.EqualError(t, err, ErrInvalidReservedBits.Error())
	require.NotNil(t, extHdr)
	require.Equal(t, protocol.PacketNumber(0x1234), extHdr.PacketNumber)
}

func TestHeaderEOF(t *testing.T) {
	data := []byte{0xc0 ^ 0x2<<4}
	data = appendVersion(data, protocol.Version1)
	data = append(data, 0x8)                                                       // dest conn ID len
	data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // dest conn ID
	data = append(data, 0x8)                                                       // src conn ID len
	data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // src conn ID
	for i := 1; i < len(data); i++ {
		_, _, _, err := ParsePacket(data[:i])
		require.Equal(t, io.EOF, err)
	}
}

func TestParseExtendedHeaderEOF(t *testing.T) {
	data := []byte{0xc0 | 0x2<<4 | 0x3}
	data = appendVersion(data, protocol.Version1)
	data = append(data, []byte{0x0, 0x0}...) // connection ID lengths
	data = append(data, encodeVarInt(0)...)  // length
	hdrLen := len(data)
	data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // packet number
	for i := hdrLen; i < len(data); i++ {
		b := data[:i]
		hdr, _, _, err := ParsePacket(b)
		require.NoError(t, err)
		_, err = hdr.ParseExtended(b)
		require.Equal(t, io.EOF, err)
	}
}

func TestParseRetryEOF(t *testing.T) {
	data := []byte{0xc0 ^ 0x3<<4}
	data = appendVersion(data, protocol.Version1)
	data = append(data, []byte{0x0, 0x0}...)                      // connection ID lengths
	data = append(data, 0xa)                                      // Orig Destination Connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
	hdrLen := len(data)
	for i := hdrLen; i < len(data); i++ {
		data = data[:i]
		hdr, _, _, err := ParsePacket(data)
		require.NoError(t, err)
		_, err = hdr.ParseExtended(data)
		require.Equal(t, io.EOF, err)
	}
}

func TestCoalescedPacketParsing(t *testing.T) {
	hdr := Header{
		Type:             protocol.PacketTypeInitial,
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		Length:           2 + 6,
		Version:          protocol.Version1,
	}
	b, err := (&ExtendedHeader{
		Header:          hdr,
		PacketNumber:    0x1337,
		PacketNumberLen: 2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	hdrRaw := append([]byte{}, b...)
	b = append(b, []byte("foobar")...) // payload of the first packet
	b = append(b, []byte("raboof")...) // second packet
	parsedHdr, data, rest, err := ParsePacket(b)
	require.NoError(t, err)
	require.Equal(t, hdr.Type, parsedHdr.Type)
	require.Equal(t, hdr.DestConnectionID, parsedHdr.DestConnectionID)
	require.Equal(t, append(hdrRaw, []byte("foobar")...), data)
	require.Equal(t, []byte("raboof"), rest)
}

func TestCoalescedPacketErrorOnTooSmallPacketNumber(t *testing.T) {
	b, err := (&ExtendedHeader{
		Header: Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			Length:           3,
			Version:          protocol.Version1,
		},
		PacketNumber:    0x1337,
		PacketNumberLen: 2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = ParsePacket(b)
	require.Error(t, err)
	require.Contains(t, err.Error(), "packet length (2 bytes) is smaller than the expected length (3 bytes)")
}

func TestCoalescedPacketErrorOnTooSmallPayload(t *testing.T) {
	b, err := (&ExtendedHeader{
		Header: Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			Length:           1000,
			Version:          protocol.Version1,
		},
		PacketNumber:    0x1337,
		PacketNumberLen: 2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	b = append(b, make([]byte, 500-2 /* for packet number length */)...)
	_, _, _, err = ParsePacket(b)
	require.EqualError(t, err, "packet length (500 bytes) is smaller than the expected length (1000 bytes)")
}

func TestDistinguishesLongAndShortHeaderPackets(t *testing.T) {
	require.False(t, IsLongHeaderPacket(0x40))
	require.True(t, IsLongHeaderPacket(0x80^0x40^0x12))
}

func TestPacketTypeForLogging(t *testing.T) {
	require.Equal(t, "Initial", (&Header{Type: protocol.PacketTypeInitial}).PacketType())
	require.Equal(t, "Handshake", (&Header{Type: protocol.PacketTypeHandshake}).PacketType())
}

func BenchmarkIs0RTTPacket(b *testing.B) {
	src := mrand.NewChaCha8([32]byte{'f', 'o', 'o', 'b', 'a', 'r'})
	random := mrand.New(src)
	packets := make([][]byte, 1024)
	for i := 0; i < len(packets); i++ {
		packets[i] = make([]byte, random.IntN(256))
		src.Read(packets[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Is0RTTPacket(packets[i%len(packets)])
	}
}

func BenchmarkParseInitial(b *testing.B) {
	b.Run("without token", func(b *testing.B) {
		benchmarkInitialPacketParsing(b, nil)
	})
	b.Run("with token", func(b *testing.B) {
		token := make([]byte, 32)
		rand.Read(token)
		benchmarkInitialPacketParsing(b, token)
	})
}

func benchmarkInitialPacketParsing(b *testing.B, token []byte) {
	hdr := Header{
		Type:             protocol.PacketTypeInitial,
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		SrcConnectionID:  protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
		Length:           1000,
		Token:            token,
		Version:          protocol.Version1,
	}
	data, err := (&ExtendedHeader{
		Header:          hdr,
		PacketNumber:    0x1337,
		PacketNumberLen: 4,
	}).Append(nil, protocol.Version1)
	if err != nil {
		b.Fatal(err)
	}
	data = append(data, make([]byte, 1000)...)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h, _, _, err := ParsePacket(data)
		if err != nil {
			b.Fatal(err)
		}
		if h.Type != hdr.Type || h.DestConnectionID != hdr.DestConnectionID || h.SrcConnectionID != hdr.SrcConnectionID ||
			!bytes.Equal(h.Token, hdr.Token) {
			b.Fatalf("headers don't match: %v vs %v", h, hdr)
		}
	}
}

func BenchmarkParseRetry(b *testing.B) {
	token := make([]byte, 64)
	rand.Read(token)
	hdr := &ExtendedHeader{
		Header: Header{
			Type:             protocol.PacketTypeRetry,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
			DestConnectionID: protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
			Token:            token,
			Version:          protocol.Version1,
		},
	}
	data, err := hdr.Append(nil, hdr.Version)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h, _, _, err := ParsePacket(data)
		if err != nil {
			b.Fatal(err)
		}
		if h.Type != hdr.Type || h.DestConnectionID != hdr.DestConnectionID || h.SrcConnectionID != hdr.SrcConnectionID ||
			!bytes.Equal(h.Token, hdr.Token[:len(hdr.Token)-16]) {
			b.Fatalf("headers don't match: %#v vs %#v", h, hdr)
		}
	}
}

func BenchmarkArbitraryHeaderParsing(b *testing.B) {
	b.Run("dest 8/ src 10", func(b *testing.B) { benchmarkArbitraryHeaderParsing(b, 8, 10) })
	b.Run("dest 20 / src 20", func(b *testing.B) { benchmarkArbitraryHeaderParsing(b, 20, 20) })
	b.Run("dest 100 / src 150", func(b *testing.B) { benchmarkArbitraryHeaderParsing(b, 100, 150) })
}

func benchmarkArbitraryHeaderParsing(b *testing.B, destLen, srcLen int) {
	destConnID := make([]byte, destLen)
	rand.Read(destConnID)
	srcConnID := make([]byte, srcLen)
	rand.Read(srcConnID)
	buf := []byte{0x80, 1, 2, 3, 4}
	buf = append(buf, uint8(destLen))
	buf = append(buf, destConnID...)
	buf = append(buf, uint8(srcLen))
	buf = append(buf, srcConnID...)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parsed, d, s, err := ParseArbitraryLenConnectionIDs(buf)
		if err != nil {
			b.Fatal(err)
		}
		if parsed != len(buf) {
			b.Fatal("expected to parse entire slice")
		}
		if !bytes.Equal(destConnID, d.Bytes()) {
			b.Fatalf("destination connection IDs don't match: %v vs %v", destConnID, d.Bytes())
		}
		if !bytes.Equal(srcConnID, s.Bytes()) {
			b.Fatalf("source connection IDs don't match: %v vs %v", srcConnID, s.Bytes())
		}
	}
}
