package wire

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseVersionNegotiationPacket(t *testing.T) {
	randConnID := func(l int) protocol.ArbitraryLenConnectionID {
		b := make(protocol.ArbitraryLenConnectionID, l)
		_, err := rand.Read(b)
		require.NoError(t, err)
		return b
	}

	srcConnID := randConnID(mrand.IntN(255) + 1)
	destConnID := randConnID(mrand.IntN(255) + 1)
	versions := []protocol.Version{0x22334455, 0x33445566}
	data := []byte{0x80, 0, 0, 0, 0}
	data = append(data, uint8(len(destConnID)))
	data = append(data, destConnID...)
	data = append(data, uint8(len(srcConnID)))
	data = append(data, srcConnID...)
	for _, v := range versions {
		data = append(data, []byte{0, 0, 0, 0}...)
		binary.BigEndian.PutUint32(data[len(data)-4:], uint32(v))
	}
	require.True(t, IsVersionNegotiationPacket(data))
	dest, src, supportedVersions, err := ParseVersionNegotiationPacket(data)
	require.NoError(t, err)
	require.Equal(t, destConnID, dest)
	require.Equal(t, srcConnID, src)
	require.Equal(t, versions, supportedVersions)
}

func TestParseVersionNegotiationPacketWithInvalidLength(t *testing.T) {
	connID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	versions := []protocol.Version{0x22334455, 0x33445566}
	data := ComposeVersionNegotiation(connID, connID, versions)
	_, _, _, err := ParseVersionNegotiationPacket(data[:len(data)-2])
	require.EqualError(t, err, "Version Negotiation packet has a version list with an invalid length")
}

func TestParseVersionNegotiationPacketEmptyVersions(t *testing.T) {
	connID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	versions := []protocol.Version{0x22334455}
	data := ComposeVersionNegotiation(connID, connID, versions)
	// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
	data = data[:len(data)-8]
	_, _, _, err := ParseVersionNegotiationPacket(data)
	require.EqualError(t, err, "Version Negotiation packet has empty version list")
}

func TestComposeVersionNegotiationWithReservedVersion(t *testing.T) {
	srcConnID := protocol.ArbitraryLenConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
	destConnID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	versions := []protocol.Version{1001, 1003}
	data := ComposeVersionNegotiation(destConnID, srcConnID, versions)
	require.True(t, IsLongHeaderPacket(data[0]))
	require.NotZero(t, data[0]&0x40)
	v, err := ParseVersion(data)
	require.NoError(t, err)
	require.Zero(t, v)
	dest, src, supportedVersions, err := ParseVersionNegotiationPacket(data)
	require.NoError(t, err)
	require.Equal(t, destConnID, dest)
	require.Equal(t, srcConnID, src)
	// the supported versions should include one reserved version number
	require.Len(t, supportedVersions, len(versions)+1)
	for _, v := range versions {
		require.Contains(t, supportedVersions, v)
	}
	var reservedVersion protocol.Version
versionLoop:
	for _, ver := range supportedVersions {
		for _, v := range versions {
			if v == ver {
				continue versionLoop
			}
		}
		reservedVersion = ver
	}
	require.NotZero(t, reservedVersion)
	require.True(t, reservedVersion&0x0f0f0f0f == 0x0a0a0a0a) // check that it's a greased version number
}

func BenchmarkComposeVersionNegotiationPacket(b *testing.B) {
	b.ReportAllocs()
	supportedVersions := []protocol.Version{protocol.Version2, protocol.Version1, 0x1337}
	destConnID := protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xa, 0xb, 0xc, 0xd}
	srcConnID := protocol.ArbitraryLenConnectionID{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	for i := 0; i < b.N; i++ {
		ComposeVersionNegotiation(destConnID, srcConnID, supportedVersions)
	}
}
