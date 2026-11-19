package handshake

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func newTokenGenerator(t *testing.T) *TokenGenerator {
	var key TokenProtectorKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	return NewTokenGenerator(key)
}

func TestTokenGeneratorNilTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)
	nilToken, err := tokenGen.DecodeToken(nil)
	require.NoError(t, err)
	require.Nil(t, nilToken)
}

func TestTokenGeneratorValidToken(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	connID1 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	connID2 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	tokenEnc, err := tokenGen.NewRetryToken(addr, connID1, connID2, protocol.Version2)
	require.NoError(t, err)
	decodedToken, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, decodedToken.IsRetryToken)
	require.True(t, decodedToken.ValidateRemoteAddr(addr))
	require.False(t, decodedToken.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: 1337}))
	require.WithinDuration(t, time.Now(), decodedToken.SentTime, 100*time.Millisecond)
	require.Equal(t, connID1, decodedToken.OriginalDestConnectionID)
	require.Equal(t, connID2, decodedToken.RetrySrcConnectionID)
	require.Equal(t, protocol.Version2, decodedToken.Version)

	tokenEnc, err = tokenGen.NewToken(addr, 1337*time.Microsecond, protocol.Version1)
	require.NoError(t, err)
	decodedToken, err = tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.False(t, decodedToken.IsRetryToken)
	require.True(t, decodedToken.ValidateRemoteAddr(addr))
	require.WithinDuration(t, time.Now(), decodedToken.SentTime, 100*time.Millisecond)
	require.Equal(t, 1337*time.Microsecond, decodedToken.RTT)
	require.Equal(t, protocol.Version1, decodedToken.Version)
}

func TestTokenGeneratorRejectsInvalidTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	_, err := tokenGen.DecodeToken([]byte("invalid token"))
	require.ErrorContains(t, err, "too short")
}

func TestTokenGeneratorDecodingFailed(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	invalidToken, err := tokenGen.tokenProtector.NewToken([]byte("foobarfoobarfoobar"))
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(invalidToken)
	require.EqualError(t, err, "unknown token type: 102")
}

func TestTokenGeneratorMalformedTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	enc, err := tokenGen.NewRetryToken(addr, connID, connID, protocol.Version1)
	require.NoError(t, err)
	data, err := tokenGen.tokenProtector.DecodeToken(enc)
	require.NoError(t, err)

	for i := range data {
		enc, err := tokenGen.tokenProtector.NewToken(data[:i])
		require.NoError(t, err)
		_, err = tokenGen.DecodeToken(enc)
		require.Error(t, err)
	}

	enc, err = tokenGen.tokenProtector.NewToken(append(data, []byte("rest")...))
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(enc)
	require.EqualError(t, err, "rest when unpacking token: 4")

	b := newTokenPlaintext(tokenTypeRetry, addr, protocol.Version1, 0)
	b = appendLengthPrefixed(b, make([]byte, protocol.MaxConnIDLen+1))
	enc, err = tokenGen.tokenProtector.NewToken(appendLengthPrefixed(b, nil))
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(enc)
	require.EqualError(t, err, "invalid connection ID length: 21")
}

func TestTokenGeneratorIPv6(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	addresses := []string{
		"2001:db8::68",
		"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
		"2001::1",
		"ff01:0:0:0:0:0:0:2",
	}
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		require.NotNil(t, ip)
		raddr := &net.UDPAddr{IP: ip, Port: 1337}
		tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{}, protocol.Version1)
		require.NoError(t, err)
		token, err := tokenGen.DecodeToken(tokenEnc)
		require.NoError(t, err)
		require.True(t, token.ValidateRemoteAddr(raddr))
		require.WithinDuration(t, time.Now(), token.SentTime, 100*time.Millisecond)
	}
}

func TestTokenGeneratorNonUDPAddr(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
	tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{}, protocol.Version1)
	require.NoError(t, err)
	token, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, token.ValidateRemoteAddr(raddr))
	require.False(t, token.ValidateRemoteAddr(&net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1338}))
	require.WithinDuration(t, time.Now(), token.SentTime, 100*time.Millisecond)
}

func BenchmarkTokenGeneratorDecodeToken(b *testing.B) {
	b.ReportAllocs()

	var key TokenProtectorKey
	_, err := rand.Read(key[:])
	require.NoError(b, err)
	tokenGen := NewTokenGenerator(key)
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
	connID1 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	connID2 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	tokenEnc, err := tokenGen.NewRetryToken(addr, connID1, connID2, protocol.Version1)
	require.NoError(b, err)

	for b.Loop() {
		if _, err := tokenGen.DecodeToken(tokenEnc); err != nil {
			b.Fatal(err)
		}
	}
}
