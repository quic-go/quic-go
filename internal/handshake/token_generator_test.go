package handshake

import (
	"crypto/rand"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/Noooste/quic-go/internal/protocol"

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
	tokenEnc, err := tokenGen.NewRetryToken(addr, connID1, connID2)
	require.NoError(t, err)
	decodedToken, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, decodedToken.ValidateRemoteAddr(addr))
	require.False(t, decodedToken.ValidateRemoteAddr(&net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: 1337}))
	require.WithinDuration(t, time.Now(), decodedToken.SentTime, 100*time.Millisecond)
	require.Equal(t, connID1, decodedToken.OriginalDestConnectionID)
	require.Equal(t, connID2, decodedToken.RetrySrcConnectionID)
}

func TestTokenGeneratorRejectsInvalidTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	_, err := tokenGen.DecodeToken([]byte("invalid token"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestTokenGeneratorDecodingFailed(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	invalidToken, err := tokenGen.tokenProtector.NewToken([]byte("foobar"))
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(invalidToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "asn1")
}

func TestTokenGeneratorAdditionalPayload(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	tok, err := asn1.Marshal(token{RemoteAddr: []byte("foobar")})
	require.NoError(t, err)
	tok = append(tok, []byte("rest")...)
	enc, err := tokenGen.tokenProtector.NewToken(tok)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(enc)
	require.EqualError(t, err, "rest when unpacking token: 4")
}

func TestTokenGeneratorEmptyTokens(t *testing.T) {
	tokenGen := newTokenGenerator(t)

	emptyTok, err := asn1.Marshal(token{RemoteAddr: []byte("")})
	require.NoError(t, err)
	emptyEnc, err := tokenGen.tokenProtector.NewToken(emptyTok)
	require.NoError(t, err)
	_, err = tokenGen.DecodeToken(emptyEnc)
	require.NoError(t, err)
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
		tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{})
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
	tokenEnc, err := tokenGen.NewRetryToken(raddr, protocol.ConnectionID{}, protocol.ConnectionID{})
	require.NoError(t, err)
	token, err := tokenGen.DecodeToken(tokenEnc)
	require.NoError(t, err)
	require.True(t, token.ValidateRemoteAddr(raddr))
	require.False(t, token.ValidateRemoteAddr(&net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1338}))
	require.WithinDuration(t, time.Now(), token.SentTime, 100*time.Millisecond)
}
