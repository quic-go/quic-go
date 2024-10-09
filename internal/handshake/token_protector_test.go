package handshake

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenProtectorEncodeAndDecode(t *testing.T) {
	var key TokenProtectorKey
	rand.Read(key[:])
	tp := newTokenProtector(key)

	token, err := tp.NewToken([]byte("foobar"))
	require.NoError(t, err)
	require.NotContains(t, string(token), "foobar")

	decoded, err := tp.DecodeToken(token)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), decoded)
}

func TestTokenProtectorDifferentKeys(t *testing.T) {
	var key1, key2 TokenProtectorKey
	rand.Read(key1[:])
	rand.Read(key2[:])
	tp1 := newTokenProtector(key1)
	tp2 := newTokenProtector(key2)

	t1, err := tp1.NewToken([]byte("foo"))
	require.NoError(t, err)
	t2, err := tp2.NewToken([]byte("foo"))
	require.NoError(t, err)

	_, err = tp1.DecodeToken(t1)
	require.NoError(t, err)
	_, err = tp1.DecodeToken(t2)
	require.Error(t, err)

	tp3 := newTokenProtector(key1)
	_, err = tp3.DecodeToken(t1)
	require.NoError(t, err)
	_, err = tp3.DecodeToken(t2)
	require.Error(t, err)
}

func TestTokenProtectorInvalidTokens(t *testing.T) {
	var key TokenProtectorKey
	rand.Read(key[:])
	tp := newTokenProtector(key)

	token, err := tp.NewToken([]byte("foobar"))
	require.NoError(t, err)
	_, err = tp.DecodeToken(token[1:])
	require.Error(t, err)
	require.Contains(t, err.Error(), "message authentication failed")
}

func TestTokenProtectorTooShortTokens(t *testing.T) {
	var key TokenProtectorKey
	rand.Read(key[:])
	tp := newTokenProtector(key)

	_, err := tp.DecodeToken([]byte("foobar"))
	require.EqualError(t, err, "token too short: 6")
}
