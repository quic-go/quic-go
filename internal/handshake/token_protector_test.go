package handshake

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenProtectorEncodeAndDecode(t *testing.T) {
	var key TokenProtectorKey
	rand.Read(key[:])
	tp := newTokenProtector(key)

	for name, data := range map[string][]byte{
		"empty": nil,
		"short": []byte("foobar"),
		"long":  bytes.Repeat([]byte("foobar"), 1024),
	} {
		t.Run(name, func(t *testing.T) {
			token, err := tp.NewToken(data)
			require.NoError(t, err)
			if len(data) > 0 {
				require.NotContains(t, string(token), string(data))
			}

			decoded, err := tp.DecodeToken(token)
			require.NoError(t, err)
			require.Equal(t, string(data), string(decoded))
		})
	}
}

func BenchmarkTokenProtectorNewToken(b *testing.B) {
	b.ReportAllocs()
	tp := newTokenProtector(TokenProtectorKey{})
	data := make([]byte, 32)
	for b.Loop() {
		if _, err := tp.NewToken(data); err != nil {
			b.Fatal(err)
		}
	}
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
	require.ErrorContains(t, err, "message authentication failed")
}

func TestTokenProtectorTooShortTokens(t *testing.T) {
	var key TokenProtectorKey
	rand.Read(key[:])
	tp := newTokenProtector(key)

	_, err := tp.DecodeToken([]byte("foobar"))
	require.EqualError(t, err, "token too short: 6")

	_, err = tp.DecodeToken(make([]byte, tokenSaltSize))
	require.EqualError(t, err, "token too short: 32")
}
