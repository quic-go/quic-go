package protocol

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRandomConnectionIDs(t *testing.T) {
	c1, err := GenerateConnectionID(8)
	require.NoError(t, err)
	require.NotZero(t, c1)
	require.Equal(t, 8, c1.Len())
	c2, err := GenerateConnectionID(8)
	require.NoError(t, err)
	require.NotEqual(t, c1, c2)
	require.Equal(t, 8, c2.Len())
}

func TestGenerateRandomLengthDestinationConnectionIDs(t *testing.T) {
	var has8ByteConnID, has20ByteConnID bool
	for i := 0; i < 1000; i++ {
		c, err := GenerateConnectionIDForInitial()
		require.NoError(t, err)
		require.GreaterOrEqual(t, c.Len(), 8)
		require.LessOrEqual(t, c.Len(), 20)
		if c.Len() == 8 {
			has8ByteConnID = true
		}
		if c.Len() == 20 {
			has20ByteConnID = true
		}
	}
	require.True(t, has8ByteConnID)
	require.True(t, has20ByteConnID)
}

func TestConnectionID(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xde, 0xad, 0xbe, 0xef, 0x42})
	c, err := ReadConnectionID(buf, 5)
	require.NoError(t, err)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef, 0x42}, c.Bytes())
	require.Equal(t, 5, c.Len())
	require.Equal(t, "deadbeef42", c.String())

	// too few bytes
	_, err = ReadConnectionID(buf, 10)
	require.Equal(t, io.EOF, err)

	// zero length
	c2, err := ReadConnectionID(buf, 0)
	require.NoError(t, err)
	require.Zero(t, c2.Len())

	// connection ID can have a length of a maximum of 20 bytes
	buf2 := bytes.NewBuffer(make([]byte, 21))
	_, err = ReadConnectionID(buf2, 21)
	require.Equal(t, ErrInvalidConnectionIDLen, err)
}

func TestConnectionIDZeroValue(t *testing.T) {
	var c ConnectionID
	require.Zero(t, c.Len())
	require.Empty(t, c.Bytes())
	require.Equal(t, "(empty)", (ConnectionID{}).String())
}

// The string representation of a connection ID is used in qlog, so it should be fast.
func BenchmarkConnectionIDStringer(b *testing.B) {
	c := ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0x42})
	b.ReportAllocs()
	for b.Loop() {
		_ = c.String()
	}
}

func TestArbitraryLenConnectionID(t *testing.T) {
	b := make([]byte, 42)
	rand.Read(b)
	c := ArbitraryLenConnectionID(b)
	require.Equal(t, b, c.Bytes())
	require.Equal(t, 42, c.Len())
}

func TestArbitraryLenConnectionIDStringer(t *testing.T) {
	require.Equal(t, "(empty)", (ArbitraryLenConnectionID{}).String())
	c := ArbitraryLenConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0x42})
	require.Equal(t, "deadbeef42", c.String())
}
