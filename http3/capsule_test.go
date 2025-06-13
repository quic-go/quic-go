package http3

import (
	"bytes"
	"io"
	"testing"

	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestCapsuleParsing(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)

	ct, r, err := ParseCapsule(bytes.NewReader(b))
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	buf := make([]byte, 3)
	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), buf)
	data, err := io.ReadAll(r) // reads until EOF
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)

	// test EOF vs ErrUnexpectedEOF
	for i := range b {
		ct, r, err := ParseCapsule(bytes.NewReader(b[:i]))
		if err != nil {
			if i == 0 {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
			continue
		}
		require.Equal(t, CapsuleType(1337), ct)
		_, err = io.ReadAll(r)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}

func TestCapsuleWriting(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteCapsule(&buf, 1337, []byte("foobar")))

	ct, r, err := ParseCapsule(&buf)
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	val, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(val))
}
