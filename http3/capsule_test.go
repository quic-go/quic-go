package http3

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestCapsuleParsing(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)

	p := NewCapsuleParser(bytes.NewReader(b))
	ct, r, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	require.Equal(t, int64(6), r.Remaining())
	buf := make([]byte, 3)
	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), buf)
	require.Equal(t, int64(3), r.Remaining())
	data, err := io.ReadAll(r) // reads until EOF
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
	require.Zero(t, r.Remaining())
	_, _, err = p.Next()
	require.ErrorIs(t, err, io.EOF)
}

func TestEmptyCapsuleParsing(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	b = quicvarint.Append(b, 0)
	// Capsule content is empty.

	p := NewCapsuleParser(bytes.NewReader(b))
	ct, r, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	data, err := io.ReadAll(r) // reads until EOF
	require.NoError(t, err)
	require.Equal(t, []byte{}, data)
}

// test EOF vs ErrUnexpectedEOF
func TestCapsuleTruncation(t *testing.T) {
	t.Run("with content", func(t *testing.T) {
		b := quicvarint.Append(nil, 1337)
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)
		testCapsuleTruncation(t, b)
	})

	t.Run("empty content", func(t *testing.T) {
		b := quicvarint.Append(nil, 1337)
		b = quicvarint.Append(b, 0)
		testCapsuleTruncation(t, b)
	})
}

func testCapsuleTruncation(t *testing.T, b []byte) {
	for i := range b {
		p := NewCapsuleParser(bytes.NewReader(b[:i]))
		ct, r, err := p.Next()
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

func TestCapsuleParserRequiresConsumption(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteCapsule(&buf, 1, []byte("first")))
	require.NoError(t, WriteCapsule(&buf, 2, []byte("second")))

	p := NewCapsuleParser(&buf)
	_, r, err := p.Next()
	require.NoError(t, err)
	_, err = r.ReadByte()
	require.NoError(t, err)
	_, _, err = p.Next()
	require.ErrorIs(t, err, errCapsuleNotConsumed)

	require.NoError(t, r.Discard())
	ct, next, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(2), ct)
	data, err := io.ReadAll(next)
	require.NoError(t, err)
	require.Equal(t, []byte("second"), data)

	_, err = r.ReadByte()
	require.ErrorIs(t, err, errReaderInvalid)
	_, err = r.Read(make([]byte, 1))
	require.ErrorIs(t, err, errReaderInvalid)
	require.ErrorIs(t, err, errReaderInvalid)
}

func TestCopiedCapsuleReadersShareProgress(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteCapsule(&buf, 1, []byte("foobar")))

	p := NewCapsuleParser(&buf)
	_, r, err := p.Next()
	require.NoError(t, err)
	r2 := r

	b, err := r.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte('f'), b)
	require.Equal(t, int64(5), r2.Remaining())
	data, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.Equal(t, []byte("oobar"), data)
	require.Zero(t, r.Remaining())
}

func TestCapsuleWriting(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteCapsule(&buf, 1337, []byte("foobar")))

	p := NewCapsuleParser(&buf)
	ct, r, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	val, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(val))
}

func TestCapsuleWriteEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteCapsule(&buf, 1337, []byte{}))
	require.NoError(t, WriteCapsule(&buf, 1337, []byte{}))

	p := NewCapsuleParser(&buf)
	ct, r, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	val, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, val)

	ct, r, err = p.Next()
	require.NoError(t, err)
	require.Equal(t, CapsuleType(1337), ct)
	val, err = io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, val)
}
