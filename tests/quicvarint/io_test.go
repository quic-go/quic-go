package quicvarint

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type nopReader struct{}

func (r *nopReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

var _ io.Reader = &nopReader{}

type nopWriter struct{}

func (r *nopWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrShortBuffer
}

// eofReader is a reader that returns data and the io.EOF at the same time in the last Read call
type eofReader struct {
	Data []byte
	pos  int
}

func (r *eofReader) Read(b []byte) (int, error) {
	n := copy(b, r.Data[r.pos:])
	r.pos += n
	if r.pos >= len(r.Data) {
		return n, io.EOF
	}
	return n, nil
}

var _ io.Writer = &nopWriter{}

func TestReaderPassesThroughUnchanged(t *testing.T) {
	b := bytes.NewReader([]byte{0})
	r := NewReader(b)
	require.Equal(t, b, r)
}

func TestReaderWrapsIOReader(t *testing.T) {
	n := &nopReader{}
	r := NewReader(n)
	require.NotEqual(t, n, r)
}

func TestReaderFailure(t *testing.T) {
	r := NewReader(&nopReader{})
	val, err := r.ReadByte()
	require.Equal(t, io.ErrUnexpectedEOF, err)
	require.Equal(t, byte(0), val)
}

func TestReaderHandlesEOF(t *testing.T) {
	// test that the eofReader behaves as we expect
	r := &eofReader{Data: []byte("foobar")}
	b := make([]byte, 3)
	n, err := r.Read(b)
	require.Equal(t, 3, n)
	require.NoError(t, err)
	require.Equal(t, "foo", string(b))
	n, err = r.Read(b)
	require.Equal(t, 3, n)
	require.Equal(t, io.EOF, err)
	require.Equal(t, "bar", string(b))
	n, err = r.Read(b)
	require.Equal(t, io.EOF, err)
	require.Zero(t, n)

	// now test using it to read varints
	reader := NewReader(&eofReader{Data: Append(nil, 1337)})
	n2, err := Read(reader)
	require.NoError(t, err)
	require.EqualValues(t, 1337, n2)
}

func TestWriterPassesThroughUnchanged(t *testing.T) {
	b := &bytes.Buffer{}
	w := NewWriter(b)
	require.Equal(t, b, w)
}

func TestWriterWrapsIOWriter(t *testing.T) {
	n := &nopWriter{}
	w := NewWriter(n)
	require.NotEqual(t, n, w)
}

func TestWriterFailure(t *testing.T) {
	w := NewWriter(&nopWriter{})
	err := w.WriteByte(0)
	require.Equal(t, io.ErrShortBuffer, err)
}
