package quicvarint

import (
	"bytes"
	"fmt"
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

// Regression test: empty reads were being converted to successful
// reads of a zero value.
func TestReaderHandlesEmptyRead(t *testing.T) {
	r, w := io.Pipe()

	go func() {
		// io.Pipe turns empty writes into empty reads.
		w.Write(nil)
		w.Close()
	}()

	br := NewReader(r)
	_, err := Read(br)
	require.ErrorIs(t, err, io.EOF)
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

type bufPeeker []byte

func (p bufPeeker) Peek(b []byte) (int, error) {
	if len(p) < len(b) {
		return copy(b, p), io.ErrUnexpectedEOF
	}
	return copy(b, p), nil
}

func TestPeek(t *testing.T) {
	for _, c := range []bufPeeker{
		{0b00011001},                   // 1-byte
		{0b01111011, 0xbd},             // 2-byte
		{0b10011101, 0x7f, 0x3e, 0x7d}, // 4-byte
		{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, // 8-byte
	} {
		t.Run(fmt.Sprintf("%d bytes", len(c)), func(t *testing.T) {
			peekVal, err := Peek(append(c, []byte("foobar")...)) // append some data, which doesn't matter
			require.NoError(t, err)
			parseVal, _, err := Parse(c)
			require.NoError(t, err)
			require.Equal(t, parseVal, peekVal)
		})
	}
}

func TestPeekErrors(t *testing.T) {
	errorCases := []struct {
		name  string
		input bufPeeker
	}{
		{"empty input", bufPeeker{}},
		{"2-byte, missing 1", bufPeeker{0b01000001}},
		{"4-byte, missing 1", bufPeeker{0b10000000, 0, 0}},
		{"8-byte, missing 1", bufPeeker{0b11000000, 0, 0, 0, 0, 0, 0}},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Peek(tc.input)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}
