package quicvarint

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimits(t *testing.T) {
	require.Equal(t, 0, Min)
	require.Equal(t, uint64(1<<62-1), uint64(Max))
}

func TestRead(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"1 byte", []byte{0b00011001}, 25},
		{"2 byte", []byte{0b01111011, 0xbd}, 15293},
		{"4 byte", []byte{0b10011101, 0x7f, 0x3e, 0x7d}, 494878333},
		{"8 byte", []byte{0b11000010, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
		{"too long", []byte{0b01000000, 0x25}, 37},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.NewReader(tt.input)
			val, err := Read(b)
			require.NoError(t, err)
			require.Equal(t, tt.expected, val)
			require.Zero(t, b.Len())
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedValue uint64
		expectedLen   int
	}{
		{"1 byte", []byte{0b00011001}, 25, 1},
		{"2 byte", []byte{0b01111011, 0xbd}, 15293, 2},
		{"4 byte", []byte{0b10011101, 0x7f, 0x3e, 0x7d}, 494878333, 4},
		{"8 byte", []byte{0b11000010, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, l, err := Parse(tt.input)
			require.Equal(t, tt.expectedValue, value)
			require.Equal(t, tt.expectedLen, l)
			require.Nil(t, err)
		})
	}
}

func TestParsingFailures(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectedErr error
	}{
		{
			name:        "empty slice",
			input:       []byte{},
			expectedErr: io.EOF,
		},
		{
			name:        "2-byte encoding: not enough bytes",
			input:       []byte{0b01000001},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "4-byte encoding: not enough bytes",
			input:       []byte{0b10000000, 0x0, 0x0},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "8-byte encoding: not enough bytes",
			input:       []byte{0b11000000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			expectedErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, l, err := Parse(tt.input)
			require.Equal(t, uint64(0), value)
			require.Equal(t, 0, l)
			require.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestVarintEncoding(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		expected []byte
	}{
		{"1 byte number", 37, []byte{0x25}},
		{"maximum 1 byte number", maxVarInt1, []byte{0b00111111}},
		{"minimum 2 byte number", maxVarInt1 + 1, []byte{0x40, maxVarInt1 + 1}},
		{"2 byte number", 15293, []byte{0b01000000 ^ 0x3b, 0xbd}},
		{"maximum 2 byte number", maxVarInt2, []byte{0b01111111, 0xff}},
		{"minimum 4 byte number", maxVarInt2 + 1, []byte{0b10000000, 0, 0x40, 0}},
		{"4 byte number", 494878333, []byte{0b10000000 ^ 0x1d, 0x7f, 0x3e, 0x7d}},
		{"maximum 4 byte number", maxVarInt4, []byte{0b10111111, 0xff, 0xff, 0xff}},
		{"minimum 8 byte number", maxVarInt4 + 1, []byte{0b11000000, 0, 0, 0, 0x40, 0, 0, 0}},
		{"8 byte number", 151288809941952652, []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}},
		{"maximum 8 byte number", maxVarInt8, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, Append(nil, tt.value))
		})
	}

	t.Run("panics when given a too large number (> 62 bit)", func(t *testing.T) {
		require.PanicsWithError(t,
			fmt.Sprintf("value doesn't fit into 62 bits: %d", maxVarInt8+1),
			func() { Append(nil, maxVarInt8+1) },
		)
	})
}

func TestAppendWithLen(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		length   int
		expected []byte
	}{
		{"1-byte number in minimal encoding", 37, 1, []byte{0x25}},
		{"1-byte number in 2 bytes", 37, 2, []byte{0b01000000, 0x25}},
		{"1-byte number in 4 bytes", 37, 4, []byte{0b10000000, 0, 0, 0x25}},
		{"1-byte number in 8 bytes", 37, 8, []byte{0b11000000, 0, 0, 0, 0, 0, 0, 0x25}},
		{"2-byte number in 4 bytes", 15293, 4, []byte{0b10000000, 0, 0x3b, 0xbd}},
		{"4-byte number in 8 bytes", 494878333, 8, []byte{0b11000000, 0, 0, 0, 0x1d, 0x7f, 0x3e, 0x7d}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := AppendWithLen(nil, tt.value, tt.length)
			require.Equal(t, tt.expected, b)

			if tt.length > 1 {
				v, n, err := Parse(b)
				require.NoError(t, err)
				require.Equal(t, tt.length, n)
				require.Equal(t, tt.value, v)
			}
		})
	}
}

func TestAppendWithLenFailures(t *testing.T) {
	tests := []struct {
		name   string
		value  uint64
		length int
	}{
		{"invalid length", 25, 3},
		{"too short for 2 bytes", maxVarInt1 + 1, 1},
		{"too short for 4 bytes", maxVarInt2 + 1, 2},
		{"too short for 8 bytes", maxVarInt4 + 1, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Panics(t, func() {
				AppendWithLen(nil, tt.value, tt.length)
			})
		})
	}
}

func TestLen(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected int
	}{
		{"zero", 0, 1},
		{"max 1 byte", maxVarInt1, 1},
		{"min 2 bytes", maxVarInt1 + 1, 2},
		{"max 2 bytes", maxVarInt2, 2},
		{"min 4 bytes", maxVarInt2 + 1, 4},
		{"max 4 bytes", maxVarInt4, 4},
		{"min 8 bytes", maxVarInt4 + 1, 8},
		{"max 8 bytes", maxVarInt8, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, Len(tt.input))
		})
	}

	t.Run("panics on too large number", func(t *testing.T) {
		require.PanicsWithError(t,
			fmt.Sprintf("value doesn't fit into 62 bits: %d", maxVarInt8+1),
			func() { Len(maxVarInt8 + 1) },
		)
	})
}

type benchmarkValue struct {
	b []byte
	v uint64
}

func randomValues(maxValue uint64) []benchmarkValue {
	r := rand.New(rand.NewPCG(13, 37))

	const num = 1025
	bv := make([]benchmarkValue, num)
	for i := range num {
		v := r.Uint64() % maxValue
		bv[i].v = v
		bv[i].b = Append([]byte{}, v)
	}
	return bv
}

// using a reader that is also an io.ByteReader
func BenchmarkReadBytesReader(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt1), false) })
	b.Run("2-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt2), false) })
	b.Run("4-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt4), false) })
	b.Run("8-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt8), false) })
}

// using a reader that is not an io.ByteReader
func BenchmarkReadSimpleReader(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt1), true) })
	b.Run("2-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt2), true) })
	b.Run("4-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt4), true) })
	b.Run("8-byte", func(b *testing.B) { benchmarkRead(b, randomValues(maxVarInt8), true) })
}

// simpleReader satisfies io.Reader, but not io.ByteReader
// This means that NewReader will need to wrap the reader.
type simpleReader struct {
	io.Reader
}

func benchmarkRead(b *testing.B, inputs []benchmarkValue, wrapBytesReader bool) {
	r := bytes.NewReader([]byte{})
	var vr Reader
	if wrapBytesReader {
		vr = NewReader(&simpleReader{r})
	} else {
		vr = NewReader(r)
	}

	var i int
	for b.Loop() {
		index := i % len(inputs)
		i++
		r.Reset(inputs[index].b)
		val, err := Read(vr)
		if err != nil {
			b.Fatal(err)
		}
		if val != inputs[index].v {
			b.Fatalf("expected %d, got %d", inputs[index].v, val)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkParse(b, randomValues(maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkParse(b, randomValues(maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkParse(b, randomValues(maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkParse(b, randomValues(maxVarInt8)) })
}

func benchmarkParse(b *testing.B, inputs []benchmarkValue) {
	var i int
	for b.Loop() {
		index := i % len(inputs)
		i++
		val, n, err := Parse(inputs[index].b)
		if err != nil {
			b.Fatal(err)
		}
		if n != len(inputs[index].b) {
			b.Fatalf("expected to consume %d bytes, consumed %d", len(inputs[i].b), n)
		}
		if val != inputs[index].v {
			b.Fatalf("expected %d, got %d", inputs[index].v, val)
		}
	}
}

func BenchmarkAppend(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(maxVarInt8)) })
}

func benchmarkAppend(b *testing.B, inputs []benchmarkValue) {
	buf := make([]byte, 8)

	var i int
	for b.Loop() {
		buf = buf[:0]
		index := i % len(inputs)
		i++
		buf = Append(buf, inputs[index].v)

		if !bytes.Equal(buf, inputs[index].b) {
			b.Fatalf("expected to write %v, wrote %v", inputs[index].b, buf)
		}
	}
}

func BenchmarkAppendWithLen(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(maxVarInt8)) })
}

func benchmarkAppendWithLen(b *testing.B, inputs []benchmarkValue) {
	buf := make([]byte, 8)

	var i int
	for b.Loop() {
		buf = buf[:0]
		index := i % len(inputs)
		i++
		buf = AppendWithLen(buf, inputs[index].v, len(inputs[index].b))

		if !bytes.Equal(buf, inputs[index].b) {
			b.Fatalf("expected to write %v, wrote %v", inputs[index].b, buf)
		}
	}
}
