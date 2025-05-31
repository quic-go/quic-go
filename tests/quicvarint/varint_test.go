package quicvarint

import (
	"bytes"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimits(t *testing.T) {
	require.Equal(t, 0, Min)
	require.Equal(t, uint64(1<<62-1), uint64(Max))
}

func TestParsing(t *testing.T) {
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
			name:        "slice too short",
			input:       Append(nil, maxVarInt2*10)[:3],
			expectedErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.input)
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
		require.Panics(t, func() { Append(nil, maxVarInt8+1) })
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
		require.Panics(t, func() { Len(maxVarInt8 + 1) })
	})
}

type benchmarkValue struct {
	b []byte
	v uint64
}

func randomValues(num int, maxValue uint64) []benchmarkValue {
	r := rand.New(rand.NewPCG(13, 37))

	bv := make([]benchmarkValue, num)
	for i := range num {
		v := r.Uint64() % maxValue
		bv[i].v = v
		bv[i].b = Append([]byte{}, v)
	}
	return bv
}

func BenchmarkRead(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkRead(b, randomValues(min(b.N, 1024), maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkRead(b, randomValues(min(b.N, 1024), maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkRead(b, randomValues(min(b.N, 1024), maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkRead(b, randomValues(min(b.N, 1024), maxVarInt8)) })
}

func benchmarkRead(b *testing.B, inputs []benchmarkValue) {
	r := bytes.NewReader([]byte{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % len(inputs)
		r.Reset(inputs[index].b)
		val, err := Read(r)
		if err != nil {
			b.Fatal(err)
		}
		if val != inputs[index].v {
			b.Fatalf("expected %d, got %d", inputs[index].v, val)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkParse(b, randomValues(min(b.N, 1024), maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkParse(b, randomValues(min(b.N, 1024), maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkParse(b, randomValues(min(b.N, 1024), maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkParse(b, randomValues(min(b.N, 1024), maxVarInt8)) })
}

func benchmarkParse(b *testing.B, inputs []benchmarkValue) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 1024
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
	b.Run("1-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(min(b.N, 1024), maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(min(b.N, 1024), maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(min(b.N, 1024), maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkAppend(b, randomValues(min(b.N, 1024), maxVarInt8)) })
}

func benchmarkAppend(b *testing.B, inputs []benchmarkValue) {
	buf := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = buf[:0]
		index := i % 1024
		buf = Append(buf, inputs[index].v)

		if !bytes.Equal(buf, inputs[index].b) {
			b.Fatalf("expected to write %v, wrote %v", inputs[index].b, buf)
		}
	}
}

func BenchmarkAppendWithLen(b *testing.B) {
	b.Run("1-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(min(b.N, 1024), maxVarInt1)) })
	b.Run("2-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(min(b.N, 1024), maxVarInt2)) })
	b.Run("4-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(min(b.N, 1024), maxVarInt4)) })
	b.Run("8-byte", func(b *testing.B) { benchmarkAppendWithLen(b, randomValues(min(b.N, 1024), maxVarInt8)) })
}

func benchmarkAppendWithLen(b *testing.B, inputs []benchmarkValue) {
	buf := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = buf[:0]
		index := i % 1024
		buf = AppendWithLen(buf, inputs[index].v, len(inputs[index].b))

		if !bytes.Equal(buf, inputs[index].b) {
			b.Fatalf("expected to write %v, wrote %v", inputs[index].b, buf)
		}
	}
}
