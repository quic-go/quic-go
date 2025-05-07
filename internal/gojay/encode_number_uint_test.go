package gojay

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncoderUint64(t *testing.T) {
	var testCasesBasic = []struct {
		name         string
		v            uint64
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint64(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint64,
			expectedJSON: "[18446744073709551615,18446744073709551615]",
		},
		{
			name:         "big",
			v:            uint64(0),
			expectedJSON: "[0,0]",
		},
	}
	for _, testCase := range testCasesBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint64(testCase.v)
				enc.AddUint64(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesOmitEmpty = []struct {
		name         string
		v            uint64
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint64(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint64,
			expectedJSON: "[18446744073709551615,18446744073709551615]",
		},
		{
			name:         "big",
			v:            uint64(0),
			expectedJSON: "[]",
		},
	}
	for _, testCase := range testCasesOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint64OmitEmpty(testCase.v)
				enc.AddUint64OmitEmpty(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyBasic = []struct {
		name         string
		v            uint64
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint64(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint64,
			expectedJSON: `{"foo":18446744073709551615,"bar":18446744073709551615}`,
		},
		{
			name:         "big",
			v:            uint64(0),
			expectedJSON: `{"foo":0,"bar":0}`,
		},
	}
	for _, testCase := range testCasesKeyBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint64Key("foo", testCase.v)
				enc.AddUint64Key("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyOmitEmpty = []struct {
		name         string
		v            uint64
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint64(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint64,
			expectedJSON: `{"foo":18446744073709551615,"bar":18446744073709551615}`,
		},
		{
			name:         "big",
			v:            uint64(0),
			expectedJSON: "{}",
		},
	}
	for _, testCase := range testCasesKeyOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint64KeyOmitEmpty("foo", testCase.v)
				enc.AddUint64KeyOmitEmpty("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint32(t *testing.T) {
	var testCasesBasic = []struct {
		name         string
		v            uint32
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint32(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint32,
			expectedJSON: "[4294967295,4294967295]",
		},
		{
			name:         "big",
			v:            uint32(0),
			expectedJSON: "[0,0]",
		},
	}
	for _, testCase := range testCasesBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint32(testCase.v)
				enc.AddUint32(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesOmitEmpty = []struct {
		name         string
		v            uint32
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint32(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint32,
			expectedJSON: "[4294967295,4294967295]",
		},
		{
			name:         "big",
			v:            uint32(0),
			expectedJSON: "[]",
		},
	}
	for _, testCase := range testCasesOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint32OmitEmpty(testCase.v)
				enc.AddUint32OmitEmpty(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyBasic = []struct {
		name         string
		v            uint32
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint32(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint32,
			expectedJSON: `{"foo":4294967295,"bar":4294967295}`,
		},
		{
			name:         "big",
			v:            uint32(0),
			expectedJSON: `{"foo":0,"bar":0}`,
		},
	}
	for _, testCase := range testCasesKeyBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint32Key("foo", testCase.v)
				enc.AddUint32Key("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyOmitEmpty = []struct {
		name         string
		v            uint32
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint32(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint32,
			expectedJSON: `{"foo":4294967295,"bar":4294967295}`,
		},
		{
			name:         "big",
			v:            uint32(0),
			expectedJSON: `{}`,
		},
	}
	for _, testCase := range testCasesKeyOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint32KeyOmitEmpty("foo", testCase.v)
				enc.AddUint32KeyOmitEmpty("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint16(t *testing.T) {
	var testCasesBasic = []struct {
		name         string
		v            uint16
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint16(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint16,
			expectedJSON: "[65535,65535]",
		},
		{
			name:         "big",
			v:            uint16(0),
			expectedJSON: "[0,0]",
		},
	}
	for _, testCase := range testCasesBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint16(testCase.v)
				enc.AddUint16(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesOmitEmpty = []struct {
		name         string
		v            uint16
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint16(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint16,
			expectedJSON: "[65535,65535]",
		},
		{
			name:         "big",
			v:            uint16(0),
			expectedJSON: "[]",
		},
	}
	for _, testCase := range testCasesOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint16OmitEmpty(testCase.v)
				enc.AddUint16OmitEmpty(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyBasic = []struct {
		name         string
		v            uint16
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint16(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint16,
			expectedJSON: `{"foo":65535,"bar":65535}`,
		},
		{
			name:         "big",
			v:            uint16(0),
			expectedJSON: `{"foo":0,"bar":0}`,
		},
	}
	for _, testCase := range testCasesKeyBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint16Key("foo", testCase.v)
				enc.AddUint16Key("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyOmitEmpty = []struct {
		name         string
		v            uint16
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint16(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint16,
			expectedJSON: `{"foo":65535,"bar":65535}`,
		},
		{
			name:         "big",
			v:            uint16(0),
			expectedJSON: `{}`,
		},
	}
	for _, testCase := range testCasesKeyOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint16KeyOmitEmpty("foo", testCase.v)
				enc.AddUint16KeyOmitEmpty("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint8(t *testing.T) {
	var testCasesBasic = []struct {
		name         string
		v            uint8
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint8(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint8,
			expectedJSON: "[255,255]",
		},
		{
			name:         "big",
			v:            uint8(0),
			expectedJSON: "[0,0]",
		},
	}
	for _, testCase := range testCasesBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint8(testCase.v)
				enc.AddUint8(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesOmitEmpty = []struct {
		name         string
		v            uint8
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint8(1),
			expectedJSON: "[1,1]",
		},
		{
			name:         "big",
			v:            math.MaxUint8,
			expectedJSON: "[255,255]",
		},
		{
			name:         "big",
			v:            uint8(0),
			expectedJSON: "[]",
		},
	}
	for _, testCase := range testCasesOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeArrayFunc(func(enc *Encoder) {
				enc.Uint8OmitEmpty(testCase.v)
				enc.AddUint8OmitEmpty(testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyBasic = []struct {
		name         string
		v            uint8
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint8(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint8,
			expectedJSON: `{"foo":255,"bar":255}`,
		},
		{
			name:         "big",
			v:            uint8(0),
			expectedJSON: `{"foo":0,"bar":0}`,
		},
	}
	for _, testCase := range testCasesKeyBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint8Key("foo", testCase.v)
				enc.AddUint8Key("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
	var testCasesKeyOmitEmpty = []struct {
		name         string
		v            uint8
		expectedJSON string
	}{
		{
			name:         "basic",
			v:            uint8(1),
			expectedJSON: `{"foo":1,"bar":1}`,
		},
		{
			name:         "big",
			v:            math.MaxUint8,
			expectedJSON: `{"foo":255,"bar":255}`,
		},
		{
			name:         "big",
			v:            uint8(0),
			expectedJSON: `{}`,
		},
	}
	for _, testCase := range testCasesKeyOmitEmpty {
		t.Run(testCase.name, func(t *testing.T) {
			var b = &strings.Builder{}
			var enc = NewEncoder(b)
			enc.Encode(EncodeObjectFunc(func(enc *Encoder) {
				enc.Uint8KeyOmitEmpty("foo", testCase.v)
				enc.AddUint8KeyOmitEmpty("bar", testCase.v)
			}))
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint64NullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run("true", func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.Uint64NullEmpty(0)
			enc.AddUint64NullEmpty(1)
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint64KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.Uint64KeyNullEmpty("foo", 0)
			enc.AddUint64KeyNullEmpty("bar", 1)
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint32NullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run("true", func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.Uint32NullEmpty(0)
			enc.AddUint32NullEmpty(1)
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint32KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddUint32KeyNullEmpty("foo", 0)
			enc.Uint32KeyNullEmpty("bar", uint32(1))
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint16NullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run("true", func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddUint16NullEmpty(0)
			enc.Uint16NullEmpty(1)
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint16KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddUint16KeyNullEmpty("foo", 0)
			enc.Uint16KeyNullEmpty("bar", uint16(1))
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint8NullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,1`,
		},
	}
	for _, testCase := range testCases {
		t.Run("true", func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddUint8NullEmpty(0)
			enc.Uint8NullEmpty(1)
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderUint8KeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":1`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":1`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddUint8KeyNullEmpty("foo", 0)
			enc.Uint8KeyNullEmpty("bar", uint8(1))
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}
