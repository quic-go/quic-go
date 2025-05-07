package gojay

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestEncodingArrStrings []string

func (t TestEncodingArrStrings) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddString(e)
	}
}
func (t TestEncodingArrStrings) IsNil() bool {
	return len(t) == 0
}

type TestEncodingArr []*TestEncoding

func (t TestEncodingArr) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddObject(e)
	}
}
func (t TestEncodingArr) IsNil() bool {
	return t == nil
}

type testEncodingArrInterfaces []interface{}

func (t testEncodingArrInterfaces) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddInterface(e)
	}
}
func (t testEncodingArrInterfaces) IsNil() bool {
	return t == nil
}

func TestEncoderArrayMarshalAPI(t *testing.T) {
	t.Run("array-objects", func(t *testing.T) {
		v := &TestEncodingArr{
			&TestEncoding{
				test:          "hello world",
				test2:         "漢字",
				testInt:       1,
				testBool:      true,
				testInterface: 1,
				sub: &SubObject{
					test1:    10,
					test2:    "hello world",
					test3:    1.23543,
					testBool: true,
					sub: &SubObject{
						test1:    10,
						testBool: false,
						test2:    "hello world",
					},
				},
			},
			&TestEncoding{
				test:     "hello world",
				test2:    "漢字",
				testInt:  1,
				testBool: true,
				sub: &SubObject{
					test1:    10,
					test2:    "hello world",
					test3:    1.23543,
					testBool: true,
					sub: &SubObject{
						test1:    10,
						testBool: false,
						test2:    "hello world",
					},
				},
			},
			nil,
		}
		r, err := Marshal(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`[{"test":"hello world","test2":"漢字","testInt":1,"testBool":true,`+
				`"testArr":[],"testF64":0,"testF32":0,"testInterface":1,"sub":{"test1":10,"test2":"hello world",`+
				`"test3":1.23543,"testBool":true,"sub":{"test1":10,"test2":"hello world",`+
				`"test3":0,"testBool":false,"sub":{}}}},{"test":"hello world","test2":"漢字","testInt":1,`+
				`"testBool":true,"testArr":[],"testF64":0,"testF32":0,"sub":{"test1":10,"test2":"hello world","test3":1.23543,`+
				`"testBool":true,"sub":{"test1":10,"test2":"hello world","test3":0,"testBool":false,"sub":{}}}},{}]`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("array-interfaces", func(t *testing.T) {
		v := &testEncodingArrInterfaces{
			1,
			int64(1),
			int32(1),
			int16(1),
			int8(1),
			uint64(1),
			uint32(1),
			uint16(1),
			uint8(1),
			float64(1.31),
			float32(1.31),
			&TestEncodingArr{},
			&TestEncodingArrStrings{},
			true,
			false,
			"test",
			&TestEncoding{
				test:     "hello world",
				test2:    "foobar",
				testInt:  1,
				testBool: true,
			},
		}
		r, err := MarshalJSONArray(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`[1,1,1,1,1,1,1,1,1.31,1.31,[],[],true,false,"test",{"test":"hello world","test2":"foobar","testInt":1,"testBool":true,"testArr":[],"testF64":0,"testF32":0,"sub":{}}]`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
}

func TestEncoderArrayEncodeAPI(t *testing.T) {
	t.Run("array-interfaces", func(t *testing.T) {
		v := &testEncodingArrInterfaces{
			1,
			int64(1),
			int32(1),
			int16(1),
			int8(1),
			uint64(1),
			uint32(1),
			uint16(1),
			uint8(1),
			float64(1.31),
			// float32(1.31),
			&TestEncodingArr{},
			true,
			"test",
			&TestEncoding{
				test:     "hello world",
				test2:    "foobar",
				testInt:  1,
				testBool: true,
			},
		}
		builder := &strings.Builder{}
		enc := BorrowEncoder(builder)
		defer enc.Release()
		err := enc.EncodeArray(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`[1,1,1,1,1,1,1,1,1.31,[],true,"test",{"test":"hello world","test2":"foobar","testInt":1,"testBool":true,"testArr":[],"testF64":0,"testF32":0,"sub":{}}]`,
			builder.String(),
			"Result of marshalling is different as the one expected")
	})

	t.Run("array-interfaces-write-error", func(t *testing.T) {
		v := &testEncodingArrInterfaces{}
		w := TestWriterError("")
		enc := BorrowEncoder(w)
		defer enc.Release()
		err := enc.EncodeArray(v)
		assert.NotNil(t, err, "err should not be nil")
	})
}

// Array add with omit key tests

type TestEncodingIntOmitEmpty []int

func (t TestEncodingIntOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddIntOmitEmpty(e)
	}
}
func (t TestEncodingIntOmitEmpty) IsNil() bool {
	return t == nil
}

type TestEncodingStringOmitEmpty []string

func (t TestEncodingStringOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddStringOmitEmpty(e)
	}
}
func (t TestEncodingStringOmitEmpty) IsNil() bool {
	return t == nil
}

type TestEncodingFloatOmitEmpty []float64

func (t TestEncodingFloatOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddFloatOmitEmpty(e)
	}
}
func (t TestEncodingFloatOmitEmpty) IsNil() bool {
	return t == nil
}

type TestEncodingFloat32OmitEmpty []float32

func (t TestEncodingFloat32OmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddFloat32OmitEmpty(e)
	}
}
func (t TestEncodingFloat32OmitEmpty) IsNil() bool {
	return t == nil
}

type TestEncodingBoolOmitEmpty []bool

func (t TestEncodingBoolOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddBoolOmitEmpty(e)
	}
}
func (t TestEncodingBoolOmitEmpty) IsNil() bool {
	return len(t) == 0
}

type TestEncodingArrOmitEmpty []TestEncodingBoolOmitEmpty

func (t TestEncodingArrOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddArrayOmitEmpty(e)
	}
}
func (t TestEncodingArrOmitEmpty) IsNil() bool {
	return len(t) == 0
}

type TestObjEmpty struct {
	empty bool
}

func (t *TestObjEmpty) MarshalJSONObject(enc *Encoder) {
}

func (t *TestObjEmpty) IsNil() bool {
	return !t.empty
}

type TestEncodingObjOmitEmpty []*TestObjEmpty

func (t TestEncodingObjOmitEmpty) MarshalJSONArray(enc *Encoder) {
	for _, e := range t {
		enc.AddObjectOmitEmpty(e)
	}
}
func (t TestEncodingObjOmitEmpty) IsNil() bool {
	return t == nil
}

func TestEncoderArrayOmitEmpty(t *testing.T) {
	t.Run("omit-int", func(t *testing.T) {
		intArr := TestEncodingIntOmitEmpty{0, 1, 0, 1}
		b, err := Marshal(intArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[1,1]`, string(b), "string(b) must be equal to `[1,1]`")
	})
	t.Run("omit-float", func(t *testing.T) {
		floatArr := TestEncodingFloatOmitEmpty{0, 1, 0, 1}
		b, err := Marshal(floatArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[1,1]`, string(b), "string(b) must be equal to `[1,1]`")
	})
	t.Run("omit-float32", func(t *testing.T) {
		float32Arr := TestEncodingFloat32OmitEmpty{0, 1, 0, 1}
		b, err := Marshal(float32Arr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[1,1]`, string(b), "string(b) must be equal to `[1,1]`")
	})
	t.Run("omit-string", func(t *testing.T) {
		stringArr := TestEncodingStringOmitEmpty{"", "hello", "", "world"}
		b, err := Marshal(stringArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `["hello","world"]`, string(b), "string(b) must be equal to `[\"hello\",\"world\"]`")
	})
	t.Run("omit-bool", func(t *testing.T) {
		boolArr := TestEncodingBoolOmitEmpty{false, true, false, true}
		b, err := Marshal(boolArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[true,true]`, string(b), "string(b) must be equal to `[true,true]`")
	})
	t.Run("omit-arr", func(t *testing.T) {
		arrArr := TestEncodingArrOmitEmpty{TestEncodingBoolOmitEmpty{true}, nil, TestEncodingBoolOmitEmpty{true}, nil}
		b, err := Marshal(arrArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[[true],[true]]`, string(b), "string(b) must be equal to `[[true],[true]]`")
	})
	t.Run("omit-obj", func(t *testing.T) {
		objArr := TestEncodingObjOmitEmpty{&TestObjEmpty{true}, &TestObjEmpty{false}, &TestObjEmpty{true}, &TestObjEmpty{false}}
		b, err := Marshal(objArr)
		assert.Nil(t, err, "err must be nil")
		assert.Equal(t, `[{},{}]`, string(b), "string(b) must be equal to `[{},{}]`")
	})
}

func TestEncoderArrErrors(t *testing.T) {
	t.Run("add-interface-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.AddInterface(nil)
		assert.Nil(t, enc.err, "enc.Err() should not be nil")
		assert.Equal(t, "", builder.String(), "builder.String() should not be ''")
	})
	t.Run("array-pooled-error", func(t *testing.T) {
		v := &testEncodingArrInterfaces{}
		enc := BorrowEncoder(nil)
		enc.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			assert.Equal(t, "Invalid usage of pooled encoder", err.(InvalidUsagePooledEncoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = enc.EncodeArray(v)
		assert.True(t, false, "should not be called as it should have panicked")
	})
}

func TestEncoderArrayFunc(t *testing.T) {
	var f EncodeArrayFunc
	assert.True(t, f.IsNil())
}

func TestEncodeArrayNullEmpty(t *testing.T) {
	var testCases = []struct {
		name, baseJSON, expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,["foo"]`,
		},
		{
			name:         "basic 1st elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,["foo"]`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddArrayNullEmpty(&TestEncodingArrStrings{})
			enc.ArrayNullEmpty(&TestEncodingArrStrings{"foo"})
		})
	}
}

func TestEncodeArrayKeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name, baseJSON, expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":["foo"]`,
		},
		{
			name:         "basic 1st elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":["foo"]`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddArrayKeyNullEmpty("foo", &TestEncodingArrStrings{})
			enc.ArrayKeyNullEmpty("bar", &TestEncodingArrStrings{"foo"})
		})
	}
}
