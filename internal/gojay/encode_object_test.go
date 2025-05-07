package gojay

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testObjectWithUnknownType struct {
	unknownType struct{}
}

func (t *testObjectWithUnknownType) IsNil() bool {
	return t == nil
}

func (t *testObjectWithUnknownType) MarshalJSONObject(enc *Encoder) {
	enc.AddInterfaceKey("unknownType", t.unknownType)
}

type TestEncoding struct {
	test          string
	test2         string
	testInt       int
	testBool      bool
	testF32       float32
	testF64       float64
	testInterface interface{}
	testArr       TestEncodingArr
	sub           *SubObject
}

func (t *TestEncoding) IsNil() bool {
	return t == nil
}

func (t *TestEncoding) MarshalJSONObject(enc *Encoder) {
	enc.AddStringKey("test", t.test)
	enc.AddStringKey("test2", t.test2)
	enc.AddIntKey("testInt", t.testInt)
	enc.AddBoolKey("testBool", t.testBool)
	enc.AddInterfaceKey("testArr", t.testArr)
	enc.AddInterfaceKey("testF64", t.testF64)
	enc.AddInterfaceKey("testF32", t.testF32)
	enc.AddInterfaceKey("testInterface", t.testInterface)
	enc.AddInterfaceKey("sub", t.sub)
}

type SubObject struct {
	test1    int
	test2    string
	test3    float64
	testBool bool
	sub      *SubObject
}

func (t *SubObject) IsNil() bool {
	return t == nil
}

func (t *SubObject) MarshalJSONObject(enc *Encoder) {
	enc.AddIntKey("test1", t.test1)
	enc.AddStringKey("test2", t.test2)
	enc.AddFloatKey("test3", t.test3)
	enc.AddBoolKey("testBool", t.testBool)
	enc.AddObjectKey("sub", t.sub)
}

type testEncodingObjInterfaces struct {
	interfaceVal interface{}
}

func (t *testEncodingObjInterfaces) IsNil() bool {
	return t == nil
}

func (t *testEncodingObjInterfaces) MarshalJSONObject(enc *Encoder) {
	enc.AddInterfaceKey("interfaceVal", t.interfaceVal)
}

func TestEncoderObjectEncodeAPI(t *testing.T) {
	t.Run("encode-basic", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeObject(&testObject{
			"漢字", nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil,
			1, nil, 1, nil, 1.1, nil, 1.1, nil, true, nil,
			&testObject{}, testSliceInts{}, interface{}("test"),
		})
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"testStr":"漢字","testInt":1,"testInt64":1,"testInt32":1,"testInt16":1,"testInt8":1,"testUint64":1,"testUint32":1,"testUint16":1,"testUint8":1,"testFloat64":1.1,"testFloat32":1.1,"testBool":true}`,
			builder.String(),
			"Result of marshalling is different as the one expected",
		)
	})
}

func TestEncoderObjectMarshalAPI(t *testing.T) {
	t.Run("marshal-basic", func(t *testing.T) {
		r, err := Marshal(&testObject{
			"漢字", nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil, 1,
			nil, 1, nil, 1, nil, 1.1, nil, 1.1, nil, true, nil,
			&testObject{}, testSliceInts{}, []interface{}{"h", "o", "l", "a"},
		})
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"testStr":"漢字","testInt":1,"testInt64":1,"testInt32":1,"testInt16":1,"testInt8":1,"testUint64":1,"testUint32":1,"testUint16":1,"testUint8":1,"testFloat64":1.1,"testFloat32":1.1,"testBool":true}`,
			string(r),
			"Result of marshalling is different as the one expected",
		)
	})

	t.Run("marshal-complex", func(t *testing.T) {
		v := &TestEncoding{
			test:          "hello world",
			test2:         "foobar",
			testInt:       1,
			testBool:      true,
			testF32:       120.53,
			testF64:       120.15,
			testInterface: true,
			testArr: TestEncodingArr{
				&TestEncoding{
					test: "1",
				},
			},
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
		}
		r, err := MarshalJSONObject(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"test":"hello world","test2":"foobar","testInt":1,"testBool":true,"testArr":[{"test":"1","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}],"testF64":120.15,"testF32":120.53,"testInterface":true,"sub":{"test1":10,"test2":"hello world","test3":1.23543,"testBool":true,"sub":{"test1":10,"test2":"hello world","test3":0,"testBool":false,"sub":{}}}}`,
			string(r),
			"Result of marshalling is different as the one expected",
		)
	})

	t.Run("marshal-interface-string", func(t *testing.T) {
		v := testEncodingObjInterfaces{"string"}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":"string"}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-int", func(t *testing.T) {
		v := testEncodingObjInterfaces{1}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-int64", func(t *testing.T) {
		v := testEncodingObjInterfaces{int64(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-int32", func(t *testing.T) {
		v := testEncodingObjInterfaces{int32(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-int16", func(t *testing.T) {
		v := testEncodingObjInterfaces{int16(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-int8", func(t *testing.T) {
		v := testEncodingObjInterfaces{int8(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-uint64", func(t *testing.T) {
		v := testEncodingObjInterfaces{uint64(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-uint32", func(t *testing.T) {
		v := testEncodingObjInterfaces{uint32(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-uint16", func(t *testing.T) {
		v := testEncodingObjInterfaces{uint16(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-uint8", func(t *testing.T) {
		v := testEncodingObjInterfaces{uint8(1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-float64", func(t *testing.T) {
		v := testEncodingObjInterfaces{float64(1.1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1.1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-interface-float32", func(t *testing.T) {
		v := testEncodingObjInterfaces{float32(1.1)}
		r, err := Marshal(&v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"interfaceVal":1.1}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-object-func", func(t *testing.T) {
		f := EncodeObjectFunc(func(enc *Encoder) {
			enc.AddStringKeyOmitEmpty("test", "test")
		})
		r, err := Marshal(f)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"test":"test"}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
	t.Run("marshal-any-object", func(t *testing.T) {
		test := struct {
			Foo string
			Bar int
		}{
			"test",
			100,
		}
		r, err := MarshalAny(test)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"Foo":"test","Bar":100}`,
			string(r),
			"Result of marshalling is different as the one expected")
	})
}

type TestObectOmitEmpty struct {
	nonNiler           int
	testInt            int
	testFloat          float64
	testFloat32        float32
	testString         string
	testBool           bool
	testObectOmitEmpty *TestObectOmitEmpty
	testObect          *TestObectOmitEmpty
}

func (t *TestObectOmitEmpty) IsNil() bool {
	return t == nil
}

func (t *TestObectOmitEmpty) MarshalJSONObject(enc *Encoder) {
	enc.AddIntKeyOmitEmpty("testInt", t.testInt)
	enc.AddIntKeyOmitEmpty("testIntNotEmpty", 1)
	enc.AddFloatKeyOmitEmpty("testFloat", t.testFloat)
	enc.AddFloatKeyOmitEmpty("testFloatNotEmpty", 1.1)
	enc.AddFloat32KeyOmitEmpty("testFloat32", t.testFloat32)
	enc.AddFloat32KeyOmitEmpty("testFloat32NotEmpty", 1.1)
	enc.AddStringKeyOmitEmpty("testString", t.testString)
	enc.AddStringKeyOmitEmpty("testStringNotEmpty", "foo")
	enc.AddBoolKeyOmitEmpty("testBool", t.testBool)
	enc.AddBoolKeyOmitEmpty("testBoolNotEmpty", true)
	enc.AddObjectKeyOmitEmpty("testObect", t.testObect)
	enc.AddObjectKeyOmitEmpty("testObectOmitEmpty", t.testObectOmitEmpty)
	enc.AddArrayKeyOmitEmpty("testArrayOmitEmpty", TestEncodingArrStrings{})
	enc.AddArrayKeyOmitEmpty("testArray", TestEncodingArrStrings{"foo"})
}

type TestObectOmitEmptyInterface struct{}

func (t *TestObectOmitEmptyInterface) IsNil() bool {
	return t == nil
}

func (t *TestObectOmitEmptyInterface) MarshalJSONObject(enc *Encoder) {
	enc.AddInterfaceKeyOmitEmpty("testInt", 0)
	enc.AddInterfaceKeyOmitEmpty("testInt64", int64(0))
	enc.AddInterfaceKeyOmitEmpty("testInt32", int32(0))
	enc.AddInterfaceKeyOmitEmpty("testInt16", int16(0))
	enc.AddInterfaceKeyOmitEmpty("testInt8", int8(0))
	enc.AddInterfaceKeyOmitEmpty("testUint8", uint8(0))
	enc.AddInterfaceKeyOmitEmpty("testUint16", uint16(0))
	enc.AddInterfaceKeyOmitEmpty("testUint32", uint32(0))
	enc.AddInterfaceKeyOmitEmpty("testUint64", uint64(0))
	enc.AddInterfaceKeyOmitEmpty("testIntNotEmpty", 1)
	enc.AddInterfaceKeyOmitEmpty("testFloat", 0)
	enc.AddInterfaceKeyOmitEmpty("testFloatNotEmpty", 1.1)
	enc.AddInterfaceKeyOmitEmpty("testFloat32", float32(0))
	enc.AddInterfaceKeyOmitEmpty("testFloat32NotEmpty", float32(1.1))
	enc.AddInterfaceKeyOmitEmpty("testString", "")
	enc.AddInterfaceKeyOmitEmpty("testStringNotEmpty", "foo")
	enc.AddInterfaceKeyOmitEmpty("testBool", false)
	enc.AddInterfaceKeyOmitEmpty("testBoolNotEmpty", true)
	enc.AddInterfaceKeyOmitEmpty("testObectOmitEmpty", nil)
	enc.AddInterfaceKeyOmitEmpty("testObect", &TestEncoding{})
	enc.AddInterfaceKeyOmitEmpty("testArr", &TestEncodingArrStrings{})
}

func TestEncoderObjectOmitEmpty(t *testing.T) {
	t.Run("encoder-omit-empty-all-types", func(t *testing.T) {
		v := &TestObectOmitEmpty{
			nonNiler:  1,
			testInt:   0,
			testObect: &TestObectOmitEmpty{testInt: 1},
		}
		r, err := MarshalJSONObject(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"testIntNotEmpty":1,"testFloatNotEmpty":1.1,"testFloat32NotEmpty":1.1,"testStringNotEmpty":"foo","testBoolNotEmpty":true,"testObect":{"testInt":1,"testIntNotEmpty":1,"testFloatNotEmpty":1.1,"testFloat32NotEmpty":1.1,"testStringNotEmpty":"foo","testBoolNotEmpty":true,"testArray":["foo"]},"testArray":["foo"]}`,
			string(r),
			"Result of marshalling is different as the one expected",
		)
	})

	t.Run("encoder-omit-empty-interface", func(t *testing.T) {
		v := &TestObectOmitEmptyInterface{}
		r, err := MarshalJSONObject(v)
		assert.Nil(t, err, "Error should be nil")
		assert.Equal(
			t,
			`{"testIntNotEmpty":1,"testFloatNotEmpty":1.1,"testFloat32NotEmpty":1.1,"testStringNotEmpty":"foo","testBoolNotEmpty":true,"testObect":{"test":"","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}}`,
			string(r),
			"Result of marshalling is different as the one expected",
		)
	})
}

func TestEncoderObjectEncodeAPIError(t *testing.T) {
	t.Run("interface-key-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeObject(&testObjectWithUnknownType{struct{}{}})
		assert.NotNil(t, err, "Error should not be nil")
		assert.Equal(t, "Invalid type struct {} provided to Marshal", err.Error(), "err.Error() should be 'Invalid type struct {} provided to Marshal'")
	})
	t.Run("write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		err := enc.EncodeObject(&testObject{})
		assert.NotNil(t, err, "Error should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err.Error() should be 'Test Error'")
	})
	t.Run("interface-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		enc.AddInterfaceKeyOmitEmpty("test", struct{}{})
		assert.NotNil(t, enc.err, "enc.Err() should not be nil")
	})
	t.Run("pool-error", func(t *testing.T) {
		v := &TestEncoding{}
		enc := BorrowEncoder(nil)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			assert.Equal(t, "Invalid usage of pooled encoder", err.(InvalidUsagePooledEncoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = enc.EncodeObject(v)
		assert.True(t, false, "should not be called as it should have panicked")
	})
}

func TestEncoderObjectKeyNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "{",
			expectedJSON: `{"foo":null,"bar":{"test":"","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `{"test":"test"`,
			expectedJSON: `{"test":"test","foo":null,"bar":{"test":"","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddObjectKeyNullEmpty("foo", (*TestEncoding)(nil))
			enc.ObjectKeyNullEmpty("bar", &TestEncoding{})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

func TestEncoderObjectNullEmpty(t *testing.T) {
	var testCases = []struct {
		name         string
		baseJSON     string
		expectedJSON string
	}{
		{
			name:         "basic 1st elem",
			baseJSON:     "[",
			expectedJSON: `[null,{"test":"","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}`,
		},
		{
			name:         "basic 2nd elem",
			baseJSON:     `["test"`,
			expectedJSON: `["test",null,{"test":"","test2":"","testInt":0,"testBool":false,"testArr":[],"testF64":0,"testF32":0,"sub":{}}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			enc.writeString(testCase.baseJSON)
			enc.AddObjectNullEmpty((*TestEncoding)(nil))
			enc.ObjectNullEmpty(&TestEncoding{})
			enc.Write()
			assert.Equal(t, testCase.expectedJSON, b.String())
		})
	}
}

type ObjectWithKeys struct {
	Str          string
	Int          int
	Int64        int64
	Int32        int32
	Int16        int16
	Int8         int8
	Uint64       uint64
	Uint32       uint32
	Uint16       uint16
	Uint8        uint8
	Float64      float64
	Float32      float32
	Bool         bool
	Obj          *ObjectWithKeys
	Slice        TestEncodingArrStrings
	Time         *time.Time
	EmbeddedJSON *EmbeddedJSON
}

func (o *ObjectWithKeys) MarshalJSONObject(enc *Encoder) {
	enc.StringKey("string", o.Str)
	enc.StringKeyOmitEmpty("string", o.Str)
	enc.StringKeyNullEmpty("string", o.Str)
	enc.IntKey("int", o.Int)
	enc.IntKeyOmitEmpty("int", o.Int)
	enc.IntKeyNullEmpty("int", o.Int)
	enc.Int64Key("int64", o.Int64)
	enc.Int64KeyOmitEmpty("int64", o.Int64)
	enc.Int64KeyNullEmpty("int64", o.Int64)
	enc.Int32Key("int32", o.Int32)
	enc.Int32KeyOmitEmpty("int32", o.Int32)
	enc.Int32KeyNullEmpty("int32", o.Int32)
	enc.Int16Key("int16", o.Int16)
	enc.Int16KeyOmitEmpty("int16", o.Int16)
	enc.Int16KeyNullEmpty("int16", o.Int16)
	enc.Int8Key("int8", o.Int8)
	enc.Int8KeyOmitEmpty("int8", o.Int8)
	enc.Int8KeyNullEmpty("int8", o.Int8)
	enc.Uint64KeyOmitEmpty("uint64", o.Uint64)
	enc.Uint64KeyNullEmpty("uint64", o.Uint64)
	enc.Uint64Key("uint64", o.Uint64)
	enc.Uint32Key("uint32", o.Uint32)
	enc.Uint32KeyOmitEmpty("uint32", o.Uint32)
	enc.Uint32KeyNullEmpty("uint32", o.Uint32)
	enc.Uint16KeyOmitEmpty("uint16", o.Uint16)
	enc.Uint16KeyNullEmpty("uint16", o.Uint16)
	enc.Uint16Key("uint16", o.Uint16)
	enc.Uint8Key("uint8", o.Uint8)
	enc.Uint8KeyOmitEmpty("uint8", o.Uint8)
	enc.Uint8KeyNullEmpty("uint8", o.Uint8)
	enc.Float64Key("float64", o.Float64)
	enc.Float64KeyOmitEmpty("float64", o.Float64)
	enc.Float64KeyNullEmpty("float64", o.Float64)
	enc.Float32Key("float32", o.Float32)
	enc.Float32KeyOmitEmpty("float32", o.Float32)
	enc.Float32KeyNullEmpty("float32", o.Float32)
	enc.BoolKey("bool", o.Bool)
	enc.BoolKeyOmitEmpty("bool", o.Bool)
	enc.BoolKeyNullEmpty("bool", o.Bool)
	enc.ObjectKeyOmitEmpty("object", o.Obj)
	enc.ObjectKeyNullEmpty("object", o.Obj)
	enc.ObjectKey("object", o.Obj)
	enc.ArrayKey("array", o.Slice)
	enc.ArrayKeyOmitEmpty("array", o.Slice)
	enc.ArrayKeyNullEmpty("array", o.Slice)
	enc.TimeKey("time", o.Time, time.RFC3339)
	enc.AddEmbeddedJSONKey("ejson", o.EmbeddedJSON)
	enc.AddEmbeddedJSONKeyOmitEmpty("ejson", o.EmbeddedJSON)
	enc.NullKey("null")
}

func (o *ObjectWithKeys) IsNil() bool {
	return o == nil
}

type NilObject struct{}

func (n *NilObject) MarshalJSONObject(enc *Encoder) {}
func (n *NilObject) IsNil() bool                    { return true }

func TestEncodeObjectWithKeys(t *testing.T) {
	t.Run(
		"should not encode any key",
		func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			var o = &ObjectWithKeys{}
			var err = enc.EncodeObjectKeys(o, []string{})
			assert.Nil(t, err)
			assert.Equal(t, `{}`, b.String())
		},
	)
	t.Run(
		"should encode some keys",
		func(t *testing.T) {
			var b strings.Builder
			var enc = NewEncoder(&b)
			var o = &ObjectWithKeys{Str: "hello", Int: 420}
			var err = enc.EncodeObjectKeys(o, []string{"string", "int"})
			assert.Nil(t, err)
			assert.Equal(
				t,
				`{"string":"hello","string":"hello","string":"hello","int":420,"int":420,"int":420}`,
				b.String(),
			)
		},
	)
	t.Run("write-error", func(t *testing.T) {
		w := TestWriterError("")
		enc := NewEncoder(w)
		o := &ObjectWithKeys{Str: "hello", Int: 420}
		err := enc.EncodeObjectKeys(o, []string{"string", "int"})
		assert.NotNil(t, err, "Error should not be nil")
		assert.Equal(t, "Test Error", err.Error(), "err.Error() should be 'Test Error'")
	})
	t.Run("pool-error", func(t *testing.T) {
		v := &TestEncoding{}
		enc := BorrowEncoder(nil)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
			assert.Equal(t, "Invalid usage of pooled encoder", err.(InvalidUsagePooledEncoderError).Error(), "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = enc.EncodeObjectKeys(v, []string{})
		assert.True(t, false, "should not be called as it should have panicked")
	})
	t.Run("interface-key-error", func(t *testing.T) {
		builder := &strings.Builder{}
		enc := NewEncoder(builder)
		err := enc.EncodeObjectKeys(&testObjectWithUnknownType{struct{}{}}, []string{})
		assert.NotNil(t, err, "Error should not be nil")
		assert.Equal(t, "Invalid type struct {} provided to Marshal", err.Error(), "err.Error() should be 'Invalid type struct {} provided to Marshal'")
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeObjectKeys(EncodeObjectFunc(func(enc *Encoder) {
			enc.ObjectKeyWithKeys("test", EncodeObjectFunc(func(enc *Encoder) {
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}), []string{})
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `{}`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeObject(EncodeObjectFunc(func(enc *Encoder) {
			enc.ObjectKeyWithKeys("test", EncodeObjectFunc(func(enc *Encoder) {
				enc.keys = nil
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `{"test":{}}`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeObject(EncodeObjectFunc(func(enc *Encoder) {
			enc.ObjectKeyWithKeys("test", EncodeObjectFunc(func(enc *Encoder) {
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `{"test":{"test":"hello"}}`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeObject(EncodeObjectFunc(func(enc *Encoder) {
			enc.writeByte(' ')
			enc.ObjectKeyWithKeys("test", EncodeObjectFunc(func(enc *Encoder) {
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `{ ,"test":{"test":"hello"}}`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeObject(EncodeObjectFunc(func(enc *Encoder) {
			enc.writeByte(' ')
			enc.ObjectKeyWithKeys("test", &NilObject{}, []string{})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `{ ,"test":{}}`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeArray(EncodeArrayFunc(func(enc *Encoder) {
			enc.ObjectWithKeys(EncodeObjectFunc(func(enc *Encoder) {
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `[{"test":"hello"}]`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeArray(EncodeArrayFunc(func(enc *Encoder) {
			enc.writeByte(' ')
			enc.ObjectWithKeys(EncodeObjectFunc(func(enc *Encoder) {
				enc.StringKey("test", "hello")
				enc.StringKey("test2", "hello")
			}), []string{"test"})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `[ ,{"test":"hello"}]`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeArray(EncodeArrayFunc(func(enc *Encoder) {
			enc.ObjectWithKeys(&NilObject{}, []string{})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `[{}]`, b.String())
	})
	t.Run("encode-object-with-keys", func(t *testing.T) {
		b := &strings.Builder{}
		enc := NewEncoder(b)
		err := enc.EncodeArray(EncodeArrayFunc(func(enc *Encoder) {
			enc.writeByte(' ')
			enc.ObjectWithKeys(&NilObject{}, []string{})
		}))
		assert.Nil(t, err, "Error should not be nil")
		assert.Equal(t, `[ ,{}]`, b.String())
	})
}
