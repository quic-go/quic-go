package gojay

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var encoderTestCases = []struct {
	v            interface{}
	expectations func(t *testing.T, b string, err error)
}{
	{
		v: 100,
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: int64(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: int32(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: int8(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: uint64(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: uint32(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: uint16(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: uint8(100),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100", b, "b should equal 100")
		},
	},
	{
		v: float64(100.12),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100.12", b, "b should equal 100.12")
		},
	},
	{
		v: float32(100.12),
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "100.12", b, "b should equal 100.12")
		},
	},
	{
		v: true,
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, "true", b, "b should equal true")
		},
	},
	{
		v: "hello world",
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, `"hello world"`, b, `b should equal "hello world"`)
		},
	},
	{
		v: "hello world",
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, `"hello world"`, b, `b should equal "hello world"`)
		},
	},
	{
		v: &TestEncodingArrStrings{"hello world", "foo bar"},
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, `["hello world","foo bar"]`, b, `b should equal ["hello world","foo bar"]`)
		},
	},
	{
		v: &testObject{
			"漢字", nil, 1, nil, 1, nil, 1, nil, 1, nil, 1, nil,
			1, nil, 1, nil, 1, nil, 1, nil, 1.1, nil, 1.1, nil, true, nil,
			&testObject{}, testSliceInts{}, []interface{}{"h", "o", "l", "a"},
		},
		expectations: func(t *testing.T, b string, err error) {
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, `{"testStr":"漢字","testInt":1,"testInt64":1,"testInt32":1,"testInt16":1,"testInt8":1,"testUint64":1,"testUint32":1,"testUint16":1,"testUint8":1,"testFloat64":1.1,"testFloat32":1.1,"testBool":true}`, string(b), `string(b) should equal {"testStr":"漢字","testInt":1,"testInt64":1,"testInt32":1,"testInt16":1,"testInt8":1,"testUint64":1,"testUint32":1,"testUint16":1,"testUint8":1,"testFloat64":1.1,"testFloat32":1.1,"testBool":true}`)
		},
	},
	{
		v: &struct{}{},
		expectations: func(t *testing.T, b string, err error) {
			assert.NotNil(t, err, "err should be nil")
			assert.IsType(t, InvalidMarshalError(""), err, "err should be of type InvalidMarshalError")
			var s = struct{}{}
			assert.Equal(t, fmt.Sprintf(invalidMarshalErrorMsg, &s), err.Error(), "err message should be equal to invalidMarshalErrorMsg")
		},
	},
}

func TestEncoderInterfaceEncodeAPI(t *testing.T) {
	t.Run("encode-all-types", func(t *testing.T) {
		for _, test := range encoderTestCases {
			builder := &strings.Builder{}
			enc := BorrowEncoder(builder)
			err := enc.Encode(test.v)
			enc.Release()
			test.expectations(t, builder.String(), err)
		}
	})
	t.Run("encode-all-types-write-error", func(t *testing.T) {
		v := ""
		w := TestWriterError("")
		enc := BorrowEncoder(w)
		err := enc.Encode(v)
		assert.NotNil(t, err, "err should not be nil")
	})
	t.Run("encode-all-types-pool-error", func(t *testing.T) {
		v := ""
		w := TestWriterError("")
		enc := BorrowEncoder(w)
		enc.isPooled = 1
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err should not be nil")
			assert.IsType(t, InvalidUsagePooledEncoderError(""), err, "err should be of type InvalidUsagePooledEncoderError")
		}()
		_ = enc.Encode(v)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
}

func TestEncoderInterfaceMarshalAPI(t *testing.T) {
	t.Run("marshal-all-types", func(t *testing.T) {
		for _, test := range encoderTestCases {
			b, err := Marshal(test.v)
			test.expectations(t, string(b), err)
		}
	})
}
