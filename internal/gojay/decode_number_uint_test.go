package gojay

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoderUint64(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint64
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 1039405",
			expectedResult: 1039405,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-big",
			json:           "18446744073709551615",
			expectedResult: 18446744073709551615,
		},
		{
			name:           "basic-big-overflow",
			json:           "18446744073709551616",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           "18446744073709551625",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "184467440737095516161",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-negative2",
			json:           "-2349557",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error1",
			json:           "132zz4",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v uint64
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
			} else {
				assert.Nil(t, err, "Err must be nil")
			}
			assert.Equal(t, testCase.expectedResult, v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := uint64(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeUint64(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v uint64
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.DecodeUint64(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint64(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v uint64
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeUint64(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
func TestDecoderUint64Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint64
		err            bool
		errType        interface{}
		resultIsNil    bool
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 1039405",
			expectedResult: 1039405,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-big",
			json:           "18446744073709551615",
			expectedResult: 18446744073709551615,
		},
		{
			name:           "basic-big-overflow",
			json:           "18446744073709551616",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           "18446744073709551625",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "184467440737095516161",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-negative2",
			json:           "-2349557",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error1",
			json:           "132zz4",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*uint64)(nil)
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
				return
			}
			assert.Nil(t, err, "Err must be nil")
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(t, testCase.expectedResult, *v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(uint64)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(uint64)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.Uint64Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderUint32(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint32
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 1039405 ",
			expectedResult: 1039405,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-2349557",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "4294967295",
			expectedResult: 4294967295,
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           "4294967395",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v uint32
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
			} else {
				assert.Nil(t, err, "Err must be nil")
			}
			assert.Equal(t, testCase.expectedResult, v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := uint32(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeUint32(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v uint32
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.DecodeUint32(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint32(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v uint32
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeUint32(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
func TestDecoderUint32Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint32
		err            bool
		errType        interface{}
		resultIsNil    bool
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 1039405 ",
			expectedResult: 1039405,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-2349557",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "4294967295",
			expectedResult: 4294967295,
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           "4294967395",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*uint32)(nil)
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
				return
			}
			assert.Nil(t, err, "Err must be nil")
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(t, testCase.expectedResult, *v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(uint32)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(uint32)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.Uint32Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderUint16(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint16
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 3224 ",
			expectedResult: 3224,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-overflow",
			json:           "335346564",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-24467",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "54546",
			expectedResult: 54546,
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           " 65537",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           " 66537",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v uint16
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
			} else {
				assert.Nil(t, err, "Err must be nil")
			}
			assert.Equal(t, testCase.expectedResult, v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := uint16(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeUint16(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v uint16
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.DecodeUint16(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint16(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api2", func(t *testing.T) {
		var v uint16
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.Decode(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint16(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v uint16
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeUint16(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
func TestDecoderUint16Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint16
		err            bool
		errType        interface{}
		resultIsNil    bool
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 3224 ",
			expectedResult: 3224,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-overflow",
			json:           "335346564",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-24467",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "54546",
			expectedResult: 54546,
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           " 65537",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow",
			json:           " 66537",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*uint16)(nil)
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
				return
			}
			assert.Nil(t, err, "Err must be nil")
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(t, testCase.expectedResult, *v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(uint16)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(uint16)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.Uint16Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderUint8(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint8
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 255 ",
			expectedResult: 255,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-234",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "200",
			expectedResult: 200,
		},
		{
			name:           "basic-overflow",
			json:           "256",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-overflow",
			json:           "274",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v uint8
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
			} else {
				assert.Nil(t, err, "Err must be nil")
			}
			assert.Equal(t, testCase.expectedResult, v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := uint8(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeUint8(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v uint8
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.DecodeUint8(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint8(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api2", func(t *testing.T) {
		var v uint8
		dec := NewDecoder(strings.NewReader(`33`))
		defer dec.Release()
		err := dec.Decode(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, uint8(33), v, "v must be equal to 33")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v uint8
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeUint8(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderUint8Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult uint8
		err            bool
		errType        interface{}
		resultIsNil    bool
	}{
		{
			name:           "basic-positive",
			json:           "100",
			expectedResult: 100,
		},
		{
			name:           "basic-positive2",
			json:           " 255 ",
			expectedResult: 255,
		},
		{
			name:           "basic-negative",
			json:           "-2",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-skip-data-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative2",
			json:           "-234",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big",
			json:           "200",
			expectedResult: 200,
		},
		{
			name:           "basic-overflow",
			json:           "256",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-overflow",
			json:           "274",
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-big-overflow",
			json:           " 4294967298",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-big-overflow2",
			json:           "42949672983",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "invalid-json",
			json:           `123invalid`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*uint8)(nil)
			err := Unmarshal(json, &v)
			if testCase.err {
				assert.NotNil(t, err, "Err must not be nil")
				if testCase.errType != nil {
					assert.IsType(
						t,
						testCase.errType,
						err,
						fmt.Sprintf("err should be of type %s", reflect.TypeOf(err).String()),
					)
				}
				return
			}
			assert.Nil(t, err, "Err must be nil")
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(t, testCase.expectedResult, *v, fmt.Sprintf("v must be equal to %d", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(uint8)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(uint8)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.Uint8Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
