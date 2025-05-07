package gojay

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoderFloat64(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult float64
		skipResult     bool
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-float",
			json:           "1.1",
			expectedResult: 1.1,
		},
		{
			name:           "basic-exponent-positive-positive-exp",
			json:           "1e2",
			expectedResult: 100,
		},
		{
			name:           "basic-exponent-positive-positive-exp2",
			json:           "5e+06",
			expectedResult: 5000000,
		},
		{
			name:           "basic-exponent-positive-positive-exp3",
			json:           "3e+3",
			expectedResult: 3000,
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
			name:           "basic-negative-err",
			json:           "-",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative-err",
			json:           "-q",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-null-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-err1",
			json:           "0.",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-err2",
			json:           "-1.",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exponent-err-",
			json:           "0.1e",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exp-err",
			json:           "0e-20",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exp-err3",
			json:           "-9e-60",
			expectedResult: 0,
			err:            true,
		},
		{
			name:       "exp-err4",
			json:       "0.e-2",
			skipResult: true,
			err:        true,
		},
		{
			name:       "exp-err5",
			json:       "-5.E-2",
			skipResult: true,
			err:        true,
		},
		{
			name:           "basic-exponent-positive-positive-exp4",
			json:           "8e+005",
			expectedResult: 800000,
		},
		{
			name:           "basic-exponent-positive-negative-exp",
			json:           "1e-2",
			expectedResult: 0.01,
		},
		{
			name:           "basic-exponent-positive-negative-exp2",
			json:           "5e-6",
			expectedResult: 0.000005,
		},
		{
			name:           "basic-exponent-positive-negative-exp3",
			json:           "3e-3",
			expectedResult: 0.003,
		},
		{
			name:           "basic-exponent-positive-negative-exp4",
			json:           "8e-005",
			expectedResult: 0.00008,
		},
		{
			name:           "basic-exponent-negative-positive-exp",
			json:           "-1e2",
			expectedResult: -100,
		},
		{
			name:           "basic-exponent-negative-positive-exp2",
			json:           "-5e+06",
			expectedResult: -5000000,
		},
		{
			name:           "basic-exponent-negative-positive-exp3",
			json:           "-3e03",
			expectedResult: -3000,
		},
		{
			name:           "basic-float2",
			json:           "877 ",
			expectedResult: 877,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8e+005",
			expectedResult: -800000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8.2e-005",
			expectedResult: -0.000082,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2.4595,
		},
		{
			name:           "basic-float2",
			json:           "877",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: -7.8876,
		},
		{
			name:           "basic-float",
			json:           "2.4595e1",
			expectedResult: 24.595,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876e002",
			expectedResult: -788.76,
		},
		{
			name:           "basic-float3",
			json:           "-0.1234",
			expectedResult: -0.1234,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.002e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "0e9223372036000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "big float",
			json:           "1.00232492420002423545849009",
			expectedResult: 1.002325,
		},
		{
			name:           "big float",
			json:           "5620.1400000000003",
			expectedResult: 5620.14,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009e10000000000 ",
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
			name:           "exponent-err",
			json:           "0.1e",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exponent-err",
			json:           "0e",
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
		{
			name:           "big float",
			json:           "5620.1400000000003",
			expectedResult: 5620.1400000000003,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v float64
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
			if !testCase.skipResult {
				assert.Equal(t, math.Round(testCase.expectedResult*1000000), math.Round(v*1000000), fmt.Sprintf("v must be equal to %f", testCase.expectedResult))
			}
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := float64(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeFloat64(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v float64
		dec := NewDecoder(strings.NewReader(`1.25`))
		defer dec.Release()
		err := dec.DecodeFloat64(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, 1.25, v, "v must be equal to 1.25")
	})
	t.Run("decoder-api2", func(t *testing.T) {
		var v float64
		dec := NewDecoder(strings.NewReader(`1.25`))
		defer dec.Release()
		err := dec.DecodeFloat64(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, 1.25, v, "v must be equal to 1.25")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v float64
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeFloat64(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderFloat64Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult float64
		resultIsNil    bool
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-float",
			json:           "1.1",
			expectedResult: 1.1,
		},
		{
			name:           "basic-exponent-positive-positive-exp",
			json:           " 1e2",
			expectedResult: 100,
		},
		{
			name:           "basic-exponent-positive-positive-exp2",
			json:           "5e+06",
			expectedResult: 5000000,
		},
		{
			name:           "basic-exponent-positive-positive-exp3",
			json:           "3e+3",
			expectedResult: 3000,
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
			resultIsNil:    true,
		},
		{
			name:           "basic-negative-err",
			json:           "-",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-negative-err",
			json:           "-q",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-err1",
			json:           "0.",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-err2",
			json:           "-1.",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exponent-err-",
			json:           "0.1e",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exp-err",
			json:           "0e-20",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exp-err3",
			json:           "-9e-60",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:        "exp-err4",
			json:        "0.e-2",
			err:         true,
			resultIsNil: true,
		},
		{
			name:        "exp-err5",
			json:        "-5.E-2",
			err:         true,
			resultIsNil: true,
		},
		{
			name:           "basic-exponent-positive-positive-exp4",
			json:           "8e+005",
			expectedResult: 800000,
		},
		{
			name:           "basic-exponent-positive-negative-exp",
			json:           "1e-2",
			expectedResult: 0.01,
		},
		{
			name:           "basic-exponent-positive-negative-exp2",
			json:           "5e-6",
			expectedResult: 0.000005,
		},
		{
			name:           "basic-exponent-positive-negative-exp3",
			json:           "3e-3",
			expectedResult: 0.003,
		},
		{
			name:           "basic-exponent-positive-negative-exp4",
			json:           "8e-005",
			expectedResult: 0.00008,
		},
		{
			name:           "basic-exponent-negative-positive-exp",
			json:           "-1e2",
			expectedResult: -100,
		},
		{
			name:           "basic-exponent-negative-positive-exp2",
			json:           "-5e+06",
			expectedResult: -5000000,
		},
		{
			name:           "basic-exponent-negative-positive-exp3",
			json:           "-3e03",
			expectedResult: -3000,
		},
		{
			name:           "basic-float2",
			json:           "877 ",
			expectedResult: 877,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8e+005",
			expectedResult: -800000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8.2e-005",
			expectedResult: -0.000082,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2.4595,
		},
		{
			name:           "basic-float2",
			json:           "877",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: -7.8876,
		},
		{
			name:           "basic-float",
			json:           "2.4595e1",
			expectedResult: 24.595,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876e002",
			expectedResult: -788.76,
		},
		{
			name:           "basic-float3",
			json:           "-0.1234",
			expectedResult: -0.1234,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.002e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "0e9223372036000000000 ",
			expectedResult: 1,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009",
			expectedResult: 1.002325,
			resultIsNil:    false,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "exponent-err",
			json:           "0.1e ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exponent-err",
			json:           "0e",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
			resultIsNil:    true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*float64)(nil)
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
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(t, math.Round(testCase.expectedResult*1000000), math.Round(*v*1000000), fmt.Sprintf("v must be equal to %f", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(float64)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(float64)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.FloatNull(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(float64)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.AddFloat64Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderFloat32(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult float32
		skipResult     bool
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-float",
			json:           "1.1",
			expectedResult: 1.1,
		},
		{
			name:           "basic-exponent-positive-positive-exp",
			json:           "1e2",
			expectedResult: 100,
		},
		{
			name:           "basic-exponent-positive-positive-exp2",
			json:           "5e+06",
			expectedResult: 5000000,
		},
		{
			name:           "basic-exponent-positive-positive-exp3",
			json:           "3e+3",
			expectedResult: 3000,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-err1",
			json:           "0.",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-err2",
			json:           "-1.",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exp-err",
			json:           "0e-20",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "exp-err3",
			json:           "-9e-60",
			expectedResult: 0,
			err:            true,
		},
		{
			name: "exp-err4",
			json: "0.e-2",
			err:  true,
		},
		{
			name: "exp-err5",
			json: "-5.E-2",
			err:  true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
		},
		{
			name:           "basic-null-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-negative-err",
			json:           "-",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "exponent-err-",
			json:           "0.1e",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-negative-err",
			json:           "-q",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-exponent-positive-positive-exp4",
			json:           "8e+005",
			expectedResult: 800000,
		},
		{
			name:           "basic-exponent-positive-negative-exp",
			json:           "1e-2",
			expectedResult: 0.01,
		},
		{
			name:           "basic-exponent-positive-negative-exp2",
			json:           "5e-6",
			expectedResult: 0.000005,
		},
		{
			name:           "basic-exponent-positive-negative-exp3",
			json:           "3e-3",
			expectedResult: 0.003,
		},
		{
			name:           "basic-exponent-positive-negative-exp4",
			json:           "8e-005",
			expectedResult: 0.00008,
		},
		{
			name:           "basic-exponent-negative-positive-exp",
			json:           "-1e2",
			expectedResult: -100,
		},
		{
			name:           "basic-exponent-negative-positive-exp2",
			json:           "-5e+06",
			expectedResult: -5000000,
		},
		{
			name:           "basic-exponent-negative-positive-exp3",
			json:           "-3e03",
			expectedResult: -3000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8e+005",
			expectedResult: -800000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8.2e-005",
			expectedResult: -0.000082,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.0023249242000242e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.002e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009",
			expectedResult: 1.0023249,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009e10000000000 ",
			expectedResult: 0,
			err:            true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2.4595,
		},
		{
			name:           "basic-float2",
			json:           "877",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "877 ",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: -7.8876,
		},
		{
			name:           "basic-float",
			json:           "2.459e1",
			expectedResult: 24.59,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876e002",
			expectedResult: -788.76,
		},
		{
			name:           "basic-float3",
			json:           "-0.1234",
			expectedResult: -0.1234,
		},
		{
			name:           "float10-digit-decimal",
			json:           "0.9833984375",
			expectedResult: 0.9833984,
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
			name:           "exponent-err",
			json:           "0e",
			expectedResult: 0,
			err:            true,
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
			var v float32
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
			if !testCase.skipResult {
				assert.Equal(
					t,
					math.Round(float64(testCase.expectedResult*1000000)), math.Round(float64(v*1000000)),
					fmt.Sprintf("v must be equal to %f", testCase.expectedResult),
				)
			}
		})
	}
	t.Run("pool-error", func(t *testing.T) {
		result := float32(1)
		dec := NewDecoder(nil)
		dec.Release()
		defer func() {
			err := recover()
			assert.NotNil(t, err, "err shouldnt be nil")
			assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
		}()
		_ = dec.DecodeFloat32(&result)
		assert.True(t, false, "should not be called as decoder should have panicked")
	})
	t.Run("decoder-api", func(t *testing.T) {
		var v float32
		dec := NewDecoder(strings.NewReader(`1.25`))
		defer dec.Release()
		err := dec.DecodeFloat32(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, float32(1.25), v, "v must be equal to 1.25")
	})
	t.Run("decoder-api2", func(t *testing.T) {
		var v float32
		dec := NewDecoder(strings.NewReader(`1.25`))
		defer dec.Release()
		err := dec.Decode(&v)
		assert.Nil(t, err, "Err must be nil")
		assert.Equal(t, float32(1.25), v, "v must be equal to 1.25")
	})
	t.Run("decoder-api-json-error", func(t *testing.T) {
		var v float32
		dec := NewDecoder(strings.NewReader(``))
		defer dec.Release()
		err := dec.DecodeFloat32(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderFloat32Null(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult float32
		resultIsNil    bool
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-float",
			json:           "1.1",
			expectedResult: 1.1,
		},
		{
			name:           "basic-exponent-positive-positive-exp",
			json:           "1e2",
			expectedResult: 100,
		},
		{
			name:           "basic-exponent-positive-positive-exp2",
			json:           "5e+06 ",
			expectedResult: 5000000,
		},
		{
			name:           "basic-exponent-positive-positive-exp3",
			json:           " 3e+3",
			expectedResult: 3000,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-err1",
			json:           "0.",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-err2",
			json:           "-1.",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exp-err",
			json:           "0e-20",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "exp-err3",
			json:           "-9e-60",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:        "exp-err4",
			json:        "0.e-2",
			err:         true,
			resultIsNil: true,
		},
		{
			name:        "exp-err5",
			json:        "-5.E-2",
			err:         true,
			resultIsNil: true,
		},
		{
			name:           "basic-null",
			json:           "null",
			expectedResult: 0,
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "trua",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-null-err",
			json:           "nxll",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-negative-err",
			json:           "-",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "exponent-err-",
			json:           "0.1e",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-negative-err",
			json:           "-q",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "basic-exponent-positive-positive-exp4",
			json:           "8e+005",
			expectedResult: 800000,
		},
		{
			name:           "basic-exponent-positive-negative-exp",
			json:           " 1e-2",
			expectedResult: 0.01,
		},
		{
			name:           "basic-exponent-positive-negative-exp2",
			json:           "5e-6",
			expectedResult: 0.000005,
		},
		{
			name:           "basic-exponent-positive-negative-exp3",
			json:           "3e-3",
			expectedResult: 0.003,
		},
		{
			name:           "basic-exponent-positive-negative-exp4",
			json:           "8e-005",
			expectedResult: 0.00008,
		},
		{
			name:           "basic-exponent-negative-positive-exp",
			json:           "-1e2",
			expectedResult: -100,
		},
		{
			name:           "basic-exponent-negative-positive-exp2",
			json:           "-5e+06",
			expectedResult: -5000000,
		},
		{
			name:           "basic-exponent-negative-positive-exp3",
			json:           "-3e03",
			expectedResult: -3000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8e+005",
			expectedResult: -800000,
		},
		{
			name:           "basic-exponent-negative-positive-exp4",
			json:           "-8.2e-005",
			expectedResult: -0.000082,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.0023249242000242e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.002e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009",
			expectedResult: 1.0023249,
		},
		{
			name:           "basic-exp-too-big",
			json:           "1.00232492420002423545849009e10000000000 ",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "basic-float",
			json:           "2.4595",
			expectedResult: 2.4595,
		},
		{
			name:           "basic-float2",
			json:           "877",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "877 ",
			expectedResult: 877,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876",
			expectedResult: -7.8876,
		},
		{
			name:           "basic-float",
			json:           "2.459e1",
			expectedResult: 24.59,
		},
		{
			name:           "basic-float2",
			json:           "-7.8876e002",
			expectedResult: -788.76,
		},
		{
			name:           "basic-float3",
			json:           "-0.1234",
			expectedResult: -0.1234,
		},
		{
			name:           "error",
			json:           "83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "error",
			json:           "-83zez4",
			expectedResult: 0,
			err:            true,
			errType:        InvalidJSONError(""),
			resultIsNil:    true,
		},
		{
			name:           "exponent-err",
			json:           "0e",
			expectedResult: 0,
			err:            true,
			resultIsNil:    true,
		},
		{
			name:           "invalid-type",
			json:           `"string"`,
			expectedResult: 0,
			err:            true,
			errType:        InvalidUnmarshalError(""),
			resultIsNil:    true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v = (*float32)(nil)
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
			if testCase.resultIsNil {
				assert.Nil(t, v)
			} else {
				assert.Equal(
					t,
					math.Round(float64(testCase.expectedResult*1000000)), math.Round(float64(*v*1000000)),
					fmt.Sprintf("v must be equal to %f", testCase.expectedResult),
				)
			}
		})
	}
	t.Run("decoder-api-invalid-json", func(t *testing.T) {
		var v = new(float32)
		err := Unmarshal([]byte(``), &v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(float32)
		var dec = NewDecoder(strings.NewReader(``))
		err := dec.Float32Null(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderFloat64Field(t *testing.T) {
	var testCasesBasic = []struct {
		name  string
		json  string
		value float64
	}{
		{
			name:  "basic",
			json:  "[1]",
			value: float64(1),
		},
		{
			name:  "big",
			json:  "[0]",
			value: float64(0),
		},
	}
	for _, testCase := range testCasesBasic {
		t.Run(testCase.name, func(t *testing.T) {
			var dec = NewDecoder(strings.NewReader(testCase.json))
			var v float64
			dec.DecodeArray(DecodeArrayFunc(func(dec *Decoder) error {
				return dec.AddFloat64(&v)
			}))
			assert.Equal(t, testCase.value, v)
		})
	}
	var testCasesBasicAlt = []struct {
		name  string
		json  string
		value float64
	}{
		{
			name:  "basic",
			json:  "[1]",
			value: float64(1),
		},
		{
			name:  "big",
			json:  "[0]",
			value: float64(0),
		},
	}
	for _, testCase := range testCasesBasicAlt {
		t.Run(testCase.name, func(t *testing.T) {
			var dec = NewDecoder(strings.NewReader(testCase.json))
			var v float64
			dec.DecodeArray(DecodeArrayFunc(func(dec *Decoder) error {
				return dec.Float(&v)
			}))
			assert.Equal(t, testCase.value, v)
		})
	}
}
