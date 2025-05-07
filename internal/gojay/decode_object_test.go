package gojay

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func makePointer(v interface{}) interface{} {
	var ptr = reflect.New(reflect.TypeOf(v))
	ptr.Elem().Set(reflect.ValueOf(v))
	return ptr.Interface()
}

func TestDecodeObjectBasic(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  testObject
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name: "basic",
			json: `{
						"testStr": "hello world!",
						"testStrNull":  "hello world!",
						"testInt": 4535,
						"testIntNull": 4535,
						"testBool": true,
						"testBoolNull": true,
						"testFloat32": 2.345,
						"testFloat32Null": 2.345,
						"testFloat64": 123.677,
						"testFloat64Null": 123.677,
						"testInt8": 23,
						"testInt8Null": 23,
						"testInt16": 1245,
						"testInt16Null": 1245,
						"testInt32": 456778,
						"testInt32Null": 456778,
						"testInt64": 1446685358,
						"testInt64Null": 1446685358,
						"testUint8": 255,
						"testUint8Null": 255,
						"testUint16": 3455,
						"testUint16Null": 3455,
						"testUint32": 343443,
						"testUint32Null": 343443,
						"testUint64": 545665757,
						"testUint64Null": 545665757,
						"testSubObjectNull": {
							"testStr": "1"
						}
					}`,
			expectedResult: testObject{
				testStr:         "hello world!",
				testStrNull:     makePointer("hello world!").(*string),
				testInt:         4535,
				testIntNull:     makePointer(4535).(*int),
				testBool:        true,
				testBoolNull:    makePointer(true).(*bool),
				testFloat32:     2.345,
				testFloat32Null: makePointer(float32(2.345)).(*float32),
				testFloat64:     123.677,
				testFloat64Null: makePointer(float64(123.677)).(*float64),
				testInt8:        23,
				testInt8Null:    makePointer(int8(23)).(*int8),
				testInt16:       1245,
				testInt16Null:   makePointer(int16(1245)).(*int16),
				testInt32:       456778,
				testInt32Null:   makePointer(int32(456778)).(*int32),
				testInt64:       1446685358,
				testInt64Null:   makePointer(int64(1446685358)).(*int64),
				testUint8:       255,
				testUint8Null:   makePointer(uint8(255)).(*uint8),
				testUint16:      3455,
				testUint16Null:  makePointer(uint16(3455)).(*uint16),
				testUint32:      343443,
				testUint32Null:  makePointer(uint32(343443)).(*uint32),
				testUint64:      545665757,
				testUint64Null:  makePointer(uint64(545665757)).(*uint64),
			},
			err: false,
		},
		{
			name: "basic-with-exponent",
			json: `{
						"testStr": "hello world!",
						"testInt": 3e3,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{
				testStr:     "hello world!",
				testInt:     3000,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
		{
			name: "basic-with-exponent3",
			json: `{
						"testStr": "hello world!",
						"testInt": 3e-3,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 12e-3,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{
				testStr:     "hello world!",
				testInt:     0,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 0.012,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
		{
			name:           "basic-err-invalid-type",
			json:           `1`,
			expectedResult: testObject{},
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-err-invalid-json",
			json:           `hello`,
			expectedResult: testObject{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-err-invalid-json",
			json:           `nall`,
			expectedResult: testObject{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-err-invalid-type",
			json:           ``,
			expectedResult: testObject{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name: "basic-err",
			json: `{
						"testStr": "hello world!",
						"testInt": 453q5,
						"testBool": trae,
						"testFloat32": 2q.345,
						"testFloat64": 12x3.677,
						"testInt8": 2s3,
						"testInt16": 1245,
						"testInt32": 4567q78,
						"testInt64": 14466e85358,
						"testUint8": 2s55,
						"testUint16": 345i5,
						"testUint32": 343q443,
						"testUint64": 5456657z57
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err2",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 4567x78,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-float32",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2q.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-float64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 1x23.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err3",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 2q3,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-int16",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1x245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-int64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446q685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-uint8",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 2x55,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-uint16",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3x455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-uint32",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 3x43443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-err-uint64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 5456x65757
					}`,
			expectedResult: testObject{},
			err:            true,
		},
		{
			name: "basic-skip-data",
			json: `{
				"testStr": "hello world!",
				"testInt": 4535,
				"testBool": true,
				"testFloat32": 2.345,
				"testFloat64": 123.677,
				"testInt8": 23,
				"skipObject": {
					"escapedString": "string with escaped \\n new line"
				},
				"testInt16": 1245,
				"testInt32": 456778,
				"testInt64": 1446685358,
				"testUint8": 255,
				"skipArray": [[],[],{}],
				"testUint16": 3455,
				"skipBool": true,
				"skipNull": null,
				"testUint32": 343443,
				"testUint64": 545665757,
				"skipString": "skipping string with escaped \\n new line",
				"skipInt": 3,
			}`,
			expectedResult: testObject{
				testStr:     "hello world!",
				testInt:     4535,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
		{
			name: "basic-skip-data-error-uint8-negative",
			json: `{
				"testStr": "hello world!",
				"testInt": 4535,
				"testBool": true,
				"testFloat32": 2.345,
				"testFloat64": 123.677,
				"testInt8": 23,
				"skipObject": {
					"escapedString": "string with escaped \\n new line"
				},
				"testInt16": 1245,
				"testInt32": 456778,
				"testInt64": 1446685358,
				"testUint8": -255,
				"skipArray": [[],[],{}],
				"testUint16": 3455,
				"skipBool": true,
				"skipNull": null,
				"testUint32": 343443,
				"testUint64": 545665757,
				"skipString": "skipping string with escaped \\n new line",
				"skipInt": 3
			}`,
			expectedResult: testObject{
				testStr:     "hello world!",
				testInt:     4535,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   0,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: true,
		},
		{
			name: "skip-data-with-unicode",
			json: `{
				"skipString": "hello\u1234\u2123",
				"testStr": "hello world!",
				"testInt": 4535,
				"testBool": true,
				"testFloat32": 2.345,
				"testFloat64": 123.677,
				"testInt8": 23,
				"skipObject": {
					"escapedString": "string with unicode \u1234\u1234\u1234"
				},
				"testInt16": 1245,
				"testInt32": 456778,
				"testInt64": 1446685358,
				"testUint8": 255,
				"skipArray": [[],[],{}],
				"testUint16": 3455,
				"skipBool": true,
				"skipNull": null,
				"testUint32": 343443,
				"testUint64": 545665757,
				"skipInt": 3
			}`,
			expectedResult: testObject{
				testStr:     "hello world!",
				testInt:     4535,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			s := testObject{}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.Decode(&s)
			if testCase.err {
				t.Log(err)
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should be of the given type")
				}
				return
			}
			assert.Nil(t, err, "err should be nil")
			if !testCase.skipCheckResult {
				assert.Equal(t, testCase.expectedResult, s, "value at given index should be the same as expected results")
			}
		})
	}
}

func TestDecodeObjectBasic0Keys(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  testObject0Keys
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name: "basic",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{
				testStr:     "hello world!",
				testInt:     4535,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
		{
			name:           "basic-err-invalid-type",
			json:           `1`,
			expectedResult: testObject0Keys{},
			err:            true,
			errType:        InvalidUnmarshalError(""),
		},
		{
			name:           "basic-err-invalid-json",
			json:           `hello`,
			expectedResult: testObject0Keys{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-err-invalid-json",
			json:           `nall`,
			expectedResult: testObject0Keys{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "basic-err-invalid-type",
			json:           ``,
			expectedResult: testObject0Keys{},
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name: "basic-err",
			json: `{
						"testStr": "hello world!",
						"testInt": 453q5,
						"testBool": trae,
						"testFloat32": 2q.345,
						"testFloat64": 12x3.677,
						"testInt8": 2s3,
						"testInt16": 1245,
						"testInt32": 4567q78,
						"testInt64": 14466e85358,
						"testUint8": 2s55,
						"testUint16": 345i5,
						"testUint32": 343q443,
						"testUint64": 5456657z57
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err2",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 4567x78,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-float32",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2q.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-float64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 1x23.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err3",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 2q3,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-int16",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1x245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-int64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446q685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-uint8",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 2x55,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-uint16",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3x455,
						"testUint32": 343443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-uint32",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 3x43443,
						"testUint64": 545665757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-err-uint64",
			json: `{
						"testStr": "hello world!",
						"testInt": 4535,
						"testBool": true,
						"testFloat32": 2.345,
						"testFloat64": 123.677,
						"testInt8": 23,
						"testInt16": 1245,
						"testInt32": 456778,
						"testInt64": 1446685358,
						"testUint8": 255,
						"testUint16": 3455,
						"testUint32": 343443,
						"testUint64": 5456x65757
					}`,
			expectedResult: testObject0Keys{},
			err:            true,
		},
		{
			name: "basic-skip-data",
			json: `{
				"testStr": "hello world!",
				"testInt": 4535,
				"testBool": true,
				"testFloat32": 2.345,
				"testFloat64": 123.677,
				"testInt8": 23,
				"skipObject": {
					"escapedString": "string with escaped \\n new line"
				},
				"testInt16": 1245,
				"testInt32": 456778,
				"testInt64": 1446685358,
				"testUint8": 255,
				"skipArray": [[],[],{}],
				"testUint16": 3455,
				"skipBool": true,
				"skipNull": null,
				"testUint32": 343443,
				"testUint64": 545665757,
				"skipString": "skipping string with escaped \\n new line",
				"skipInt": 3,
			}`,
			expectedResult: testObject0Keys{
				testStr:     "hello world!",
				testInt:     4535,
				testBool:    true,
				testFloat32: 2.345,
				testFloat64: 123.677,
				testInt8:    23,
				testInt16:   1245,
				testInt32:   456778,
				testInt64:   1446685358,
				testUint8:   255,
				testUint16:  3455,
				testUint32:  343443,
				testUint64:  545665757,
			},
			err: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			s := testObject0Keys{}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.Decode(&s)
			if testCase.err {
				t.Log(err)
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should be of the given type")
				}
				return
			}
			assert.Nil(t, err, "err should be nil")
			if !testCase.skipCheckResult {
				assert.Equal(t, testCase.expectedResult, s, "value at given index should be the same as expected results")
			}
		})
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			s := testObject0Keys{}
			err := UnmarshalJSONObject([]byte(testCase.json), &s)
			if testCase.err {
				t.Log(err)
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should be of the given type")
				}
				return
			}
			assert.Nil(t, err, "err should be nil")
			if !testCase.skipCheckResult {
				assert.Equal(t, testCase.expectedResult, s, "value at given index should be the same as expected results")
			}
		})
	}
}

type ObjectNull struct {
	SubObject *ObjectNull
	SubArray  *testSliceBools
}

func (o *ObjectNull) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "subobject":
		return dec.ObjectNull(&o.SubObject)
	case "subarray":
		return dec.AddArrayNull(&o.SubArray)
	}
	return nil
}

func (o *ObjectNull) NKeys() int {
	return 2
}

type ObjectNullZeroNKeys struct {
	SubObject *ObjectNullZeroNKeys
	SubArray  *testSliceBools
}

func (o *ObjectNullZeroNKeys) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "subobject":
		return dec.AddObjectNull(&o.SubObject)
	case "subarray":
		return dec.AddArrayNull(&o.SubArray)
	}
	return nil
}

func (o *ObjectNullZeroNKeys) NKeys() int {
	return 0
}

func TestDecodeObjectNull(t *testing.T) {
	t.Run("sub obj should not be nil", func(t *testing.T) {
		var o = &ObjectNull{}
		var err = UnmarshalJSONObject([]byte(`{"subobject": {},"subarray":[true]}`), o)
		assert.Nil(t, err)
		assert.NotNil(t, o.SubObject)
		assert.NotNil(t, o.SubArray)
	})
	t.Run("sub obj and sub array should be nil", func(t *testing.T) {
		var o = &ObjectNull{}
		var err = UnmarshalJSONObject([]byte(`{"subobject": null,"subarray": null}`), o)
		assert.Nil(t, err)
		assert.Nil(t, o.SubObject)
		assert.Nil(t, o.SubArray)
	})
	t.Run(
		"sub obj should not be be nil",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":{"subobject":{}}}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.Nil(t, err)
			assert.NotNil(t, o.SubObject)
		},
	)
	t.Run(
		"sub obj should be nil",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":null}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.Nil(t, err)
			assert.Nil(t, o.SubObject)
		},
	)
	t.Run(
		"skip data",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobject": {},
					"subarray": [],
					"subarray": [],
					"skipped": ""
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.Nil(t, err)
			assert.NotNil(t, o.SubObject)
			assert.Nil(t, o.SubArray)
		},
	)
	t.Run(
		"skip data not child",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var dec = NewDecoder(strings.NewReader(`{
					"subobject": {},
					"subarray": [],
					"subarray": [],
					"skipped": ""
			}`))
			var _, err = dec.decodeObjectNull(&o)
			assert.Nil(t, err)
			assert.NotNil(t, o.SubObject)
		},
	)
	t.Run(
		"err empty json",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var dec = NewDecoder(strings.NewReader(``))
			var _, err = dec.decodeObjectNull(&o)
			assert.NotNil(t, err)
		},
	)
	t.Run(
		"should return an error as type is not ptr",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":{}}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull("")
			}))
			assert.NotNil(t, err)
			assert.Equal(t, ErrUnmarshalPtrExpected, err)
		},
	)
	t.Run(
		"should return an error as type is not ptr",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":[]}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ArrayNull("")
			}))
			assert.NotNil(t, err)
			assert.Equal(t, ErrUnmarshalPtrExpected, err)
		},
	)
	t.Run(
		"should return an error as type is not ptr to UnmarshalerJSONObject",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":{}}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ObjectNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidUnmarshalError(""), err)
		},
	)
	t.Run(
		"should return an error as type is not ptr to UnmarshalerJSONObject",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":[]}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ArrayNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidUnmarshalError(""), err)
		},
	)
	t.Run(
		"should return an error as type is not ptr to UnmarshalerJSONObject",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":{}}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ArrayNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidUnmarshalError(""), err)
		},
	)
	t.Run(
		"should return an error as type is not ptr to UnmarshalerJSONObject",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":"`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ArrayNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"skip data",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key": ""}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ObjectNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidUnmarshalError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":{"subobject":{"a":a}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":{"subobject":a}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":{"subobject":{"sub}}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &testSliceBools{}
			var err = UnmarshalJSONObject([]byte(`{"subobject":a`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ArrayNull(&o)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"key":a`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var strPtr = new(string)
				return dec.ObjectNull(&strPtr)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var err = UnmarshalJSONObject([]byte(`{"subobject": {},"}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				var o = &ObjectNull{}
				return dec.ObjectNull(&o)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject": a`), o)
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"invalid JSON for object",
		func(t *testing.T) {
			var o = &ObjectNull{}
			var err = UnmarshalJSONObject([]byte(`{"subobject": na`), o)
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"zero nkeys, no error, two keys",
		func(t *testing.T) {
			var o = &ObjectNullZeroNKeys{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobject": {
						"subobject":{}
					},
					"subarray": []
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.Nil(t, err)
		},
	)
	t.Run(
		"zero nkeys, no error, two keys, skip data",
		func(t *testing.T) {
			var o = &ObjectNullZeroNKeys{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobject": {
						"subobject":{}
					},
					"subarray": [],
					"skipped": 1
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.Nil(t, err)
		},
	)
	t.Run(
		"zero nkeys, error skip data",
		func(t *testing.T) {
			var o = &ObjectNullZeroNKeys{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobject": {
						"subobject":{}
					},
					"subarray": [],
					"skippedInvalid": "q
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"zero nkeys, error invalid json in keys",
		func(t *testing.T) {
			var o = &ObjectNullZeroNKeys{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobj
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
	t.Run(
		"zero nkeys, error invalid json, sub object",
		func(t *testing.T) {
			var o = &ObjectNullZeroNKeys{}
			var err = UnmarshalJSONObject([]byte(`{
				"subobject": {
					"subobject": {
						"subobj
					}	
				}
			}`), DecodeObjectFunc(func(dec *Decoder, k string) error {
				return dec.ObjectNull(&o.SubObject)
			}))
			assert.NotNil(t, err)
			assert.IsType(t, InvalidJSONError(""), err)
		},
	)
}

func TestDecodeObjectComplex(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  testObjectComplex
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name: "basic",
			json: `{
				"testSubObject": {},
				"testSubSliceInts": [1,2]
			}`,
			expectedResult: testObjectComplex{
				testSubObject:    &testObject{},
				testSubSliceInts: &testSliceInts{1, 2},
			},
			err: false,
		},
		{
			name: "complex",
			json: `{
				"testSubObject": {
					"testStr": "some string",
					"testInt":124465,
					"testUint16":120,
					"testUint8":15,
					"testInt16":-135,
					"testInt8":-23
				},
				"testSubSliceInts": [1,2,3,4,5],
				"testStr": "some \n string"
			}`,
			expectedResult: testObjectComplex{
				testSubObject: &testObject{
					testStr:    "some string",
					testInt:    124465,
					testUint16: 120,
					testUint8:  15,
					testInt16:  -135,
					testInt8:   -23,
				},
				testSubSliceInts: &testSliceInts{1, 2, 3, 4, 5},
				testStr:          "some \n string",
			},
			err: false,
		},
		{
			name: "complex-json-err",
			json: `{"testSubObject":{"testStr":"some string,"testInt":124465,"testUint16":120, "testUint8":15,"testInt16":-135,"testInt8":-23},"testSubSliceInts":[1,2],"testStr":"some \n string"}`,
			expectedResult: testObjectComplex{
				testSubObject: &testObject{},
			},
			err: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			s := testObjectComplex{
				testSubObject:    &testObject{},
				testSubSliceInts: &testSliceInts{},
			}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.Decode(&s)
			if testCase.err {
				t.Log(err)
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should be of the given type")
				}
				return
			}
			assert.Nil(t, err, "err should be nil")
			if !testCase.skipCheckResult {
				assert.Equal(t, testCase.expectedResult, s, "value at given index should be the same as expected results")
			}
		})
	}
}

func assertResult(t *testing.T, v *TestObj, err error) {
	assert.Nil(t, err, "Err must be nil")
	assert.Equal(t, 245, v.test, "v.test must be equal to 245")
	assert.Equal(t, 246, v.test2, "v.test2 must be equal to 246")
	assert.Equal(t, "string", v.test3, "v.test3 must be equal to 'string'")
	assert.Equal(t, "complex string with spaces and some slashes\"", v.test4, "v.test4 must be equal to 'string'")
	assert.Equal(t, -1.15657654376543, v.test5, "v.test5 must be equal to 1.15")
	assert.Len(t, v.testArr, 2, "v.testArr must be of len 2")

	assert.Equal(t, 121, v.testSubObj.test3, "v.testSubObj.test3 must be equal to 121")
	assert.Equal(t, 122, v.testSubObj.test4, "v.testSubObj.test4 must be equal to 122")
	assert.Equal(t, "string", v.testSubObj.test5, "v.testSubObj.test5 must be equal to 'string'")
	assert.Equal(t, 150, v.testSubObj.testSubSubObj.test3, "v.testSubObj.testSubSubObj.test3 must be equal to 150")
	assert.Equal(t, 150, v.testSubObj.testSubSubObj2.test3, "v.testSubObj.testSubSubObj2.test3 must be equal to 150")

	assert.Equal(t, 122, v.testSubObj2.test3, "v.testSubObj2.test3 must be equal to 121")
	assert.Equal(t, 123, v.testSubObj2.test4, "v.testSubObj2.test4 must be equal to 122")
	assert.Equal(t, "string", v.testSubObj2.test5, "v.testSubObj2.test5 must be equal to 'string'")
	assert.Equal(t, 151, v.testSubObj2.testSubSubObj.test3, "v.testSubObj2.testSubSubObj.test must be equal to 150")
}

func TestDecoderObject(t *testing.T) {
	json := []byte(`{
		"test": 245,
		"test2": 246,
		"test3": "string",
		"test4": "complex string with spaces and some slashes\"",
		"test5": -1.15657654376543,
		"testNull": null,
		"testArr": [
			{
				"test": 245,
				"test2": 246
			},
			{
				"test": 245,
				"test2": 246
			}
		],
		"testSubObj": {
			"test": 121,
			"test2": 122,
			"testNull": null,
			"testSubSubObj": {
				"test": 150,
				"testNull": null
			},
			"testSubSubObj2": {
				"test": 150
			},
			"test3": "string"
			"testNull": null,
		},
		"testSubObj2": {
			"test": 122,
			"test3": "string"
			"testSubSubObj": {
				"test": 151
			},
			"test2": 123
		}
	}`)
	v := &TestObj{}
	err := Unmarshal(json, v)
	assertResult(t, v, err)
}

func TestDecodeObjectJSONNull(t *testing.T) {
	json := []byte(`null`)
	v := &TestObj{}
	err := Unmarshal(json, v)
	assert.Nil(t, err, "Err must be nil")
	assert.Equal(t, v.test, 0, "v.test must be 0 val")
}

var jsonComplex = []byte(`{
	"test": "{\"test\":\"1\",\"test1\":2}",
	"test2\n": "\\\\\\\\\n",
	"testArrSkip": ["testString with escaped \\\" quotes"],
	"testSkipString": "skip \\ string with \n escaped char \" ",
	"testSkipObject": {
		"testSkipSubObj": {
			"test": "test"
		}
	},
	"testSkipNumber": 123.23,
	"testSkipNumber2": 123.23 ,
	"testBool": true,
	"testSkipBoolTrue": true,
	"testSkipBoolFalse": false,
	"testSkipBoolNull": null,
	"testSub": {
		"test": "{\"test\":\"1\",\"test1\":2}",
		"test2\n": "[1,2,3]",
		"test3": 1,
		"testObjSkip": {
			"test": "test string with escaped \" quotes"
		},
		"testStrSkip" : "test"
	},
	"testBoolSkip": false,
	"testObjInvalidType": "somestring",
	"testArrSkip2": [[],["someString"]],
	"test3": 1
}`)

type jsonObjectComplex struct {
	Test               string
	Test2              string
	Test3              int
	Test4              bool
	testSub            *jsonObjectComplex
	testObjInvalidType *jsonObjectComplex
}

func (j *jsonObjectComplex) UnmarshalJSONObject(dec *Decoder, key string) error {
	switch key {
	case "test":
		return dec.AddString(&j.Test)
	case "test2\n":
		return dec.AddString(&j.Test2)
	case "test3":
		return dec.AddInt(&j.Test3)
	case "testBool":
		return dec.AddBool(&j.Test4)
	case "testSub":
		j.testSub = &jsonObjectComplex{}
		return dec.AddObject(j.testSub)
	case "testObjInvalidType":
		j.testObjInvalidType = &jsonObjectComplex{}
		return dec.AddObject(j.testObjInvalidType)
	}
	return nil
}

func (j *jsonObjectComplex) NKeys() int {
	return 6
}

func TestDecodeObjComplex(t *testing.T) {
	result := jsonObjectComplex{}
	err := UnmarshalJSONObject(jsonComplex, &result)
	assert.NotNil(t, err, "err should not be as invalid type as been encountered nil")
	assert.Equal(t, `Cannot unmarshal JSON to type '*gojay.jsonObjectComplex'`, err.Error(), "err should not be as invalid type as been encountered nil")
	assert.Equal(t, `{"test":"1","test1":2}`, result.Test, "result.Test is not expected value")
	assert.Equal(t, "\\\\\\\\\n", result.Test2, "result.Test2 is not expected value")
	assert.Equal(t, 1, result.Test3, "result.test3 is not expected value")
	assert.Equal(t, `{"test":"1","test1":2}`, result.testSub.Test, "result.testSub.test is not expected value")
	assert.Equal(t, `[1,2,3]`, result.testSub.Test2, "result.testSub.test2 is not expected value")
	assert.Equal(t, 1, result.testSub.Test3, "result.testSub.test3 is not expected value")
	assert.Equal(t, true, result.Test4, "result.Test4 is not expected value, should be true")
}

type jsonDecodePartial struct {
	Test  string
	Test2 string
}

func (j *jsonDecodePartial) UnmarshalJSONObject(dec *Decoder, key string) error {
	switch key {
	case "test":
		return dec.AddString(&j.Test)
	case `test2`:
		return dec.AddString(&j.Test2)
	}
	return nil
}

func (j *jsonDecodePartial) NKeys() int {
	return 2
}

func TestDecodeObjectPartial(t *testing.T) {
	result := jsonDecodePartial{}
	dec := NewDecoder(nil)
	dec.data = []byte(`{
		"test": "test",
		"test2": "test",
		"testArrSkip": ["test"],
		"testSkipString": "test",
		"testSkipNumber": 123.23
	}`)
	dec.length = len(dec.data)
	err := dec.DecodeObject(&result)
	assert.Nil(t, err, "err should be nil")
	assert.NotEqual(t, len(dec.data), dec.cursor)
}

func TestDecoderObjectInvalidJSON(t *testing.T) {
	result := jsonDecodePartial{}
	dec := NewDecoder(nil)
	dec.data = []byte(`{
		"test2": "test",
		"testArrSkip": ["test"],
		"testSkipString": "testInvalidJSON\\\\
	}`)
	dec.length = len(dec.data)
	err := dec.DecodeObject(&result)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidJSONError(""), err, "err message must be 'Invalid JSON'")
}

type myMap map[string]string

func (m myMap) UnmarshalJSONObject(dec *Decoder, k string) error {
	str := ""
	err := dec.AddString(&str)
	if err != nil {
		return err
	}
	m[k] = str
	return nil
}

// return 0 to parse all keys
func (m myMap) NKeys() int {
	return 0
}

func TestDecoderObjectMap(t *testing.T) {
	json := `{
		"test": "string",
		"test2": "string",
		"test3": "string",
		"test4": "string",
		"test5": "string",
	}`
	m := myMap(make(map[string]string))
	dec := BorrowDecoder(strings.NewReader(json))
	err := dec.Decode(m)

	assert.Nil(t, err, "err should be nil")
	assert.Len(t, m, 5, "len of m should be 5")
}

func TestDecoderObjectDecoderAPI(t *testing.T) {
	json := `{
		"test": 245,
		"test2": 246,
		"test3": "string",
		"test4": "complex string with spaces and some slashes\"",
		"test5": -1.15657654376543,
		"testNull": null,
		"testArr": [
			{
				"test": 245,
				"test2": 246
			},
			{
				"test": 245,
				"test2": 246
			}
		],
		"testSubObj": {
			"test": 121,
			"test2": 122,
			"testNull": null,
			"testSubSubObj": {
				"test": 150,
				"testNull": null
			},
			"testSubSubObj2": {
				"test": 150
			},
			"test3": "string"
			"testNull": null,
		},
		"testSubObj2": {
			"test": 122,
			"test3": "string"
			"testSubSubObj": {
				"test": 151
			},
			"test2": 123
		}
	}`
	v := &TestObj{}
	dec := NewDecoder(strings.NewReader(json))
	err := dec.DecodeObject(v)
	assertResult(t, v, err)
}

type ReadCloser struct {
	json []byte
}

func (r *ReadCloser) Read(b []byte) (int, error) {
	copy(b, r.json)
	return len(r.json), io.EOF
}

func TestDecoderObjectDecoderAPIReadCloser(t *testing.T) {
	readCloser := ReadCloser{
		json: []byte(`{
			"test": "string",
			"test2": "string",
			"test3": "string",
			"test4": "string",
			"test5": "string",
		}`),
	}
	m := myMap(make(map[string]string))
	dec := NewDecoder(&readCloser)
	err := dec.DecodeObject(m)
	assert.Nil(t, err, "err should be nil")
	assert.Len(t, m, 5, "len of m should be 5")
}

func TestDecoderObjectDecoderAPIFuncReadCloser(t *testing.T) {
	readCloser := ReadCloser{
		json: []byte(`{
			"test": "string",
			"test2": "string",
			"test3": "string",
			"test4": "string",
			"test5": "string",
		}`),
	}
	m := myMap(make(map[string]string))
	dec := NewDecoder(&readCloser)
	err := dec.DecodeObject(DecodeObjectFunc(func(dec *Decoder, k string) error {
		str := ""
		err := dec.AddString(&str)
		if err != nil {
			return err
		}
		m[k] = str
		return nil
	}))
	assert.Nil(t, err, "err should be nil")
	assert.Len(t, m, 5, "len of m should be 5")
}

func TestDecoderObjectDecoderInvalidJSONError(t *testing.T) {
	v := &TestObj{}
	dec := NewDecoder(strings.NewReader(`{"err:}`))
	err := dec.DecodeObject(v)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidJSONError(""), err, "err message must be 'Invalid JSON'")
}

func TestDecoderObjectDecoderInvalidJSONError2(t *testing.T) {
	v := &TestSubObj{}
	dec := NewDecoder(strings.NewReader(`{"err:}`))
	err := dec.DecodeObject(v)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidJSONError(""), err, "err message must be 'Invalid JSON'")
}

func TestDecoderObjectDecoderInvalidJSONError3(t *testing.T) {
	v := &TestSubObj{}
	dec := NewDecoder(strings.NewReader(`{"err":"test}`))
	err := dec.DecodeObject(v)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidJSONError(""), err, "err message must be 'Invalid JSON'")
}

func TestDecoderObjectDecoderInvalidJSONError4(t *testing.T) {
	testArr := testSliceInts{}
	dec := NewDecoder(strings.NewReader(`hello`))
	err := dec.DecodeArray(&testArr)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidJSONError(""), err, "err message must be 'Invalid JSON'")
}

func TestDecoderObjectPoolError(t *testing.T) {
	result := jsonDecodePartial{}
	dec := NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	_ = dec.DecodeObject(&result)
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestNextKey(t *testing.T) {
	testCases := []struct {
		name          string
		json          string
		expectedValue string
		err           bool
	}{
		{
			name:          "basic",
			json:          `"key":"value"`,
			expectedValue: "key",
		},
		{
			name:          "basic-err",
			json:          ``,
			expectedValue: "",
			err:           true,
		},
		{
			name:          "basic-err2",
			json:          `"key"`,
			expectedValue: "",
			err:           true,
		},
		{
			name:          "basic-err3",
			json:          `"key`,
			expectedValue: "",
			err:           true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			s, _, err := dec.nextKey()
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
				return
			}
			assert.Nil(t, err, "err should be nil")
			assert.Equal(t, testCase.expectedValue, s, fmt.Sprintf("s should be '%s'", testCase.expectedValue))
		})
	}
}

func TestSkipObject(t *testing.T) {
	testCases := []struct {
		name string
		json string
		err  bool
	}{
		{
			name: "basic",
			json: `"key":"value"}`,
		},
		{
			name: "basic-escape-solidus",
			json: `"key":"value\/solidus"}`,
		},
		{
			name: "basic-escaped",
			json: `"key":"value\\\\\\\" hello"}`,
		},
		{
			name: "basic-escaped",
			json: `"key":"value\\\\\\\\"}`,
		},
		{
			name: "basic-err",
			json: ``,
			err:  true,
		},
		{
			name: "basic-err2",
			json: `{"key":"value"`,
			err:  true,
		},
		{
			name: "basic-err2",
			json: `"key":"value\n"}`,
			err:  false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			_, err := dec.skipObject()
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
				return
			}
			assert.Nil(t, err, "err should be nil")
		})
	}
}

func TestSkipData(t *testing.T) {
	testCases := []struct {
		name string
		err  bool
		json string
	}{
		{
			name: "skip-bool-false-err",
			json: `fulse`,
			err:  true,
		},
		{
			name: "skip-bool-true-err",
			json: `trou`,
			err:  true,
		},
		{
			name: "skip-bool-null-err",
			json: `nil`,
			err:  true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.skipData()
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
			} else {
				assert.Nil(t, err, "err should be nil")
			}
		})
	}
	t.Run("error-invalid-json", func(t *testing.T) {
		dec := NewDecoder(strings.NewReader(""))
		err := dec.skipData()
		assert.NotNil(t, err, "err should not be nil as data is empty")
		assert.IsType(t, InvalidJSONError(""), err, "err should of type InvalidJSONError")
	})
	t.Run("skip-array-error-invalid-json", func(t *testing.T) {
		dec := NewDecoder(strings.NewReader(""))
		_, err := dec.skipArray()
		assert.NotNil(t, err, "err should not be nil as data is empty")
		assert.IsType(t, InvalidJSONError(""), err, "err should of type InvalidJSONError")
	})
}
