package gojay

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeInterfaceBasic(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  interface{}
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name:           "array",
			json:           `[1,2,3]`,
			expectedResult: []interface{}([]interface{}{float64(1), float64(2), float64(3)}),
			err:            false,
		},
		{
			name:           "object",
			json:           `{"testStr": "hello world!"}`,
			expectedResult: map[string]interface{}(map[string]interface{}{"testStr": "hello world!"}),
			err:            false,
		},
		{
			name:           "string",
			json:           `"hola amigos!"`,
			expectedResult: interface{}("hola amigos!"),
			err:            false,
		},
		{
			name:           "bool-true",
			json:           `true`,
			expectedResult: interface{}(true),
			err:            false,
		},
		{
			name:           "bool-false",
			json:           `false`,
			expectedResult: interface{}(false),
			err:            false,
		},
		{
			name:           "null",
			json:           `null`,
			expectedResult: interface{}(nil),
			err:            false,
		},
		{
			name:           "number",
			json:           `1234`,
			expectedResult: interface{}(float64(1234)),
			err:            false,
		},
		{
			name:            "array-error",
			json:            `["h""o","l","a"]`,
			err:             true,
			errType:         &json.SyntaxError{},
			skipCheckResult: true,
		},
		{
			name:            "object-error",
			json:            `{"testStr" "hello world!"}`,
			err:             true,
			errType:         &json.SyntaxError{},
			skipCheckResult: true,
		},
		{
			name:            "string-error",
			json:            `"hola amigos!`,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "bool-true-error",
			json:            `truee`,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "bool-false-error",
			json:            `fase`,
			expectedResult:  interface{}(false),
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "null-error",
			json:            `nulllll`,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "number-error",
			json:            `1234"`,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "unknown-error",
			json:            `?`,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
		{
			name:            "empty-json-error",
			json:            ``,
			err:             true,
			errType:         InvalidJSONError(""),
			skipCheckResult: true,
		},
	}

	for _, testCase := range testCases {
		t.Run("DecodeInterface()"+testCase.name, func(t *testing.T) {
			var i interface{}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.DecodeInterface(&i)
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
				assert.Equal(t, testCase.expectedResult, i, "value at given index should be the same as expected results")
			}
		})
	}

	for _, testCase := range testCases {
		t.Run("Decode()"+testCase.name, func(t *testing.T) {
			var i interface{}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.Decode(&i)
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
				assert.Equal(t, testCase.expectedResult, i, "value at given index should be the same as expected results")
			}
		})
	}
}

func TestDecodeInterfaceAsInterface(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  interface{}
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name: "basic-array",
			json: `{
        "testStr": "hola",
        "testInterface": ["h","o","l","a"]
      }`,
			expectedResult: map[string]interface{}(
				map[string]interface{}{
					"testStr":       "hola",
					"testInterface": []interface{}{"h", "o", "l", "a"},
				}),
			err: false,
		},
		{
			name: "basic-string",
			json: `{
        "testInterface": "漢字"
      }`,
			expectedResult: map[string]interface{}(
				map[string]interface{}{
					"testInterface": "漢字",
				}),
			err: false,
		},
		{
			name: "basic-error",
			json: `{
        "testInterface": ["a""d","i","o","s"]
      }`,
			err:             true,
			errType:         &json.SyntaxError{},
			skipCheckResult: true,
		},
		{
			name: "basic-interface",
			json: `{
        "testInterface": {
          "string": "prost"
        }
      }`,
			expectedResult: map[string]interface{}(
				map[string]interface{}{
					"testInterface": map[string]interface{}{"string": "prost"},
				}),
			err: false,
		},
		{
			name: "complex-interface",
			json: `{
        "testInterface": {
          "number": 1988,
          "string": "prost",
          "array": ["h","o","l","a"],
          "object": {
            "k": "v",
            "a": [1,2,3]
          },
          "array-of-objects": [
            {"k": "v"},
            {"a": "b"}
          ]
        }
      }`,
			expectedResult: map[string]interface{}(
				map[string]interface{}{
					"testInterface": map[string]interface{}{
						"array-of-objects": []interface{}{
							map[string]interface{}{"k": "v"},
							map[string]interface{}{"a": "b"},
						},
						"number": float64(1988),
						"string": "prost",
						"array":  []interface{}{"h", "o", "l", "a"},
						"object": map[string]interface{}{
							"k": "v",
							"a": []interface{}{float64(1), float64(2), float64(3)},
						},
					},
				}),
			err: false,
		},
	}

	for _, testCase := range testCases {
		t.Run("Decode()"+testCase.name, func(t *testing.T) {
			var s interface{}
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
		t.Run("DecodeInterface()"+testCase.name, func(t *testing.T) {
			var s interface{}
			dec := BorrowDecoder(strings.NewReader(testCase.json))
			defer dec.Release()
			err := dec.DecodeInterface(&s)
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

func TestDecodeAsTestObject(t *testing.T) {
	testCases := []struct {
		name            string
		json            string
		expectedResult  testObject
		err             bool
		errType         interface{}
		skipCheckResult bool
	}{
		{
			name: "basic-array",
			json: `{
        "testStr": "hola",
        "testInterface": ["h","o","l","a"]
      }`,
			expectedResult: testObject{
				testStr:       "hola",
				testInterface: []interface{}([]interface{}{"h", "o", "l", "a"}),
			},
			err: false,
		},
		{
			name: "basic-string",
			json: `{
        "testInterface": "漢字"
      }`,
			expectedResult: testObject{
				testInterface: interface{}("漢字"),
			},
			err: false,
		},
		{
			name: "basic-error",
			json: `{
        "testInterface": ["a""d","i","o","s"]
      }`,
			err:             true,
			errType:         &json.SyntaxError{},
			skipCheckResult: true,
		},
		{
			name: "mull-interface",
			json: `{
        "testInterface": null,
        "testStr": "adios"
      }`,
			expectedResult: testObject{
				testInterface: interface{}(nil),
				testStr:       "adios",
			},
			err: false,
		},
		{
			name: "basic-interface",
			json: `{
        "testInterface": {
          "string": "prost"
        },
      }`,
			expectedResult: testObject{
				testInterface: map[string]interface{}{"string": "prost"},
			},
			err: false,
		},
		{
			name: "complex-interface",
			json: `{
        "testInterface": {
          "number": 1988,
          "string": "prost",
          "array": ["h","o","l","a"],
          "object": {
            "k": "v",
            "a": [1,2,3]
          },
          "array-of-objects": [
            {"k": "v"},
            {"a": "b"}
          ]
        },
      }`,
			expectedResult: testObject{
				testInterface: map[string]interface{}{
					"array-of-objects": []interface{}{
						map[string]interface{}{"k": "v"},
						map[string]interface{}{"a": "b"},
					},
					"number": float64(1988),
					"string": "prost",
					"array":  []interface{}{"h", "o", "l", "a"},
					"object": map[string]interface{}{
						"k": "v",
						"a": []interface{}{float64(1), float64(2), float64(3)},
					},
				},
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

func TestUnmarshalInterface(t *testing.T) {
	json := []byte(`{
    "testInterface": {
      "number": 1988,
      "null": null,
      "string": "prost",
      "array": ["h","o","l","a"],
      "object": {
        "k": "v",
        "a": [1,2,3]
      },
      "array-of-objects": [
        {"k": "v"},
        {"a": "b"}
      ]
    }
	}`)
	v := &testObject{}
	err := Unmarshal(json, v)
	assert.Nil(t, err, "Err must be nil")
	expectedInterface := map[string]interface{}{
		"array-of-objects": []interface{}{
			map[string]interface{}{"k": "v"},
			map[string]interface{}{"a": "b"},
		},
		"number": float64(1988),
		"string": "prost",
		"null":   interface{}(nil),
		"array":  []interface{}{"h", "o", "l", "a"},
		"object": map[string]interface{}{
			"k": "v",
			"a": []interface{}{float64(1), float64(2), float64(3)},
		},
	}
	assert.Equal(t, expectedInterface, v.testInterface, "v.testInterface must be equal to the expected one")
}

func TestUnmarshalInterfaceError(t *testing.T) {
	testCases := []struct {
		name string
		json []byte
	}{
		{
			name: "basic",
			json: []byte(`{"testInterface": {"number": 1bc4}}`),
		},
		{
			name: "syntax",
			json: []byte(`{
        "testInterface": {
          "array?": [1,"a", ?]
        }
      }`),
		},
		{
			name: "complex",
			json: []byte(`{
        "testInterface": {
          "number": 1988,
          "string": "prost",
          "array": ["h""o","l","a"],
          "object": {
            "k": "v",
            "a": [1,2,3]
          },
          "array-of-objects": [
            {"k": "v"},
            {"a": "b"}
          ]
        }
      }`),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			v := &testObject{}
			err := Unmarshal(testCase.json, v)
			assert.NotNil(t, err, "Err must be not nil")
			t.Log(err)
			assert.IsType(t, &json.SyntaxError{}, err, "err should be a json.SyntaxError{}")
		})
	}
}

func TestDecodeInterfacePoolError(t *testing.T) {
	result := interface{}(1)
	dec := NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	_ = dec.DecodeInterface(&result)
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestDecodeNull(t *testing.T) {
	var i interface{}
	dec := BorrowDecoder(strings.NewReader("null"))
	defer dec.Release()
	err := dec.DecodeInterface(&i)
	assert.Nil(t, err, "err should be nil")
	assert.Equal(t, interface{}(nil), i, "value at given index should be the same as expected results")
}
