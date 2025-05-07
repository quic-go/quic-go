package gojay

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoderString(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult string
		err            bool
		errType        interface{}
	}{
		{
			name:           "basic-string",
			json:           `"string"`,
			expectedResult: "string",
			err:            false,
		},
		{
			name:           "string-solidus",
			json:           `"\/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "basic-string",
			json:           ``,
			expectedResult: "",
			err:            false,
		},
		{
			name:           "basic-string",
			json:           `""`,
			expectedResult: "",
			err:            false,
		},
		{
			name:           "basic-string2",
			json:           `"hello world!"`,
			expectedResult: "hello world!",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\n"`,
			expectedResult: "\n",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\n"`,
			expectedResult: `\n`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\t"`,
			expectedResult: "\t",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\t"`,
			expectedResult: `\t`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\b"`,
			expectedResult: "\b",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\b"`,
			expectedResult: `\b`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\f"`,
			expectedResult: "\f",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\f"`,
			expectedResult: `\f`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\r"`,
			expectedResult: "\r",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "escape-control-char-solidus",
			json:           `"\/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "escape-control-char-solidus",
			json:           `"/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "escape-control-char-solidus-escape-char",
			json:           `"\\/"`,
			expectedResult: `\/`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\r"`,
			expectedResult: `\r`,
			err:            false,
		},
		{
			name:           "utf8",
			json:           `"𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏 𠳕 𠴕 𠵼 𠵿"`,
			expectedResult: "𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏 𠳕 𠴕 𠵼 𠵿",
			err:            false,
		},
		{
			name:           "utf8-code-point",
			json:           `"\u06fc"`,
			expectedResult: `ۼ`,
			err:            false,
		},
		{
			name:           "utf8-code-point-escaped",
			json:           `"\\u2070"`,
			expectedResult: `\u2070`,
			err:            false,
		},
		{
			name:           "utf8-code-point-err",
			json:           `"\u2Z70"`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\uDD1E"`,
			expectedResult: `𝄞`,
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\\"`,
			expectedResult: `�\`,
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\uD834"`,
			expectedResult: "�\x00\x00\x00",
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834"`,
			expectedResult: `�`,
			err:            false,
		},
		{
			name:           "utf16-surrogate-err",
			json:           `"\uD834\`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-err2",
			json:           `"\uD834\uDZ1E`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-err3",
			json:           `"\uD834`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\t"`,
			expectedResult: "�\t",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\n"`,
			expectedResult: "�\n",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\f"`,
			expectedResult: "�\f",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\b"`,
			expectedResult: "�\b",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\r"`,
			expectedResult: "�\r",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\h"`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "null",
			json:           `null`,
			expectedResult: "",
		},
		{
			name:           "null-err",
			json:           `nall`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "escape quote err",
			json:           `"test string \" escaped"`,
			expectedResult: `test string " escaped`,
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \t escaped"`,
			expectedResult: "test string \t escaped",
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \r escaped"`,
			expectedResult: "test string \r escaped",
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \b escaped"`,
			expectedResult: "test string \b escaped",
			err:            false,
		},
		{
			name:           "escape quote err",
			json:           `"test string \n escaped"`,
			expectedResult: "test string \n escaped",
			err:            false,
		},
		{
			name:           "escape quote err",
			json:           `"test string \\\" escaped`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "escape quote err",
			json:           `"test string \\\l escaped"`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-json",
			json:           `invalid`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "string-complex",
			json:           `  "string with spaces and \"escape\"d \"quotes\" and escaped line returns \n and escaped \\\\ escaped char"`,
			expectedResult: "string with spaces and \"escape\"d \"quotes\" and escaped line returns \n and escaped \\\\ escaped char",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			str := ""
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.Decode(&str)
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should of the given type")
				}
			} else {
				assert.Nil(t, err, "err should be nil")
			}
			assert.Equal(t, testCase.expectedResult, str, fmt.Sprintf("'%s' should be equal to expectedResult", str))
		})
	}
}
func TestDecoderStringNull(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult string
		err            bool
		errType        interface{}
		resultIsNil    bool
	}{
		{
			name:           "basic-string",
			json:           `"string"`,
			expectedResult: "string",
			err:            false,
		},
		{
			name:           "string-solidus",
			json:           `"\/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "basic-string",
			json:           ``,
			expectedResult: "",
			err:            false,
			resultIsNil:    true,
		},
		{
			name:           "basic-string",
			json:           `""`,
			expectedResult: "",
			err:            false,
		},
		{
			name:           "basic-string2",
			json:           `"hello world!"`,
			expectedResult: "hello world!",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\n"`,
			expectedResult: "\n",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\n"`,
			expectedResult: `\n`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\t"`,
			expectedResult: "\t",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\t"`,
			expectedResult: `\t`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\b"`,
			expectedResult: "\b",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\b"`,
			expectedResult: `\b`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\f"`,
			expectedResult: "\f",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\f"`,
			expectedResult: `\f`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\r"`,
			expectedResult: "\r",
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "escape-control-char-solidus",
			json:           `"\/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "escape-control-char-solidus",
			json:           `"/"`,
			expectedResult: "/",
			err:            false,
		},
		{
			name:           "escape-control-char-solidus-escape-char",
			json:           `"\\/"`,
			expectedResult: `\/`,
			err:            false,
		},
		{
			name:           "escape-control-char",
			json:           `"\\r"`,
			expectedResult: `\r`,
			err:            false,
		},
		{
			name:           "utf8",
			json:           `"𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏 𠳕 𠴕 𠵼 𠵿"`,
			expectedResult: "𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏 𠳕 𠴕 𠵼 𠵿",
			err:            false,
		},
		{
			name:           "utf8-code-point",
			json:           `"\u06fc"`,
			expectedResult: `ۼ`,
			err:            false,
		},
		{
			name:           "utf8-code-point-escaped",
			json:           `"\\u2070"`,
			expectedResult: `\u2070`,
			err:            false,
		},
		{
			name:           "utf8-code-point-err",
			json:           `"\u2Z70"`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\uDD1E"`,
			expectedResult: `𝄞`,
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\\"`,
			expectedResult: `�\`,
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834\uD834"`,
			expectedResult: "�\x00\x00\x00",
			err:            false,
		},
		{
			name:           "utf16-surrogate",
			json:           `"\uD834"`,
			expectedResult: `�`,
			err:            false,
		},
		{
			name:           "utf16-surrogate-err",
			json:           `"\uD834\`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-err2",
			json:           `"\uD834\uDZ1E`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-err3",
			json:           `"\uD834`,
			expectedResult: ``,
			err:            true,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\t"`,
			expectedResult: "�\t",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\n"`,
			expectedResult: "�\n",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\f"`,
			expectedResult: "�\f",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\b"`,
			expectedResult: "�\b",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\r"`,
			expectedResult: "�\r",
			err:            false,
		},
		{
			name:           "utf16-surrogate-followed-by-control-char",
			json:           `"\uD834\h"`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "null",
			json:           `null`,
			expectedResult: "",
			resultIsNil:    true,
		},
		{
			name:           "null-err",
			json:           `nall`,
			expectedResult: "",
			err:            true,
		},
		{
			name:           "escape quote err",
			json:           `"test string \" escaped"`,
			expectedResult: `test string " escaped`,
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \t escaped"`,
			expectedResult: "test string \t escaped",
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \r escaped"`,
			expectedResult: "test string \r escaped",
			err:            false,
		},
		{
			name:           "escape quote err2",
			json:           `"test string \b escaped"`,
			expectedResult: "test string \b escaped",
			err:            false,
		},
		{
			name:           "escape quote err",
			json:           `"test string \n escaped"`,
			expectedResult: "test string \n escaped",
			err:            false,
		},
		{
			name:           "escape quote err",
			json:           `"test string \\\" escaped`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "escape quote err",
			json:           `"test string \\\l escaped"`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "invalid-json",
			json:           `invalid`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "string-complex",
			json:           `  "string with spaces and \"escape\"d \"quotes\" and escaped line returns \n and escaped \\\\ escaped char"`,
			expectedResult: "string with spaces and \"escape\"d \"quotes\" and escaped line returns \n and escaped \\\\ escaped char",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			str := (*string)(nil)
			err := Unmarshal([]byte(testCase.json), &str)
			if testCase.err {
				assert.NotNil(t, err, "err should not be nil")
				if testCase.errType != nil {
					assert.IsType(t, testCase.errType, err, "err should of the given type")
				}
				return
			}
			assert.Nil(t, err, "Err must be nil")
			if testCase.resultIsNil {
				assert.Nil(t, str)
			} else {
				assert.Equal(t, testCase.expectedResult, *str, fmt.Sprintf("v must be equal to %s", testCase.expectedResult))
			}
		})
	}
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(string)
		var dec = NewDecoder(strings.NewReader(`a`))
		err := dec.StringNull(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}
func TestDecoderStringInvalidType(t *testing.T) {
	json := []byte(`1`)
	var v string
	err := Unmarshal(json, &v)
	assert.NotNil(t, err, "Err must not be nil as JSON is invalid")
	assert.IsType(t, InvalidUnmarshalError(""), err, "err message must be 'Invalid JSON'")
}

func TestDecoderStringDecoderAPI(t *testing.T) {
	var v string
	dec := NewDecoder(strings.NewReader(`"hello world!"`))
	defer dec.Release()
	err := dec.DecodeString(&v)
	assert.Nil(t, err, "Err must be nil")
	assert.Equal(t, "hello world!", v, "v must be equal to 'hello world!'")
}

func TestDecoderStringPoolError(t *testing.T) {
	// reset the pool to make sure it's not full
	decPool = sync.Pool{
		New: func() interface{} {
			return NewDecoder(nil)
		},
	}
	result := ""
	dec := NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	_ = dec.DecodeString(&result)
	assert.True(t, false, "should not be called as decoder should have panicked")
}

func TestDecoderSkipEscapedStringError(t *testing.T) {
	dec := NewDecoder(strings.NewReader(``))
	defer dec.Release()
	err := dec.skipEscapedString()
	assert.NotNil(t, err, "Err must be nil")
	assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
}

func TestDecoderSkipEscapedStringError2(t *testing.T) {
	dec := NewDecoder(strings.NewReader(`\"`))
	defer dec.Release()
	err := dec.skipEscapedString()
	assert.NotNil(t, err, "Err must be nil")
	assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
}

func TestDecoderSkipEscapedStringError3(t *testing.T) {
	dec := NewDecoder(strings.NewReader(`invalid`))
	defer dec.Release()
	err := dec.skipEscapedString()
	assert.NotNil(t, err, "Err must be nil")
	assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
}

func TestDecoderSkipEscapedStringError4(t *testing.T) {
	dec := NewDecoder(strings.NewReader(`\u12`))
	defer dec.Release()
	err := dec.skipEscapedString()
	assert.NotNil(t, err, "Err must be nil")
	assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
}

func TestDecoderSkipStringError(t *testing.T) {
	dec := NewDecoder(strings.NewReader(`invalid`))
	defer dec.Release()
	err := dec.skipString()
	assert.NotNil(t, err, "Err must be nil")
	assert.IsType(t, InvalidJSONError(""), err, "err must be of type InvalidJSONError")
}

func TestSkipString(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult string
		err            bool
		errType        interface{}
	}{
		{
			name:           "escape quote err",
			json:           `test string \\" escaped"`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "escape quote err",
			json:           `test string \\\l escaped"`,
			expectedResult: ``,
			err:            true,
			errType:        InvalidJSONError(""),
		},
		{
			name:           "string-solidus",
			json:           `Asia\/Bangkok","enable":true}"`,
			expectedResult: "",
			err:            false,
		},
		{
			name:           "string-unicode",
			json:           `[2]\u66fe\u5b97\u5357"`,
			expectedResult: "",
			err:            false,
		},
	}

	for _, testCase := range testCases {
		dec := NewDecoder(strings.NewReader(testCase.json))
		err := dec.skipString()
		if testCase.err {
			assert.NotNil(t, err, "err should not be nil")
			if testCase.errType != nil {
				assert.IsType(t, testCase.errType, err, "err should be of expected type")
			}
			return
		}
		assert.Nil(t, err, "err should be nil")
	}
}
