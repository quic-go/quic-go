package gojay

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoderBool(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult bool
		expectations   func(t *testing.T, v bool, err error)
	}{
		{
			name: "true-basic",
			json: "true",
			expectations: func(t *testing.T, v bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.True(t, v, "result should be true")
			},
		},
		{
			name: "false-basic",
			json: "false",
			expectations: func(t *testing.T, v bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-basic",
			json: "null",
			expectations: func(t *testing.T, v bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error",
			json: "taue",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error2",
			json: "trae",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error3",
			json: "trua",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error4",
			json: "truea",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error5",
			json: "t",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "true-error6",
			json: "a",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error",
			json: "fulse",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error2",
			json: "fause",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error3",
			json: "falze",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error4",
			json: "falso",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error5",
			json: "falsea",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error6",
			json: "f",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "false-error7",
			json: "a",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error",
			json: "nall",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error2",
			json: "nual",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error3",
			json: "nula",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error4",
			json: "nulle",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error5",
			json: "n",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-error6",
			json: "a",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-skip",
			json: "{}",
			expectations: func(t *testing.T, v bool, err error) {
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUnmarshalError(""), err, "err should be of type InvalidUnmarshalError")
				assert.False(t, v, "result should be false")
			},
		},
		{
			name: "null-skip",
			json: "",
			expectations: func(t *testing.T, v bool, err error) {
				assert.Nil(t, err, "err should not be nil")
				assert.False(t, v, "result should be false")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			json := []byte(testCase.json)
			var v bool
			err := Unmarshal(json, &v)
			testCase.expectations(t, v, err)
		})
	}
}

func TestDecoderBoolNull(t *testing.T) {
	testCases := []struct {
		name           string
		json           string
		expectedResult bool
		expectations   func(t *testing.T, v *bool, err error)
	}{
		{
			name: "true-basic",
			json: "true",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.True(t, *v, "result should be true")
			},
		},
		{
			name: "false-basic",
			json: "false",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.False(t, *v, "result should be false")
			},
		},
		{
			name: "null-basic",
			json: "null",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.Nil(t, err, "err should be nil")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "true-error",
			json: "taue",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be false")
			},
		},
		{
			name: "true-error2",
			json: "trae",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "true-error3",
			json: "trua",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "true-error4",
			json: "truea",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "true-error5",
			json: "t",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "true-error6",
			json: "a",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error",
			json: "fulse",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error2",
			json: "fause",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error3",
			json: "falze",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error4",
			json: "falso",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error5",
			json: "falsea",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error6",
			json: "f",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "false-error7",
			json: "a",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error",
			json: "nall",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error2",
			json: "nual",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error3",
			json: "nula",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error4",
			json: "nulle",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error5",
			json: "n",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-error6",
			json: "a",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should be nil")
				assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-skip",
			json: "{}",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.NotNil(t, err, "err should not be nil")
				assert.IsType(t, InvalidUnmarshalError(""), err, "err should be of type InvalidUnmarshalError")
				assert.Nil(t, v, "result should be nil")
			},
		},
		{
			name: "null-skip",
			json: "",
			expectations: func(t *testing.T, v *bool, err error) {
				assert.Nil(t, err, "err should not be nil")
				assert.Nil(t, v, "result should be nil")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var v = struct {
				b *bool
			}{}
			err := Unmarshal([]byte(testCase.json), &v.b)
			testCase.expectations(t, v.b, err)
		})
	}
	t.Run("decoder-api-invalid-json2", func(t *testing.T) {
		var v = new(bool)
		var dec = NewDecoder(strings.NewReader(`folse`))
		err := dec.BoolNull(&v)
		assert.NotNil(t, err, "Err must not be nil")
		assert.IsType(t, InvalidJSONError(""), err, "err should be of type InvalidJSONError")
	})
}

func TestDecoderBoolDecoderAPI(t *testing.T) {
	var v bool
	dec := BorrowDecoder(strings.NewReader("true"))
	defer dec.Release()
	err := dec.DecodeBool(&v)
	assert.Nil(t, err, "Err must be nil")
	assert.Equal(t, true, v, "v must be equal to true")
}

func TestDecoderBoolPoolError(t *testing.T) {
	v := true
	dec := NewDecoder(nil)
	dec.Release()
	defer func() {
		err := recover()
		assert.NotNil(t, err, "err shouldnt be nil")
		assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
	}()
	_ = dec.DecodeBool(&v)
	assert.True(t, false, "should not be called as decoder should have panicked")
}
