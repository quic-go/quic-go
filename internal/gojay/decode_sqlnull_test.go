package gojay

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSQLNullString(t *testing.T) {
	testCases := []struct {
		name               string
		json               string
		expectedNullString sql.NullString
		err                bool
	}{
		{
			name:               "basic",
			json:               `"test"`,
			expectedNullString: sql.NullString{String: "test", Valid: true},
		},
		{
			name:               "basic",
			json:               `"test`,
			expectedNullString: sql.NullString{String: "test", Valid: true},
			err:                true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			nullString := sql.NullString{}
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.DecodeSQLNullString(&nullString)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedNullString, nullString)
			}
		})
	}
	t.Run(
		"should panic because decoder is pooled",
		func(t *testing.T) {
			dec := NewDecoder(nil)
			dec.Release()
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err shouldnt be nil")
				assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
			}()
			_ = dec.DecodeSQLNullString(&sql.NullString{})
			assert.True(t, false, "should not be called as decoder should have panicked")
		},
	)
}

func TestDecodeSQLNullInt64(t *testing.T) {
	testCases := []struct {
		name              string
		json              string
		expectedNullInt64 sql.NullInt64
		err               bool
	}{
		{
			name:              "basic",
			json:              `1`,
			expectedNullInt64: sql.NullInt64{Int64: 1, Valid: true},
		},
		{
			name:              "basic",
			json:              `"test`,
			expectedNullInt64: sql.NullInt64{Int64: 1, Valid: true},
			err:               true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			nullInt64 := sql.NullInt64{}
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.DecodeSQLNullInt64(&nullInt64)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedNullInt64, nullInt64)
			}
		})
	}
	t.Run(
		"should panic because decoder is pooled",
		func(t *testing.T) {
			dec := NewDecoder(nil)
			dec.Release()
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err shouldnt be nil")
				assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
			}()
			_ = dec.DecodeSQLNullInt64(&sql.NullInt64{})
			assert.True(t, false, "should not be called as decoder should have panicked")
		},
	)
}

func TestDecodeSQLNullFloat64(t *testing.T) {
	testCases := []struct {
		name                string
		json                string
		expectedNullFloat64 sql.NullFloat64
		err                 bool
	}{
		{
			name:                "basic",
			json:                `1`,
			expectedNullFloat64: sql.NullFloat64{Float64: 1, Valid: true},
		},
		{
			name:                "basic",
			json:                `"test`,
			expectedNullFloat64: sql.NullFloat64{Float64: 1, Valid: true},
			err:                 true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			nullFloat64 := sql.NullFloat64{}
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.DecodeSQLNullFloat64(&nullFloat64)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedNullFloat64, nullFloat64)
			}
		})
	}
	t.Run(
		"should panic because decoder is pooled",
		func(t *testing.T) {
			dec := NewDecoder(nil)
			dec.Release()
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err shouldnt be nil")
				assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
			}()
			_ = dec.DecodeSQLNullFloat64(&sql.NullFloat64{})
			assert.True(t, false, "should not be called as decoder should have panicked")
		},
	)
}

func TestDecodeSQLNullBool(t *testing.T) {
	testCases := []struct {
		name             string
		json             string
		expectedNullBool sql.NullBool
		err              bool
	}{
		{
			name:             "basic",
			json:             `true`,
			expectedNullBool: sql.NullBool{Bool: true, Valid: true},
		},
		{
			name:             "basic",
			json:             `"&`,
			expectedNullBool: sql.NullBool{Bool: true, Valid: true},
			err:              true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			nullBool := sql.NullBool{}
			dec := NewDecoder(strings.NewReader(testCase.json))
			err := dec.DecodeSQLNullBool(&nullBool)
			if testCase.err {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedNullBool, nullBool)
			}
		})
	}
	t.Run(
		"should panic because decoder is pooled",
		func(t *testing.T) {
			dec := NewDecoder(nil)
			dec.Release()
			defer func() {
				err := recover()
				assert.NotNil(t, err, "err shouldnt be nil")
				assert.IsType(t, InvalidUsagePooledDecoderError(""), err, "err should be of type InvalidUsagePooledDecoderError")
			}()
			_ = dec.DecodeSQLNullBool(&sql.NullBool{})
			assert.True(t, false, "should not be called as decoder should have panicked")
		},
	)
}

type SQLDecodeObject struct {
	S sql.NullString
	F sql.NullFloat64
	I sql.NullInt64
	B sql.NullBool
}

func (s *SQLDecodeObject) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "s":
		return dec.AddSQLNullString(&s.S)
	case "f":
		return dec.AddSQLNullFloat64(&s.F)
	case "i":
		return dec.AddSQLNullInt64(&s.I)
	case "b":
		return dec.AddSQLNullBool(&s.B)
	}
	return nil
}

func (s *SQLDecodeObject) NKeys() int {
	return 0
}

func TestDecodeSQLNullKeys(t *testing.T) {
	var testCases = []struct {
		name           string
		json           string
		expectedResult *SQLDecodeObject
		err            bool
	}{
		{
			name: "basic all valid",
			json: `{
				"s": "foo",
				"f": 0.3,
				"i": 3,
				"b": true
			}`,
			expectedResult: &SQLDecodeObject{
				S: sql.NullString{
					String: "foo",
					Valid:  true,
				},
				F: sql.NullFloat64{
					Float64: 0.3,
					Valid:   true,
				},
				I: sql.NullInt64{
					Int64: 3,
					Valid: true,
				},
				B: sql.NullBool{
					Bool:  true,
					Valid: true,
				},
			},
		},
		{
			name: "string not valid",
			json: `{
				"s": null,
				"f": 0.3,
				"i": 3,
				"b": true
			}`,
			expectedResult: &SQLDecodeObject{
				S: sql.NullString{
					Valid: false,
				},
				F: sql.NullFloat64{
					Float64: 0.3,
					Valid:   true,
				},
				I: sql.NullInt64{
					Int64: 3,
					Valid: true,
				},
				B: sql.NullBool{
					Bool:  true,
					Valid: true,
				},
			},
		},
		{
			name: "string not valid, int not valid",
			json: `{
				"s": null,
				"f": 0.3,
				"i": null,
				"b": true
			}`,
			expectedResult: &SQLDecodeObject{
				S: sql.NullString{
					Valid: false,
				},
				F: sql.NullFloat64{
					Float64: 0.3,
					Valid:   true,
				},
				I: sql.NullInt64{
					Valid: false,
				},
				B: sql.NullBool{
					Bool:  true,
					Valid: true,
				},
			},
		},
		{
			name: "keys absent",
			json: `{
				"f": 0.3,
				"i": 3,
				"b": true
			}`,
			expectedResult: &SQLDecodeObject{
				S: sql.NullString{
					Valid: false,
				},
				F: sql.NullFloat64{
					Float64: 0.3,
					Valid:   true,
				},
				I: sql.NullInt64{
					Valid: true,
					Int64: 3,
				},
				B: sql.NullBool{
					Bool:  true,
					Valid: true,
				},
			},
		},
		{
			name: "keys all null",
			json: `{
				"s": null,
				"f": null,
				"i": null,
				"b": null
			}`,
			expectedResult: &SQLDecodeObject{
				S: sql.NullString{
					Valid: false,
				},
				F: sql.NullFloat64{
					Valid: false,
				},
				I: sql.NullInt64{
					Valid: false,
				},
				B: sql.NullBool{
					Valid: false,
				},
			},
		},
		{
			name: "err string key",
			json: `{
				"s": "`,
			err: true,
		},
		{
			name: "err float key",
			json: `{
				"s": null,
				"f": 1",
				"i": null,
				"b": null
			}`,
			err: true,
		},
		{
			name: "err int key",
			json: `{
				"s": null,
				"f": null,
				"i": 1",
				"b": null
			}`,
			err: true,
		},
		{
			name: "err bool key",
			json: `{
				"s": null,
				"f": null,
				"i": null,
				"b": tra
			}`,
			err: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var o = &SQLDecodeObject{}
			var dec = NewDecoder(strings.NewReader(testCase.json))
			var err = dec.Decode(o)

			if testCase.err {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			require.Equal(
				t,
				testCase.expectedResult,
				o,
			)
		})
	}

}
